package discovery

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/protoext"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	defaultTestConfig = DiscoveryConfig{
		AliveTimeInterval:            300 * time.Millisecond,
		AliveExpirationTimeout:       3000 * time.Millisecond,
		AliveExpirationCheckInterval: 300 * time.Millisecond,
		ReconnectInterval:            3000 * time.Millisecond,
		MaxConnectAttempts:           DefaultMaxConnectAttempts,
		MsgExpirationFactor:          DefaultMsgExpirationFactor,
	}

	noopPolicy = func(remotePeer *NetworkMember) (Sieve, EnvelopeFilter) {
		return func(message *protoext.SignedGossipMessage) bool {
				return true
			}, func(message *protoext.SignedGossipMessage) *pgossip.Envelope {
				return message.Envelope
			}
	}
)

/* ------------------------------------------------------------------------------------------ */

type mockReceivedMessage struct {
	msg  *protoext.SignedGossipMessage
	info *protoext.ConnectionInfo
}

func (*mockReceivedMessage) Respond(msg *pgossip.GossipMessage) {
	panic("not implemented")
}

func (rm *mockReceivedMessage) GetSignedGossipMessage() *protoext.SignedGossipMessage {
	return rm.msg
}

func (rm *mockReceivedMessage) GetSourceEnvelope() *pgossip.Envelope {
	panic("not implemented")
}

func (rm *mockReceivedMessage) GetConnectionInfo() *protoext.ConnectionInfo {
	return rm.info
}

func (rm *mockReceivedMessage) Ack(error) {
	panic("not implemented")
}

/* ------------------------------------------------------------------------------------------ */

type mockAnchorPeerTracker struct {
	endpoints []string
}

func (m *mockAnchorPeerTracker) IsAnchorPeer(endpoint string) bool {
	return utils.Contains(endpoint, m.endpoints)
}

func (m *mockAnchorPeerTracker) Update(channelName string, endpoints map[string]struct{}) {
	for endpoint := range endpoints {
		m.endpoints = append(m.endpoints, endpoint)
	}
}

/* ------------------------------------------------------------------------------------------ */

type mockCommModule struct {
	validatedMessages chan *protoext.SignedGossipMessage
	msgsReceived      uint32
	msgsSent          uint32
	id                string
	identitySwitch    chan utils.PKIidType
	presumedDead      chan utils.PKIidType
	detectedDead      chan string
	streams           map[string]pgossip.Gossip_GossipStreamClient
	conns             map[string]*grpc.ClientConn
	mutex             *sync.RWMutex
	incMsgs           chan protoext.ReceivedMessage
	lastSeqs          map[string]uint64
	shouldGossip      bool
	disableComm       bool
	mock              *mock.Mock
	signCount         uint32
}

func (comm *mockCommModule) ValidateAliveMsg(sgm *protoext.SignedGossipMessage) bool {
	comm.mutex.RLock()
	c := comm.validatedMessages
	comm.mutex.RUnlock()

	if c != nil {
		c <- sgm
	}

	return true
}

func (comm *mockCommModule) IdentitySwitch() <-chan utils.PKIidType {
	return comm.identitySwitch
}

func (comm *mockCommModule) ReceiveDiscoveryMessage(msg protoext.ReceivedMessage) {
	comm.incMsgs <- msg
}

func (comm *mockCommModule) SignMessage(msg *pgossip.GossipMessage, internalEndpoint string) *pgossip.Envelope {
	atomic.AddUint32(&comm.signCount, 1)
	secret := &pgossip.Secret{
		Content: &pgossip.Secret_InternalEndpoint{
			InternalEndpoint: internalEndpoint,
		},
	}
	signer := func(msg []byte) ([]byte, error) {
		return nil, nil
	}
	sgm, _ := protoext.NoopSign(msg)
	protoext.SignSecret(sgm.Envelope, signer, secret)
	return sgm.Envelope
}

func (comm *mockCommModule) Gossip(msg *protoext.SignedGossipMessage) {
	if !comm.shouldGossip || comm.disableComm {
		return
	}
	comm.mutex.Lock()
	defer comm.mutex.Unlock()
	for _, conn := range comm.streams {
		conn.Send(msg.Envelope)
	}
}

func (comm *mockCommModule) Forward(msg protoext.ReceivedMessage) {
	if !comm.shouldGossip || comm.disableComm {
		return
	}
	comm.mutex.Lock()
	defer comm.mutex.Unlock()
	for _, conn := range comm.streams {
		conn.Send(msg.GetSignedGossipMessage().Envelope)
	}
}

func (comm *mockCommModule) SendToPeer(peer *NetworkMember, msg *protoext.SignedGossipMessage) {
	if comm.disableComm {
		return
	}
	comm.mutex.RLock()
	conn, exists := comm.streams[peer.Endpoint]
	mock := comm.mock
	comm.mutex.RUnlock()

	if mock != nil {
		mock.Called(peer, msg)
	}

	if !exists {
		if comm.Ping(peer) == false {
			fmt.Printf("Ping to %s failed.\n", peer.Endpoint)
			return
		}
	}

	comm.mutex.Lock()
	s, _ := protoext.NoopSign(msg.GossipMessage)
	conn.Send(s.Envelope)
	comm.mutex.Unlock()
	atomic.AddUint32(&comm.msgsSent, 1)
}

func (comm *mockCommModule) Ping(peer *NetworkMember) bool {
	if comm.disableComm {
		return false
	}

	comm.mutex.Lock()
	defer comm.mutex.Unlock()

	if comm.mock != nil {
		comm.mock.Called()
	}

	_, exists := comm.streams[peer.Endpoint]
	conn := comm.conns[peer.Endpoint]
	if !exists || conn.GetState() == connectivity.Shutdown {
		newConn, err := grpc.Dial(peer.Endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return false
		}
		if stream, err := pgossip.NewGossipClient(newConn).GossipStream(context.Background()); err == nil {
			comm.conns[peer.Endpoint] = newConn
			comm.streams[peer.Endpoint] = stream
			return true
		}
		return false
	}
	if _, err := pgossip.NewGossipClient(conn).Ping(context.Background(), &pgossip.Empty{}); err != nil {
		return false
	}
	return true
}

func (comm *mockCommModule) Accept() <-chan protoext.ReceivedMessage {
	return comm.incMsgs
}

func (comm *mockCommModule) PresumedDead() <-chan utils.PKIidType {
	return comm.presumedDead
}

func (comm *mockCommModule) CloseConn(peer *NetworkMember) {
	comm.mutex.Lock()
	defer comm.mutex.Unlock()

	if _, exists := comm.streams[peer.Endpoint]; !exists {
		return
	}
	comm.streams[peer.Endpoint].CloseSend()
	comm.conns[peer.Endpoint].Close()
}

func (comm *mockCommModule) Stop() {
	comm.mutex.Lock()
	for _, conn := range comm.conns {
		conn.Close()
	}
	for _, stream := range comm.streams {
		stream.CloseSend()
	}
	comm.mutex.Unlock()
}

func (comm *mockCommModule) recordValidation(validatedMsgs chan *protoext.SignedGossipMessage) {
	comm.mutex.Lock()
	defer comm.mutex.Unlock()
	comm.validatedMessages = validatedMsgs
}

type gossipInstance struct {
	msgInterceptor func(*protoext.SignedGossipMessage)
	comm           *mockCommModule
	Discovery
	gRPCServer    *grpc.Server
	listener      net.Listener
	syncInitiator *time.Ticker
	stopChan      chan struct{}
	port          int
}

func (g *gossipInstance) GossipStream(stream pgossip.Gossip_GossipStreamServer) error {
	for {
		envelope, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		logger := g.discoveryImpl().logger
		sgm, err := protoext.EnvelopeToSignedGossipMessage(envelope)
		if err != nil {
			logger.Errorf("Failed deserializing GossipMessage from envelope, error: %s.", err.Error())
			continue
		}
		g.msgInterceptor(sgm)
		logger.Debugf("%s got message: %s.", g.Discovery.Self().Endpoint, sgm.String())
		g.comm.incMsgs <- &mockReceivedMessage{
			msg: sgm,
			info: &protoext.ConnectionInfo{
				ID: utils.PKIidType("testID"),
			},
		}
		atomic.AddUint32(&g.comm.msgsReceived, 1)
		if aliveMsg := sgm.GetAliveMsg(); aliveMsg != nil {
			g.tryForwardMessage(sgm)
		}
	}
}

func (g *gossipInstance) Ping(context.Context, *pgossip.Empty) (*pgossip.Empty, error) {
	return &pgossip.Empty{}, nil
}

func (g *gossipInstance) Stop() {
	if g.syncInitiator != nil {
		g.syncInitiator.Stop()
	}
	close(g.stopChan)
	g.gRPCServer.Stop()
	g.listener.Close()
	g.comm.Stop()
	g.Discovery.Stop()
}

func (g *gossipInstance) receivedMsgCount() int {
	return int(atomic.LoadUint32(&g.comm.msgsReceived))
}

func (g *gossipInstance) sentMsgCount() int {
	return int(atomic.LoadUint32(&g.comm.msgsSent))
}

func (g *gossipInstance) discoveryImpl() *gossipDiscoveryImpl {
	return g.Discovery.(*gossipDiscoveryImpl)
}

func (g *gossipInstance) initiateSync(frequency time.Duration, peerNum int) {
	g.syncInitiator = time.NewTicker(frequency)
	g.stopChan = make(chan struct{})
	go func() {
		for {
			select {
			case <-g.syncInitiator.C:
				g.Discovery.InitiateSync(peerNum)
			case <-g.stopChan:
				g.syncInitiator.Stop()
				return
			}
		}
	}()
}

func (g *gossipInstance) tryForwardMessage(msg *protoext.SignedGossipMessage) {
	g.comm.mutex.Lock()
	aliveMsg := msg.GetAliveMsg()
	forward := false
	id := utils.PKIidType(aliveMsg.Membership.PkiId).String()
	seqNum := aliveMsg.Timestamp.SeqNum
	if last, exists := g.comm.lastSeqs[id]; exists {
		if last < seqNum {
			g.comm.lastSeqs[id] = seqNum
			forward = true
		}
	} else {
		g.comm.lastSeqs[id] = seqNum
		forward = true
	}
	g.comm.mutex.Unlock()
	if forward {
		g.comm.Gossip(msg)
	}
}

/* ------------------------------------------------------------------------------------------ */

// 可以广播
func createDiscoveryInstance(port int, id string, bootstrapPeers []string) *gossipInstance {
	return createDiscoveryInstanceCustomConfig(port, id, bootstrapPeers, defaultTestConfig)
}

// 可以广播
func createDiscoveryInstanceCustomConfig(port int, id string, bootstrapPeers []string, config DiscoveryConfig) *gossipInstance {
	return createDiscoveryInstanceThatGossips(port, id, bootstrapPeers, true, noopPolicy, config)
}

// 不可以广播
func createDiscoveryInstanceWithNoGossip(port int, id string, bootstrapPeers []string) *gossipInstance {
	return createDiscoveryInstanceThatGossips(port, id, bootstrapPeers, false, noopPolicy, defaultTestConfig)
}

// 不可以广播
func createDiscoveryInstanceWithNoGossipWithDisclosurePolicy(port int, id string, bootstrapPeers []string, policy DisclosurePolicy) *gossipInstance {
	return createDiscoveryInstanceThatGossips(port, id, bootstrapPeers, false, policy, defaultTestConfig)
}

func createDiscoveryInstanceThatGossips(port int, id string, bootstrapPeers []string, shouldGossip bool, policy DisclosurePolicy, config DiscoveryConfig) *gossipInstance {
	return createDiscoveryInstanceThatGossipsWithInterceptors(port, id, bootstrapPeers, shouldGossip, policy, func(sgm *protoext.SignedGossipMessage) {}, config)
}

func createDiscoveryInstanceThatGossipsWithInterceptors(port int, id string, bootstrapPeers []string, shouldGossip bool, policy DisclosurePolicy, f func(*protoext.SignedGossipMessage), config DiscoveryConfig) *gossipInstance {
	mockTracker := &mockAnchorPeerTracker{}
	return createDiscoveryInstanceWithAnchorPeerTracker(port, id, bootstrapPeers, shouldGossip, policy, f, config, mockTracker, nil)
}

func createDiscoveryInstanceWithAnchorPeerTracker(port int, id string, bootstrapPeers []string, shouldGossip bool, policy DisclosurePolicy, f func(*protoext.SignedGossipMessage), config DiscoveryConfig, anchorPeerTracker AnchorPeerTracker, logger mlog.Logger) *gossipInstance {
	comm := &mockCommModule{
		conns:          make(map[string]*grpc.ClientConn),
		streams:        make(map[string]pgossip.Gossip_GossipStreamClient),
		incMsgs:        make(chan protoext.ReceivedMessage, 1000),
		presumedDead:   make(chan utils.PKIidType, 10000),
		id:             id,
		detectedDead:   make(chan string, 10000),
		identitySwitch: make(chan utils.PKIidType),
		mutex:          &sync.RWMutex{},
		lastSeqs:       make(map[string]uint64),
		shouldGossip:   shouldGossip,
		disableComm:    false,
	}

	endpoint := fmt.Sprintf("localhost:%d", port)
	self := NetworkMember{
		Metadata:         []byte{},
		PKIid:            []byte(endpoint),
		Endpoint:         endpoint,
		InternalEndpoint: endpoint,
	}

	listenAddress := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		panic(err.Error())
	}
	s := grpc.NewServer()
	config.BootstrapPeers = bootstrapPeers
	if logger == nil {
		logger = utils.GetLogger(utils.DiscoveryLogger, id, mlog.DebugLevel, true, true)
	}
	discoveryService := NewDiscoveryService(self, comm, comm, policy, config, anchorPeerTracker, logger)
	for _, bootPeer := range bootstrapPeers {
		discoveryService.Connect(NetworkMember{Endpoint: bootPeer, InternalEndpoint: bootPeer}, func() (*PeerIdentification, error) {
			return &PeerIdentification{SelfOrg: true, PKIid: utils.PKIidType(bootPeer)}, nil
		})
	}

	gInst := &gossipInstance{
		comm:           comm,
		gRPCServer:     s,
		Discovery:      discoveryService,
		listener:       listener,
		port:           port,
		msgInterceptor: f,
	}

	pgossip.RegisterGossipServer(s, gInst)
	go s.Serve(listener)

	return gInst
}
