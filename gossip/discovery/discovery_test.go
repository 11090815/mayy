package discovery

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/protoext"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

	// noopPolicy 不做任何过滤操作，不论是谁发出 request 请求，都会将 response 原封不动的反馈给它。
	noopPolicy = func(remotePeer *NetworkMember) (Sieve, EnvelopeFilter) {
		return func(message *protoext.SignedGossipMessage) bool {
				return true
			}, func(message *protoext.SignedGossipMessage) *pgossip.Envelope {
				return message.Envelope
			}
	}

	timeout = 15 * time.Second
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
	_, exists := comm.streams[peer.Endpoint]
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
	comm.streams[peer.Endpoint].Send(s.Envelope)
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
		sgm, err := protoext.EnvelopeToSignedGossipMessage(envelope)
		if err != nil {
			continue
		}
		g.msgInterceptor(sgm)
		g.comm.incMsgs <- &mockReceivedMessage{
			msg: sgm,
			info: &protoext.ConnectionInfo{
				ID: utils.PKIidType("testID"),
			},
		}
		atomic.AddUint32(&g.comm.msgsReceived, 1)
		// if aliveMsg := sgm.GetAliveMsg(); aliveMsg != nil {
		// 	g.tryForwardMessage(sgm)
		// }
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

// interceptor 将别人广播来的消息用 interceptor 截获并处理一下。
func createDiscoveryInstanceThatGossipsWithInterceptors(port int, id string, bootstrapPeers []string, shouldGossip bool, policy DisclosurePolicy, f func(*protoext.SignedGossipMessage), config DiscoveryConfig) *gossipInstance {
	mockTracker := &mockAnchorPeerTracker{}
	return createDiscoveryInstanceWithAnchorPeerTracker(port, id, bootstrapPeers, shouldGossip, policy, f, config, mockTracker, nil)
}

func createDiscoveryInstanceWithAnchorPeerTracker(port int, id string, bootstrapPeers []string, shouldGossip bool, policy DisclosurePolicy, fn func(*protoext.SignedGossipMessage), config DiscoveryConfig, anchorPeerTracker AnchorPeerTracker, logger mlog.Logger) *gossipInstance {
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
		msgInterceptor: fn,
		stopChan:       make(chan struct{}),
	}

	pgossip.RegisterGossipServer(s, gInst)
	go s.Serve(listener)

	return gInst
}

func waitUntilOrPanic(t *testing.T, pred func() bool) {
	waitUntilTimeoutOrFail(t, pred, timeout)
}

func waitUntilTimeoutOrFail(t *testing.T, pred func() bool, timeout time.Duration) {
	start := time.Now()
	limit := start.UnixNano() + timeout.Nanoseconds()
	for time.Now().UnixNano() < limit {
		if pred() {
			return
		}
		time.Sleep(timeout / 10)
	}
	require.Fail(t, "timeout expired")
}

func bootPeer(port int) string {
	return fmt.Sprintf("localhost:%d", port)
}

func assertMembership(t *testing.T, instances []*gossipInstance, expectedNum int, msg string) {
	wg := sync.WaitGroup{}
	wg.Add(len(instances))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, inst := range instances {
		go func(inst *gossipInstance, ctx context.Context) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(timeout / 10):
					if len(inst.GetMembership()) == expectedNum {
						return
					}
				}
			}
		}(inst, ctx)
	}

	wg.Wait()
	require.NoError(t, ctx.Err(), msg)
}

/* ------------------------------------------------------------------------------------------ */

func TestClone(t *testing.T) {
	nm := &NetworkMember{
		PKIid: []byte("pkiID"),
		Properties: &pgossip.Properties{
			LedgerHeight: 10,
			LeftChannel:  true,
			Chaincodes: []*pgossip.Chaincode{
				{Name: "dscabs", Version: "v1.0.0", Metadata: []byte("metadata")},
			},
		},
		Envelope:         &pgossip.Envelope{Payload: []byte("payload")},
		Endpoint:         "endpoint",
		InternalEndpoint: "internalEndpoint",
		Metadata:         []byte("metadata"),
	}

	nm2 := nm.Clone()

	require.Equal(t, nm2, *nm)
	require.False(t, nm2.Properties == nm.Properties)
	require.False(t, nm2.Envelope == nm.Envelope)
}

func TestToString(t *testing.T) {
	nm1 := &NetworkMember{Endpoint: "a", InternalEndpoint: "b"}
	require.Equal(t, "b", nm1.PreferredEndpoint())
	nm2 := &NetworkMember{Endpoint: "a"}
	require.Equal(t, "a", nm2.PreferredEndpoint())

	fmt.Println(nm1.String())

	now := time.Now()
	ts1 := &timestamp{
		incTime: now,
		seqNum:  2,
	}
	ts2 := &timestamp{
		incTime:  now,
		seqNum:   2,
		lastSeen: now.Add(-20 * time.Minute),
	}

	fmt.Println(ts1.String())
	fmt.Println(ts2.String())
}

func TestBadInput(t *testing.T) {
	inst := createDiscoveryInstance(2048, fmt.Sprintf("d%d", 0), []string{})
	inst.discoveryImpl().handleMsgFromComm(nil)
	sgm, _ := protoext.NoopSign(&pgossip.GossipMessage{
		Content: &pgossip.GossipMessage_DataMsg{
			DataMsg: &pgossip.DataMessage{
				Payload: &pgossip.Payload{Data: []byte("data")},
			},
		},
	})
	inst.discoveryImpl().handleMsgFromComm(&mockReceivedMessage{
		msg: sgm,
		info: &protoext.ConnectionInfo{
			ID: []byte("pkiID"),
		},
	})
	inst.Stop()
}

func TestConnect(t *testing.T) {
	nodeNum := 5
	instances := []*gossipInstance{}

	for i := 0; i < nodeNum; i++ {
		inst := createDiscoveryInstance(2048+i, fmt.Sprintf("node%d", i+1), []string{})
		instances = append(instances, inst)
		j := (i + 1) % nodeNum
		endpoint := fmt.Sprintf("localhost:%d", 2048+j)
		networkMember2Connect2 := NetworkMember{Endpoint: endpoint, PKIid: []byte(endpoint)}
		inst.Connect(networkMember2Connect2, func() (*PeerIdentification, error) {
			return &PeerIdentification{SelfOrg: false, PKIid: nil}, nil
		})
		defer inst.Stop()
	}

	fullMembership := func() bool {
		finished := true
		for i := 0; i < nodeNum; i++ {
			if nodeNum-1 != len(instances[i].discoveryImpl().GetMembership()) {
				finished = false
			}
		}
		return finished
	}
	waitUntilOrPanic(t, fullMembership)
}

func TestNoSigningIfNoMembership(t *testing.T) {
	inst := createDiscoveryInstance(2048, "alone", nil)
	defer inst.Stop()
	time.Sleep(defaultTestConfig.AliveTimeInterval * 10)
	require.Zero(t, atomic.LoadUint32(&inst.comm.signCount))
	inst.InitiateSync(10000)
	require.Zero(t, atomic.LoadUint32(&inst.comm.signCount))
}

func TestValidation(t *testing.T) {
	// wrapReceivedMessage := func(msg *protoext.SignedGossipMessage) protoext.ReceivedMessage {
	// 	return &mockReceivedMessage{
	// 		msg: msg,
	// 		info: &protoext.ConnectionInfo{
	// 			ID: utils.PKIidType("testID"),
	// 		},
	// 	}
	// }

	requestMessagesReceived := make(chan *protoext.SignedGossipMessage, 100)
	responseMessagesReceived := make(chan *protoext.SignedGossipMessage, 100)
	aliveMessagesReceived := make(chan *protoext.SignedGossipMessage, 5000)

	var membershipRequest atomic.Value
	var membershipResponseWithAlivePeers atomic.Value
	var membershipResponseWithDeadPeers atomic.Value

	recordMembershipRequest := func(req *protoext.SignedGossipMessage) {
		msg, _ := protoext.EnvelopeToSignedGossipMessage(req.GetMemReq().SelfInformation)
		membershipRequest.Store(msg)
		requestMessagesReceived <- msg
	}

	recordMembershipResponse := func(res *protoext.SignedGossipMessage) {
		memRes := res.GetMemRes()
		if len(memRes.Alive) > 0 {
			membershipResponseWithAlivePeers.Store(res)
		}
		if len(memRes.Dead) > 0 {
			membershipResponseWithDeadPeers.Store(res)
		}
		responseMessagesReceived <- res
	}

	interceptor := func(msg *protoext.SignedGossipMessage) {
		if memReq := msg.GetMemReq(); memReq != nil {
			recordMembershipRequest(msg)
		}
		if memRes := msg.GetMemRes(); memRes != nil {
			recordMembershipResponse(msg)
		}
		// 不是 req，也不是 res，那就是 alive
		aliveMessagesReceived <- msg
	}

	p1 := createDiscoveryInstanceThatGossipsWithInterceptors(4675, "p1", []string{bootPeer(4677)}, true, noopPolicy, interceptor, defaultTestConfig)
	p2 := createDiscoveryInstance(4676, "p2", []string{bootPeer(4675)})
	p3 := createDiscoveryInstance(4677, "p3", nil)
	instances := []*gossipInstance{p1, p2, p3}

	assertMembership(t, instances, 2, "signal 2")

	instances = []*gossipInstance{p1, p2}
	p3.Stop()
	assertMembership(t, instances, 1, "signal 1")
	p1.InitiateSync(1)

	waitUntilOrPanic(t, func() bool {
		return membershipResponseWithDeadPeers.Load() != nil
	})

	p1.Stop()
	p2.Stop()

	t.Log("Recorded", len(aliveMessagesReceived), "alive messages")
	t.Log("Recorded", len(requestMessagesReceived), "request messages")
	t.Log("Recorded", len(responseMessagesReceived), "response messages")
}
