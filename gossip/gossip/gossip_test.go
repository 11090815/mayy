package gossip

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/mayy/common/metrics/disabled"
	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/csp/factory"
	"github.com/11090815/mayy/gossip/discovery"
	"github.com/11090815/mayy/gossip/gossip/algo"
	"github.com/11090815/mayy/gossip/gossip/channel"
	gossipcomm "github.com/11090815/mayy/gossip/gossip/comm"
	"github.com/11090815/mayy/gossip/metrics"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/internal/pkg/comm"
	"github.com/11090815/mayy/protobuf/pgossip"
	"github.com/stretchr/testify/require"
)

var (
	// 180s
	timeout           = time.Second * 180
	r                 *rand.Rand
	aliveTimeInterval = 1000 * time.Millisecond
	discoveryConfig   = discovery.Config{
		AliveTimeInterval:            aliveTimeInterval,
		AliveExpirationTimeout:       10 * aliveTimeInterval,
		AliveExpirationCheckInterval: aliveTimeInterval,
		ReconnectInterval:            aliveTimeInterval,
		MaxConnectionAttempts:        5,
		MsgExpirationFactor:          discovery.DefaultMsgExpirationFactor,
	}
	orgInChannelA = utils.OrgIdentityType("ORG1")
	channelA      = utils.StringToChannelID("ChannelA")
)

func TestMain(m *testing.M) {
	r = rand.New(rand.NewSource(time.Now().UnixNano()))
	factory.InitCSPFactoryWithOpts(&factory.FactoryOpts{
		Kind:          "sw",
		KeyStorePath:  "./keys",
		SecurityLevel: 384,
		HashFamily:    "SHA2",
		ReadOnly:      true,
	})
	os.Exit(m.Run())
}

func shouldBeDataMsg(msg any) bool {
	return msg.(*pgossip.GossipMessage).GetDataMsg() != nil
}

func shouldBeLeadershipMsg(msg any) bool {
	return msg.(*pgossip.GossipMessage).Tag == pgossip.GossipMessage_CHAN_AND_ORG && msg.(*pgossip.GossipMessage).GetLeadershipMsg() != nil
}

func bootPeersWithPorts(ports ...int) []string {
	var peers []string
	for _, port := range ports {
		peers = append(peers, fmt.Sprintf("localhost:%d", port))
	}
	return peers
}

func waitUntilOrFail(t *testing.T, pred func() bool, context string) {
	start := time.Now()
	limit := start.UnixNano() + timeout.Nanoseconds()
	for time.Now().UnixNano() < limit {
		if pred() {
			return
		}
		time.Sleep(timeout / 1000)
	}
	utils.PrintStackTrace()
	require.Failf(t, "Timeout expired, context: %s", context)
}

func waitUntilOrFailBlocking(t *testing.T, f func(), context string) {
	successChan := make(chan struct{}, 1)
	go func() {
		f()
		successChan <- struct{}{}
	}()
	select {
	case <-time.NewTimer(timeout).C:
		break
	case <-successChan:
		return
	}
	utils.PrintStackTrace()
	require.Failf(t, "Timeout expired, while %s", context)
}

// waitForTestCompletion 如果 stopFlag 在 180s 内没有变成 1，则会报错。
func waitForTestCompletion(stopFlag *int32, t *testing.T) {
	time.Sleep(timeout)
	if atomic.LoadInt32(stopFlag) == int32(1) {
		return
	}
	utils.PrintStackTrace()
	require.Fail(t, "Didn't stop within a timely manner.")
}

func stopPeers(peers []*gossipGRPC) {
	stopping := sync.WaitGroup{}
	stopping.Add(len(peers))
	for i, pi := range peers {
		go func(i int, peer *gossipGRPC) {
			defer stopping.Done()
			peer.Stop()
		}(i, pi)
	}
	stopping.Wait()
}

func checkPeersMembership(t *testing.T, peers []*gossipGRPC, n int) func() bool {
	return func() bool {
		for _, peer := range peers {
			if len(peer.Peers()) != n {
				return false
			}
			for _, p := range peer.Peers() {
				require.NotNil(t, p.InternalEndpoint)
				require.NotEmpty(t, p.Endpoint)
			}
		}
		return true
	}
}

func metadataOfPeer(members []utils.NetworkMember, endpoint string) []byte {
	for _, member := range members {
		if member.InternalEndpoint == endpoint {
			return member.Metadata
		}
	}
	return nil
}

func heightOfPeer(members []utils.NetworkMember, endpoint string) int {
	for _, member := range members {
		if member.InternalEndpoint == endpoint {
			return int(member.Properties.LedgerHeight)
		}
	}
	return -1
}

/* ------------------------------------------------------------------------------------------ */

func createDataMsg(seqNum uint64, data []byte, channel utils.ChannelID) *pgossip.GossipMessage {
	return &pgossip.GossipMessage{
		Channel: channel,
		Nonce:   0,
		Tag:     pgossip.GossipMessage_CHAN_AND_ORG,
		Content: &pgossip.GossipMessage_DataMsg{
			DataMsg: &pgossip.DataMessage{
				Payload: &pgossip.Payload{
					Data:   data,
					SeqNum: seqNum,
				},
			},
		},
	}
}

func createLeadershipMsg(isDeclaration bool, channel utils.ChannelID, incTime uint64, seqNum uint64, pkiid []byte) *pgossip.GossipMessage {
	return &pgossip.GossipMessage{
		Nonce:   0,
		Tag:     pgossip.GossipMessage_CHAN_AND_ORG,
		Channel: channel,
		Content: &pgossip.GossipMessage_LeadershipMsg{
			LeadershipMsg: &pgossip.LeadershipMessage{
				IsDeclaration: isDeclaration,
				PkiId:         pkiid,
				Timestamp: &pgossip.PeerTime{
					IncNum: incTime,
					SeqNum: seqNum,
				},
			},
		},
	}
}

/* ------------------------------------------------------------------------------------------ */

type joinChanMsg struct {
	orgs2anchorPeers map[string][]utils.AnchorPeer
}

func (jcm *joinChanMsg) SequenceNumber() uint64 {
	return uint64(time.Now().UnixNano())
}

func (jcm *joinChanMsg) Orgs() []utils.OrgIdentityType {
	if jcm.orgs2anchorPeers == nil {
		return []utils.OrgIdentityType{orgInChannelA}
	}
	orgs := make([]utils.OrgIdentityType, len(jcm.orgs2anchorPeers))
	i := 0
	for org := range jcm.orgs2anchorPeers {
		orgs[i] = utils.StringToOrgIdentityType(org)
		i++
	}
	return orgs
}

func (jcm *joinChanMsg) AnchorPeersOf(org utils.OrgIdentityType) []utils.AnchorPeer {
	if jcm.orgs2anchorPeers == nil {
		return []utils.AnchorPeer{}
	}
	return jcm.orgs2anchorPeers[org.String()]
}

/* ------------------------------------------------------------------------------------------ */

type orgCryptoService struct{}

func (*orgCryptoService) OrgByPeerIdentity(identity utils.PeerIdentityType) utils.OrgIdentityType {
	return orgInChannelA
}

func (*orgCryptoService) Verify(jcm utils.JoinChannelMessage) error {
	return nil
}

/* ------------------------------------------------------------------------------------------ */

type gossipGRPC struct {
	*Node
	gRPCServer *comm.GRPCServer
}

func (g *gossipGRPC) Stop() {
	g.Node.Stop()
	g.gRPCServer.Stop()
}

func newGossipInstanceWithGrpcMcsMetrics(id int, port int, gRPCServer *comm.GRPCServer, certs *utils.TLSCertificates, secureDialOpts utils.PeerSecureDialOpts,
	maxMsgCount int, mcs utils.MessageCryptoService, metrics *metrics.GossipMetrics, bootPorts ...int) *gossipGRPC {
	conf := &Config{
		ID:                         fmt.Sprintf("peer%d", id),
		MaxPropagationBurstLatency: 500 * time.Millisecond,
		MaxPropagationBurstSize:    20,
		PropagateIterations:        1,
		PropagatePeerNum:           3,
		InternalEndpoint:           fmt.Sprintf("localhost:%d", port),
		ExternalEndpoint:           fmt.Sprintf("localhost:%d", port),
		PublishCertPeriod:          4 * time.Second,
		TLSCerts:                   certs,
		PullConfig: algo.Config{
			DigestWaitTime:   algo.DefaultDigestWaitTime,
			RequestWaitTime:  algo.DefaultRequestWaitTime,
			ResponseWaitTime: algo.DefaultResponseWaitTime,
		},
		DiscoveryConfig: discovery.Config{
			BootstrapPeers:               bootPeersWithPorts(bootPorts...),
			AliveTimeInterval:            discoveryConfig.AliveTimeInterval,
			AliveExpirationTimeout:       discoveryConfig.AliveExpirationTimeout,
			AliveExpirationCheckInterval: discoveryConfig.AliveExpirationCheckInterval,
			ReconnectInterval:            discoveryConfig.ReconnectInterval,
			MaxConnectionAttempts:        discoveryConfig.MaxConnectionAttempts,
			MsgExpirationFactor:          discoveryConfig.MsgExpirationFactor,
		},
		ChannelConfig: channel.Config{
			MaxBlockCountToStore:           maxMsgCount,
			PullInterval:                   4 * time.Second,
			PullPeerNum:                    5,
			PublishStateInfoInterval:       time.Second,
			RequestStateInfoInterval:       time.Second,
			TimeForMembershipTracker:       5 * time.Second,
			LeadershipMsgExpirationTimeout: channel.DefaultLeadershipMsgExpirationTimeout,
			BlockExpirationTimeout:         100 * time.Second,
			StateInfoCacheSweepInterval:    5 * time.Second,
		},
		CommConfig: gossipcomm.Config{
			DialTimeout:  gossipcomm.DefaultDialTimeout,
			ConnTimeout:  gossipcomm.DefaultConnTimeout,
			RecvBuffSize: gossipcomm.DefaultRecvBuffSize,
			SendBuffSize: gossipcomm.DefaultSendBuffSize,
		},
	}
	identity := utils.PeerIdentityType(conf.ID)
	logger := utils.GetLogger(utils.GossipLogger, conf.ID, mlog.ErrorLevel, true, true)
	node := NewNode(conf, gRPCServer.Server(), &orgCryptoService{}, mcs, identity, secureDialOpts, logger, metrics, nil, logger.With("module", utils.DiscoveryLogger))
	go func() {
		err := gRPCServer.Start()
		if err != nil {
			panic(err.Error())
		}
	}()
	return &gossipGRPC{Node: node, gRPCServer: gRPCServer}
}

func newGossipInstanceWithGRPC(id int, port int, gRPCServer *comm.GRPCServer, certs *utils.TLSCertificates,
	secureDialOpts utils.PeerSecureDialOpts, maxMsgCount int, bootPorts ...int) *gossipGRPC {
	metrics := metrics.NewGossipMetrics(&disabled.Provider{})
	mcs := &naiveCryptoService{}
	return newGossipInstanceWithGrpcMcsMetrics(id, port, gRPCServer, certs, secureDialOpts, maxMsgCount, mcs, metrics, bootPorts...)
}

func newGossipInstanceWithExpiration(expirations map[string]time.Time, mutex *sync.RWMutex, id int, port int, gRPCServer *comm.GRPCServer,
	certs *utils.TLSCertificates, secureDialOpts utils.PeerSecureDialOpts, maxMsgCount int, bootPorts ...int) *gossipGRPC {
	metrics := metrics.NewGossipMetrics(&disabled.Provider{})
	mcs := &naiveCryptoService{expirationTimesLock: mutex, expirationTimes: expirations}
	return newGossipInstanceWithGrpcMcsMetrics(id, port, gRPCServer, certs, secureDialOpts, maxMsgCount, mcs, metrics, bootPorts...)
}

func newGossipInstanceWithGRPCWithOnlyPull(id int, port int, gRPCServer *comm.GRPCServer, certs *utils.TLSCertificates,
	secureDialOpts utils.PeerSecureDialOpts, maxMsgCount int, mcs utils.MessageCryptoService, metrics *metrics.GossipMetrics, bootPorts ...int) *gossipGRPC {
	shortenedWaitTime := 200 * time.Millisecond
	conf := &Config{
		ID:                         fmt.Sprintf("p%d", id),
		MaxPropagationBurstLatency: time.Second,
		MaxPropagationBurstSize:    10,
		PropagateIterations:        0,
		PropagatePeerNum:           0,
		InternalEndpoint:           fmt.Sprintf("localhost:%d", port),
		ExternalEndpoint:           fmt.Sprintf("1.2.3.4:%d", port),
		PublishCertPeriod:          0,
		TLSCerts:                   certs,
		DiscoveryConfig: discovery.Config{
			BootstrapPeers:               bootPeersWithPorts(bootPorts...),
			AliveTimeInterval:            discoveryConfig.AliveTimeInterval,
			AliveExpirationTimeout:       discoveryConfig.AliveExpirationTimeout,
			AliveExpirationCheckInterval: discoveryConfig.AliveExpirationCheckInterval,
			ReconnectInterval:            discoveryConfig.ReconnectInterval,
			MaxConnectionAttempts:        discoveryConfig.MaxConnectionAttempts,
			MsgExpirationFactor:          discoveryConfig.MsgExpirationFactor,
		},
		ChannelConfig: channel.Config{
			MaxBlockCountToStore:           maxMsgCount,
			PullInterval:                   time.Second,
			PullPeerNum:                    20,
			PublishStateInfoInterval:       time.Second,
			RequestStateInfoInterval:       time.Second,
			TimeForMembershipTracker:       5 * time.Second,
			LeadershipMsgExpirationTimeout: channel.DefaultLeadershipMsgExpirationTimeout,
			BlockExpirationTimeout:         time.Second * 100,
			StateInfoCacheSweepInterval:    5 * time.Second,
		},
		CommConfig: gossipcomm.Config{
			DialTimeout:  gossipcomm.DefaultDialTimeout,
			ConnTimeout:  gossipcomm.DefaultConnTimeout,
			RecvBuffSize: gossipcomm.DefaultRecvBuffSize,
			SendBuffSize: gossipcomm.DefaultSendBuffSize,
		},
		PullConfig: algo.Config{
			DigestWaitTime:   shortenedWaitTime,
			RequestWaitTime:  shortenedWaitTime,
			ResponseWaitTime: shortenedWaitTime,
		},
	}

	logger := utils.GetLogger(utils.GossipLogger, conf.ID, mlog.PanicLevel, true, true)
	selfID := utils.PeerIdentityType(conf.ID)
	node := NewNode(conf, gRPCServer.Server(), &orgCryptoService{}, mcs, selfID, secureDialOpts, logger, metrics, nil, logger.With("module", utils.DiscoveryLogger))
	go func() {
		gRPCServer.Start()
	}()
	return &gossipGRPC{Node: node, gRPCServer: gRPCServer}
}

func newGossipInstanceCreateGRPCWithMCSWithMetrics(id int, maxMsgCount int, mcs utils.MessageCryptoService,
	metrics *metrics.GossipMetrics, bootPorts ...int) *gossipGRPC {
	port, server, certs, secureOpts, _ := utils.CreateGRPCLayer()
	return newGossipInstanceWithGrpcMcsMetrics(id, port, server, certs, secureOpts, maxMsgCount, mcs, metrics, bootPorts...)
}

func newGossipInstanceCreateGRPC(id int, maxMsgCount int, bootPorts ...int) *gossipGRPC {
	metrics := metrics.NewGossipMetrics(&disabled.Provider{})
	mcs := &naiveCryptoService{}
	return newGossipInstanceCreateGRPCWithMCSWithMetrics(id, maxMsgCount, mcs, metrics, bootPorts...)
}

func newGossipInstanceCreateGRPCWithOnlyPull(id int, maxMsgCount int, mcs utils.MessageCryptoService,
	metrics *metrics.GossipMetrics, bootPorts ...int) *gossipGRPC {
	port, server, certs, secureOpts, _ := utils.CreateGRPCLayer()
	return newGossipInstanceWithGRPCWithOnlyPull(id, port, server, certs, secureOpts, maxMsgCount, mcs, metrics, bootPorts...)
}

/* ------------------------------------------------------------------------------------------ */

func TestLeaveChannel(t *testing.T) {
	port0, grpc0, certs0, secDialOpts0, _ := utils.CreateGRPCLayer()
	port1, grpc1, certs1, secDialOpts1, _ := utils.CreateGRPCLayer()
	port2, grpc2, certs2, secDialOpts2, _ := utils.CreateGRPCLayer()

	node0 := newGossipInstanceWithGRPC(0, port0, grpc0, certs0, secDialOpts0, 100, port1)
	node0.JoinChan(&joinChanMsg{}, channelA)
	node0.UpdateLedgerHeight(1, channelA)
	defer node0.Stop()

	node1 := newGossipInstanceWithGRPC(1, port1, grpc1, certs1, secDialOpts1, 100, port0)
	node1.JoinChan(&joinChanMsg{}, channelA)
	node1.UpdateLedgerHeight(1, channelA)
	defer node1.Stop()

	node2 := newGossipInstanceWithGRPC(2, port2, grpc2, certs2, secDialOpts2, 100, port1)
	node2.JoinChan(&joinChanMsg{}, channelA)
	node2.UpdateLedgerHeight(1, channelA)
	defer node2.Stop()

	countMembership := func(g *gossipGRPC, expected int) func() bool {
		return func() bool {
			peers := g.PeersOfChannel(channelA)
			return len(peers) == expected
		}
	}

	waitUntilOrFail(t, countMembership(node0, 2), "wait for node0 to form membership")
	waitUntilOrFail(t, countMembership(node1, 2), "wait for node1 to form membership")
	waitUntilOrFail(t, countMembership(node2, 2), "wait for node2 to form membership")

	node2.LeaveChan(channelA)

	waitUntilOrFail(t, countMembership(node0, 1), "wait for node0 to update membership")
	waitUntilOrFail(t, countMembership(node1, 1), "wait for node1 to update membership")
	waitUntilOrFail(t, countMembership(node2, 0), "wait for node2 to update membership")
}

func TestPull(t *testing.T) {
	startTime := time.Now()

	stopped := int32(0)
	go waitForTestCompletion(&stopped, t)

	n := 5
	msgCount2Send := 10

	metrics := metrics.NewGossipMetrics(&disabled.Provider{})
	mcs := &naiveCryptoService{}
	port0, grpc0, certs0, secDialOpts0, _ := utils.CreateGRPCLayer()

	peers := make([]*gossipGRPC, n)
	wg := sync.WaitGroup{}
	wg.Add(n)
	for i := 1; i <= n; i++ {
		go func(i int) {
			defer wg.Done()
			pi := newGossipInstanceCreateGRPCWithOnlyPull(i, 100, mcs, metrics, port0)
			pi.JoinChan(&joinChanMsg{}, channelA)
			pi.UpdateLedgerHeight(1, channelA)
			peers[i-1] = pi
		}(i)
	}
	wg.Wait()

	time.Sleep(time.Second)

	boot := newGossipInstanceWithGRPCWithOnlyPull(0, port0, grpc0, certs0, secDialOpts0, 100, mcs, metrics)
	boot.JoinChan(&joinChanMsg{}, channelA)
	boot.UpdateLedgerHeight(1, channelA)

	knowAll := func() bool {
		for i := 1; i <= n; i++ {
			neighbourCount := len(peers[i-1].Peers())
			if n != neighbourCount {
				return false
			}
		}
		return true
	}

	receivedMsgs := make([]int, n)
	wg = sync.WaitGroup{}
	wg.Add(n)
	for i := 1; i <= n; i++ {
		go func(i int) {
			acceptChan, _ := peers[i-1].Accept(shouldBeDataMsg, false)
			go func(index int, ch <-chan *pgossip.GossipMessage) {
				defer wg.Done()
				for j := 0; j < msgCount2Send; j++ {
					<-ch
					receivedMsgs[index]++
				}
			}(i-1, acceptChan)
		}(i)
	}

	for i := 1; i <= msgCount2Send; i++ {
		boot.Gossip(createDataMsg(uint64(i), []byte{}, channelA))
	}

	waitUntilOrFail(t, knowAll, "waiting to form membership among all peers")
	waitUntilOrFailBlocking(t, wg.Wait, "waiting peers to register for gossip message")

	receivedAll := func() bool {
		for i := 0; i < n; i++ {
			if msgCount2Send != receivedMsgs[i] {
				return false
			}
		}
		return true
	}
	waitUntilOrFail(t, receivedAll, "waiting for all messages to be received by all peers")
	for i := 1; i <= n; i++ {
		neighbourCount := len(peers[i-1].Peers())
		t.Logf("p%d: %d\n", i, neighbourCount)
	}

	stop := func() {
		stopPeers(append(peers, boot))
	}
	waitUntilOrFailBlocking(t, stop, "waiting to stop all peers")
	t.Logf("Took %fs", time.Since(startTime).Seconds())

	atomic.StoreInt32(&stopped, 1)
}

func TestConnectToAnchorPeers(t *testing.T) {
	stopped := int32(0)
	go waitForTestCompletion(&stopped, t)

	n := 8
	anchorPeercount := 3

	var ports []int
	var grpcs []*comm.GRPCServer
	var certs []*utils.TLSCertificates
	var secDialOpts []utils.PeerSecureDialOpts

	joinMsg := &joinChanMsg{orgs2anchorPeers: map[string][]utils.AnchorPeer{orgInChannelA.String(): {}}}
	for i := 0; i < anchorPeercount; i++ {
		port, grpc, cert, secDialOpt, _ := utils.CreateGRPCLayer()
		ports = append(ports, port)
		grpcs = append(grpcs, grpc)
		certs = append(certs, cert)
		secDialOpts = append(secDialOpts, secDialOpt)
		anchorPeer := utils.AnchorPeer{Host: "localhost", Port: port}
		joinMsg.orgs2anchorPeers[orgInChannelA.String()] = append(joinMsg.orgs2anchorPeers[orgInChannelA.String()], anchorPeer)
	}

	nodes := make([]*gossipGRPC, n)
	wg := sync.WaitGroup{}
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			nodes[i] = newGossipInstanceCreateGRPC(i+anchorPeercount, 100)
			nodes[i].JoinChan(joinMsg, channelA)
			nodes[i].UpdateLedgerHeight(1, channelA)
			wg.Done()
		}(i)
	}
	waitUntilOrFailBlocking(t, wg.Wait, "waiting until all nodes join the channel")

	index := r.Intn(anchorPeercount)
	anchorPeer := newGossipInstanceWithGRPC(index, ports[index], grpcs[index], certs[index], secDialOpts[index], 100)
	anchorPeer.JoinChan(joinMsg, channelA)
	anchorPeer.UpdateLedgerHeight(1, channelA)
	defer anchorPeer.Stop()
	waitUntilOrFail(t, checkPeersMembership(t, nodes, n), "waiting for peers to form membership view")

	channelMembership := func() bool {
		for _, peer := range nodes {
			if len(peer.PeersOfChannel(channelA)) != n {
				return false
			}
		}
		return true
	}
	waitUntilOrFail(t, channelMembership, "waiting for peers to form channel membership view")

	stop := func() {
		stopPeers(nodes)
	}
	waitUntilOrFailBlocking(t, stop, "waiting for gossip instances to stop")
	atomic.StoreInt32(&stopped, 1)
}

func TestMembership(t *testing.T) {
	stopped := int32(0)
	go waitForTestCompletion(&stopped, t)
	n := 10

	port0, grpc0, certs0, secDialOpts0, _ := utils.CreateGRPCLayer()
	boot := newGossipInstanceWithGRPC(0, port0, grpc0, certs0, secDialOpts0, 100)
	boot.JoinChan(&joinChanMsg{}, channelA)
	boot.UpdateLedgerHeight(1, channelA)

	peers := make([]*gossipGRPC, n)
	wg := sync.WaitGroup{}
	wg.Add(n - 1)
	for i := 1; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			p := newGossipInstanceCreateGRPC(i, 100, port0)
			peers[i-1] = p
			p.JoinChan(&joinChanMsg{}, channelA)
			p.UpdateLedgerHeight(1, channelA)
		}(i)
	}

	portn, grpcn, certsn, secDialOptsn, _ := utils.CreateGRPCLayer()
	lastPeer := fmt.Sprintf("localhost:%d", portn)
	pn := newGossipInstanceWithGRPC(n, portn, grpcn, certsn, secDialOptsn, 100, port0)
	peers[n-1] = pn
	pn.JoinChan(&joinChanMsg{}, channelA)
	pn.UpdateLedgerHeight(1, channelA)
	waitUntilOrFailBlocking(t, wg.Wait, "waiting for all peers to join the channel")

	seeAllNeighbours := func() bool {
		for i := 0; i < n; i++ {
			neighbourCount := len(peers[i].Peers())
			if neighbourCount != n {
				return false
			}
		}
		return true
	}
	waitUntilOrFail(t, seeAllNeighbours, "waiting for all peers to form the membership")

	peers[n-1].UpdateMetadata([]byte("la la la")) // 更新 metadata 后，会周期性的向其他节点广播自己的 alive 消息，里面包含自己的 metadata 信息。
	// 这个周期包括三个：
	// 1.我们定期向其他节点广播自己的 alive 消息。
	// 2.我们定期向其他节点发送 member request 请求，里面携带我们的 alive 消息。
	// 3.回复别人定期发过来的 member request 请求，回复内容中包含我们的 alive 消息。
	metaDataUpdated := func() bool {
		if !bytes.Equal([]byte("la la la"), metadataOfPeer(boot.Peers(), lastPeer)) {
			return false
		}
		for i := 0; i < n-1; i++ {
			if !bytes.Equal([]byte("la la la"), metadataOfPeer(peers[i].Peers(), lastPeer)) {
				return false
			}
		}
		return true
	}

	waitUntilOrFail(t, metaDataUpdated, "wait until metadata update is got propagated")
	stop := func() {
		stopPeers(peers)
	}
	waitUntilOrFailBlocking(t, stop, "waiting for gossip instances to stop")
	atomic.StoreInt32(&stopped, 1)
}

func TestNoMessagesSelfLoop(t *testing.T) {
	port0, grpc0, certs0, secDialOpts0, _ := utils.CreateGRPCLayer()
	boot := newGossipInstanceWithGRPC(0, port0, grpc0, certs0, secDialOpts0, 100)
	boot.JoinChan(&joinChanMsg{}, channelA)
	boot.UpdateLedgerHeight(1, channelA)

	peer := newGossipInstanceCreateGRPC(1, 100, port0)
	peer.JoinChan(&joinChanMsg{}, channelA)
	peer.UpdateLedgerHeight(1, channelA)
	waitUntilOrFail(t, checkPeersMembership(t, []*gossipGRPC{peer}, 1), "waiting for peers to form membership")
	_, commCh := boot.Accept(func(a any) bool {
		return a.(utils.ReceivedMessage).GetSignedGossipMessage().GetDataMsg() != nil
	}, true)
	wg := sync.WaitGroup{}
	wg.Add(2)

	go func(ch <-chan utils.ReceivedMessage) {
		defer wg.Done()
		for {
			select {
			case msg := <-ch:
				{
					if msg.GetSignedGossipMessage().GetDataMsg() != nil {
						t.Errorf("Should not receive data message back, but got %s", msg.GetSignedGossipMessage().String())
					}
				}
			case <-time.After(2 * time.Second):
				return
			}
		}
	}(commCh)

	peerCh, _ := peer.Accept(shouldBeDataMsg, false)
	go func(ch <-chan *pgossip.GossipMessage) {
		defer wg.Done()
		<-ch
	}(peerCh)

	boot.Gossip(createDataMsg(2, []byte{}, channelA))
	waitUntilOrFailBlocking(t, wg.Wait, "waiting for everyone to get the message")
	stop := func() {
		stopPeers([]*gossipGRPC{boot, peer})
	}
	waitUntilOrFailBlocking(t, stop, "waiting for gossip instances to stop")
}

// 测试传播能力
func TestDissemination(t *testing.T) {
	stopped := int32(0)
	go waitForTestCompletion(&stopped, t)

	n := 10
	msgsCount2Send := 10

	port0, grpc0, certs0, secDialOpts0, _ := utils.CreateGRPCLayer()
	boot := newGossipInstanceWithGRPC(0, port0, grpc0, certs0, secDialOpts0, 100)
	boot.JoinChan(&joinChanMsg{}, channelA)
	boot.UpdateLedgerHeight(1, channelA)
	boot.UpdateChaincodes([]*pgossip.Chaincode{{Name: "ChainCode", Version: "v1.0"}}, channelA)

	peers := make([]*gossipGRPC, n)
	receivedMessages := make([]int, n)
	wg := sync.WaitGroup{}
	wg.Add(n)
	portn, grpcn, certsn, secDialOptsn, _ := utils.CreateGRPCLayer()
	for i := 1; i <= n; i++ {
		var peer *gossipGRPC
		if i == n {
			peer = newGossipInstanceWithGRPC(i, portn, grpcn, certsn, secDialOptsn, 100, port0)
		} else {
			peer = newGossipInstanceCreateGRPC(i, 100, port0)
		}
		peers[i-1] = peer
		peer.JoinChan(&joinChanMsg{}, channelA)
		peer.UpdateLedgerHeight(1, channelA)
		peer.UpdateChaincodes([]*pgossip.Chaincode{{Name: "ChainCode", Version: "v1.0"}}, channelA)
		acceptChan, _ := peer.Accept(shouldBeDataMsg, false)
		go func(index int, ch <-chan *pgossip.GossipMessage) {
			defer wg.Done()
			for j := 0; j < msgsCount2Send; j++ {
				<-ch
				receivedMessages[index]++
			}
		}(i-1, acceptChan)
		if i == n {
			peer.UpdateLedgerHeight(2, channelA)
		}
	}
	lastPeer := fmt.Sprintf("localhost:%d", portn)
	metaDataUpdated := func() bool {
		if heightOfPeer(boot.PeersOfChannel(channelA), lastPeer) != 2 {
			return false
		}
		for i := 0; i < n-1; i++ {
			if heightOfPeer(peers[i].PeersOfChannel(channelA), lastPeer) != 2 {
				return false
			}
			for _, p := range peers[i].PeersOfChannel(channelA) {
				if len(p.Properties.Chaincodes) != 1 {
					return false
				}
				if !reflect.DeepEqual(p.Properties.Chaincodes, []*pgossip.Chaincode{{Name: "ChainCode", Version: "v1.0"}}) {
					return false
				}
			}
		}
		return true
	}

	waitUntilOrFail(t, checkPeersMembership(t, peers, n), "waiting for all peers to form membership")
	for i := 2; i <= msgsCount2Send+1; i++ {
		boot.Gossip(createDataMsg(uint64(i), []byte{}, channelA))
	}

	waitUntilOrFailBlocking(t, wg.Wait, "waiting to receive all messages")
	waitUntilOrFail(t, metaDataUpdated, "waiting dissemination")

	for i := 0; i < n; i++ {
		require.Equal(t, msgsCount2Send, receivedMessages[i])
	}

	receivedLeadershipMessages := make([]int, n)
	wg = sync.WaitGroup{}
	wg.Add(n)
	for i := 1; i <= n; i++ {
		leadershipCh, _ := peers[i-1].Accept(shouldBeLeadershipMsg, false)
		go func(index int, ch <-chan *pgossip.GossipMessage) {
			defer wg.Done()
			msg := <-ch
			if bytes.Equal(msg.Channel, channelA) {
				receivedLeadershipMessages[index]++
			}
		}(i-1, leadershipCh)
	}

	// _, ch := peers[1].Accept(func(a any) bool {return true}, true)
	// go func(ch <-chan utils.ReceivedMessage) {
	// 	for {
	// 		msg := <-ch
	// 		panic(msg.GetSignedGossipMessage().String())
	// 	}
	// }(ch)

	seqNum := 0
	incTime := uint64(time.Now().UnixNano())
	leadershipMessage := createLeadershipMsg(true, channelA, incTime, uint64(seqNum), boot.communication.GetPKIid())
	boot.Gossip(leadershipMessage)
	waitUntilOrFailBlocking(t, wg.Wait, "waiting to get all leadership messages")
	for i := 0; i < n; i++ {
		require.Equal(t, 1, receivedLeadershipMessages[i])
	}

	stop := func() {
		stopPeers(append(peers, boot))
	}
	waitUntilOrFailBlocking(t, stop, "waiting for gossip instances to stop")
	atomic.StoreInt32(&stopped, 1)
}

func TestMembershipConvergence(t *testing.T) {
	port0, grpc0, certs0, secDialOpts0, _ := utils.CreateGRPCLayer()
	port1, grpc1, certs1, secDialOpts1, _ := utils.CreateGRPCLayer()
	port2, grpc2, certs2, secDialOpts2, _ := utils.CreateGRPCLayer()
	boot0 := newGossipInstanceWithGRPC(0, port0, grpc0, certs0, secDialOpts0, 100)
	boot1 := newGossipInstanceWithGRPC(1, port1, grpc1, certs1, secDialOpts1, 100)
	boot2 := newGossipInstanceWithGRPC(2, port2, grpc2, certs2, secDialOpts2, 100)
	ports := []int{port0, port1, port2}

	peers := []*gossipGRPC{boot0, boot1, boot2}
	for i := 3; i < 15; i++ {
		peer := newGossipInstanceCreateGRPC(i, 100, ports[i%3])
		peers = append(peers, peer)
	}

	waitUntilOrFail(t, checkPeersMembership(t, peers, 4), "waiting for all instances to form membership")

	port15, grpc15, certs15, secDialOpts15, _ := utils.CreateGRPCLayer()
	bridge := newGossipInstanceWithGRPC(15, port15, grpc15, certs15, secDialOpts15, 100, ports...)
	bridgeAddr := fmt.Sprintf("localhost:%d", port15)
	bridge.UpdateMetadata([]byte("bridge"))

	allKnown := func() bool {
		for i := 0; i < 15; i++ {
			if len(peers[i].Peers()) != 15 {
				return false
			}
			if string(metadataOfPeer(peers[i].Peers(), bridgeAddr)) != "bridge" {
				return false
			}
		}
		return true
	}

	waitUntilOrFail(t, allKnown, "waiting for all instances to form membership")

	waitUntilOrFailBlocking(t, bridge.Stop, "waiting for bridge stop")
	time.Sleep(time.Second * 15)

	ensureForget := func() bool {
		for i := 0; i < 15; i++ {
			if len(peers[i].Peers()) != 14 {
				return false
			}
		}
		return true
	}
	waitUntilOrFail(t, ensureForget, "waiting for all instances to form membership")

	port15, grpc15, certs15, secDialOpts15, _ = utils.CreateGRPCLayer()
	bridge = newGossipInstanceWithGRPC(15, port15, grpc15, certs15, secDialOpts15, 100, ports...)
	bridgeAddr = fmt.Sprintf("localhost:%d", port15)
	bridge.UpdateMetadata([]byte("Bridge"))

	allKnown2 := func() bool {
		for i := 0; i < 15; i++ {
			if len(peers[i].Peers()) != 15 {
				return false
			}
			if string(metadataOfPeer(peers[i].Peers(), bridgeAddr)) != "Bridge" {
				return false
			}
		}
		return true
	}
	waitUntilOrFail(t, allKnown2, "waiting for all instances to form membership")
	stop := func() {
		stopPeers(append(peers, bridge))
	}
	waitUntilOrFailBlocking(t, stop, "waiting fro instances to stop")
}

/*
测试场景描述：g0 g1 g2 是三个节点，其中 g1 是恶意节点，并且想假装 g2 向 g1
发送一个 membership 请求。

想要的结果：g0 不会回复 g1，并且，当 g2 自己给 g0 发送 membership 请求
时，g0 应该要回复 g2。
*/
func TestMembershipRequestSpoofing(t *testing.T) {
	port0, grpc0, certs0, secDialOpts0, _ := utils.CreateGRPCLayer()
	port1, grpc1, certs1, secDialOpts1, _ := utils.CreateGRPCLayer()
	port2, grpc2, certs2, secDialOpts2, _ := utils.CreateGRPCLayer()
	g0 := newGossipInstanceWithGRPC(0, port0, grpc0, certs0, secDialOpts0, 100)
	g1 := newGossipInstanceWithGRPC(1, port1, grpc1, certs1, secDialOpts1, 100, port2)
	g2 := newGossipInstanceWithGRPC(2, port2, grpc2, certs2, secDialOpts2, 100, port1)
	defer g0.Stop()
	defer g1.Stop()
	defer g2.Stop()

	pkiID0 := utils.PKIidType("peer0")
	pkiID2 := utils.PKIidType("peer2")
	endpoint0 := fmt.Sprintf("localhost:%d", port0)

	waitUntilOrFail(t, checkPeersMembership(t, []*gossipGRPC{g1, g2}, 1), "waiting for g1 and g2 form membership")
	_, aliveMsgCh := g1.Accept(func(a any) bool {
		msg := a.(utils.ReceivedMessage).GetSignedGossipMessage()
		return msg.GetAliveMsg() != nil && bytes.Equal(msg.GetAliveMsg().Membership.PkiId, pkiID2)
	}, true)
	aliveMsg := <-aliveMsgCh // 收到g2的alive消息

	_, g0tog1 := g1.Accept(func(a any) bool {
		connInfo := a.(utils.ReceivedMessage).GetConnectionInfo()
		return bytes.Equal(pkiID0, connInfo.PkiID)
	}, true)

	_, g0tog2 := g2.Accept(func(a any) bool {
		connInfo := a.(utils.ReceivedMessage).GetConnectionInfo()
		return bytes.Equal(pkiID0, connInfo.PkiID)
	}, true)

	memRequestSpoofFactory := func(aliveMsgEnv *pgossip.Envelope) *utils.SignedGossipMessage {
		sgm, _ := utils.NoopSign(&pgossip.GossipMessage{
			Tag:   pgossip.GossipMessage_EMPTY,
			Nonce: 0,
			Content: &pgossip.GossipMessage_MemReq{
				MemReq: &pgossip.MembershipRequest{
					SelfInformation: aliveMsgEnv,
				},
			},
		})
		return sgm
	}
	spoofedMemReq := memRequestSpoofFactory(aliveMsg.GetSourceEnvelope())
	g1.Send(spoofedMemReq.GossipMessage, &utils.RemotePeer{Endpoint: endpoint0, PKIID: pkiID0}) // g1将g2的alive消息(请求)转发给g0
	select {
	case <-time.After(time.Second):
		break
	case <-g0tog1:
		require.Fail(t, "g1 should not get response from g0")
	}

	g2.Send(spoofedMemReq.GossipMessage, &utils.RemotePeer{Endpoint: endpoint0, PKIID: pkiID0})
	select {
	case <-time.After(time.Second):
		require.Fail(t, "g2 should get response from g0")
	case <-g0tog2:
		break
	}
}

/*
测试场景描述：生成一些节点，并让它们之间建立起连接来。然后让一半节点进入通道 A，
另一半节点进入通道 B。但是，要确保每个通道的前 3 个节点才有资格从该通道中获取区块。
确保节点只接收与其通道相关的消息，并且只有在符合其通道资格的情况下才接收消息。
*/
func TestDataLeakage(t *testing.T) {
	totalPeers := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	n := len(totalPeers)

	var ports []int
	var grpcs []*comm.GRPCServer
	var certs []*utils.TLSCertificates
	var secDialOpts []utils.PeerSecureDialOpts
	var pkids []string

	for i := 0; i < n; i++ {
		port, grpc, cert, secDialOpt, _ := utils.CreateGRPCLayer()
		ports = append(ports, port)
		grpcs = append(grpcs, grpc)
		certs = append(certs, cert)
		secDialOpts = append(secDialOpts, secDialOpt)
		pkids = append(pkids, fmt.Sprintf("peer%d", i))
	}

	metrics := metrics.NewGossipMetrics(&disabled.Provider{})
	mcs := &naiveCryptoService{
		allowedPkiIDS: map[string]struct{}{
			// channel A
			pkids[0]: {},
			pkids[1]: {},
			pkids[2]: {},
			// channel B
			pkids[5]: {},
			pkids[6]: {},
			pkids[7]: {},
		},
	}

	peers := make([]*gossipGRPC, n)
	wg := sync.WaitGroup{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			totPeers := append([]int(nil), ports[:i]...)
			bootPeers := append(totPeers, ports[i+1:]...)
			peers[i] = newGossipInstanceWithGrpcMcsMetrics(i, ports[i], grpcs[i], certs[i], secDialOpts[i], 100, mcs, metrics, bootPeers...)
			wg.Done()
		}(i)
	}
	waitUntilOrFailBlocking(t, wg.Wait, "waiting to create all peers")
	waitUntilOrFail(t, checkPeersMembership(t, peers, n-1), "waiting for all peers to form membership view")

	channels := []utils.ChannelID{channelA, utils.StringToChannelID("ChannelB")}
	height := uint64(1)

	for i, channel := range channels {
		for j := 0; j < (n / 2); j++ {
			index := (n/2)*i + j
			peers[index].JoinChan(&joinChanMsg{}, channel)
			if i != 0 {
				height = uint64(2)
			}
			peers[index].UpdateLedgerHeight(height, channel)
		}
	}

	seeChannleMetadata := func() bool {
		for i, channel := range channels {
			for j := 0; j < 3; j++ {
				index := (n/2)*i + j
				if len(peers[index].PeersOfChannel(channel)) < 2 {
					return false
				}
			}
		}
		return true
	}
	waitUntilOrFail(t, seeChannleMetadata, "waiting for all peers to build per channel view")

	for i, channel := range channels {
		for j := 0; j < 3; j++ {
			index := (n/2)*i + j
			require.Len(t, peers[index].PeersOfChannel(channel), 2)
			if i == 0 {
				require.Equal(t, uint64(1), peers[index].PeersOfChannel(channel)[0].Properties.LedgerHeight)
			} else {
				require.Equal(t, uint64(2), peers[index].PeersOfChannel(channel)[0].Properties.LedgerHeight)
			}
		}
	}

	gotMessages := func() {
		var wg sync.WaitGroup
		wg.Add(4)
		for i, channel := range channels {
			for j := 1; j < 3; j++ {
				index := (n/2)*i + j
				go func(index int, channel utils.ChannelID) {
					dataMsgCh, _ := peers[index].Accept(shouldBeDataMsg, false)
					msg := <-dataMsgCh
					require.Equal(t, []byte(channel), msg.Channel)
					wg.Done()
				}(index, channel)
			}
		}
		wg.Wait()
	}

	peers[0].Gossip(createDataMsg(2, []byte{}, channels[0]))
	peers[n/2].Gossip(createDataMsg(3, []byte{}, channels[1]))
	waitUntilOrFailBlocking(t, gotMessages, "waiting to get eligiable data message")

	stop := func() {
		stopPeers(peers)
	}
	waitUntilOrFailBlocking(t, stop, "waiting for all peers to stop")
}

func TestDisseminateAll2All(t *testing.T) {
	totalPeers := []int{0, 1, 2, 3}
	n := len(totalPeers)
	peers := make([]*gossipGRPC, n)

	var ports []int
	var grpcs []*comm.GRPCServer
	var certs []*utils.TLSCertificates
	var secDialOpts []utils.PeerSecureDialOpts

	for i := 0; i < n; i++ {
		port, grpc, cert, secDialOpt, _ := utils.CreateGRPCLayer()
		ports = append(ports, port)
		grpcs = append(grpcs, grpc)
		certs = append(certs, cert)
		secDialOpts = append(secDialOpts, secDialOpt)
	}

	wg := sync.WaitGroup{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			totPeers := append([]int(nil), ports[:i]...)
			bootPeers := append(totPeers, ports[i+1:]...)
			peers[i] = newGossipInstanceWithGRPC(i, ports[i], grpcs[i], certs[i], secDialOpts[i], 100, bootPeers...)
			peers[i].JoinChan(&joinChanMsg{}, channelA)
			peers[i].UpdateLedgerHeight(1, channelA)
			wg.Done()
		}(i)
	}
	wg.Wait()
	waitUntilOrFail(t, checkPeersMembership(t, peers, n-1), "waiting for all peers to form membership view")

	blockMutex := sync.WaitGroup{}
	blockMutex.Add(3 * n * (n - 1))
	wg = sync.WaitGroup{}
	wg.Add(n)

	reader := func(msgCh <-chan *pgossip.GossipMessage) {
		wg.Done()
		for range msgCh {
			blockMutex.Done()
		}
	}
	for i := 0; i < n; i++ {
		msgCh, _ := peers[i].Accept(shouldBeDataMsg, false)
		go reader(msgCh)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		go func(i int) {
			blockStartIndex := i * 3
			for j := 0; j < 3; j++ {
				blockSeq := uint64(j + blockStartIndex)
				peers[i].Gossip(createDataMsg(blockSeq, []byte{}, channelA))
			}
		}(i)
	}
	waitUntilOrFailBlocking(t, blockMutex.Wait, "waiting for all blocks been distributed among all peers")

	stop := func() {
		stopPeers(peers)
	}
	waitUntilOrFailBlocking(t, stop, "waiting for all peers to stop")
}

func TestSendByRule(t *testing.T) {
	port0, grpc0, certs0, secDialOpts0, _ := utils.CreateGRPCLayer()
	port1, grpc1, certs1, secDialOpts1, _ := utils.CreateGRPCLayer()
	port2, grpc2, certs2, secDialOpts2, _ := utils.CreateGRPCLayer()
	port3, grpc3, certs3, secDialOpts3, _ := utils.CreateGRPCLayer()

	g0 := newGossipInstanceWithGRPC(port0, port0, grpc0, certs0, secDialOpts0, 100)
	g1 := newGossipInstanceWithGRPC(port1, port1, grpc1, certs1, secDialOpts1, 100, port0)
	g2 := newGossipInstanceWithGRPC(port2, port2, grpc2, certs2, secDialOpts2, 100, port0)
	g3 := newGossipInstanceWithGRPC(port3, port3, grpc3, certs3, secDialOpts3, 100, port0)

	peers := []*gossipGRPC{g0, g1, g2, g3}
	for _, peer := range peers {
		peer.JoinChan(&joinChanMsg{}, channelA)
		peer.UpdateLedgerHeight(1, channelA)
	}
	defer stopPeers(peers)

	msg, _ := utils.NoopSign(createDataMsg(1, []byte{}, channelA))

	rule := SendRule{
		IsEligible: func(nm utils.NetworkMember) bool {
			t.Fatal("Shouldn't have called")
			return false
		},
		Timeout: time.Second,
		MinAck:  1,
	}
	require.NoError(t, g0.SendByRule(msg, rule))

	rule = SendRule{
		MaxPeers: 100,
	}
	err := g0.SendByRule(msg, rule)
	require.Error(t, err)
	require.Contains(t, err.Error(), "didn't specify the timeout")

	rule.Timeout = time.Second * 3
	err = g0.SendByRule(msg, rule)
	require.NoError(t, err)

	rule.Channel = utils.StringToChannelID("ChannelB")
	err = g0.SendByRule(msg, rule)
	require.Error(t, err)
	require.Contains(t, err.Error(), "but this channel doesn't exist")

	rule.Channel = channelA
	rule.MinAck = len(peers)
	err = g0.SendByRule(msg, rule)
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("requested to send to at least %d peers, but only", len(peers)))

	waitUntilOrFail(t, func() bool {
		return len(g0.PeersOfChannel(channelA)) == len(peers)-1
	}, "waiting for g0 to see the other peers in the channel")
	rule.MinAck = 3
	err = g0.SendByRule(msg, rule)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timed out")
	require.Contains(t, err.Error(), "3")

	acceptDataMsgs := func(a any) bool {
		return a.(utils.ReceivedMessage).GetSignedGossipMessage().GetDataMsg() != nil
	}
	_, achCh1 := g1.Accept(acceptDataMsgs, true)
	_, achCh2 := g2.Accept(acceptDataMsgs, true)
	_, achCh3 := g3.Accept(acceptDataMsgs, true)
	ack := func(c <-chan utils.ReceivedMessage) {
		msg := <-c
		msg.Ack(nil)
	}

	go ack(achCh1)
	go ack(achCh2)
	go ack(achCh3)
	err = g0.SendByRule(msg, rule)
	require.NoError(t, err)

	nack := func(c <-chan utils.ReceivedMessage) {
		msg := <-c
		msg.Ack(fmt.Errorf("en heng"))
	}

	go nack(achCh1)
	go nack(achCh2)
	go nack(achCh3)
	err = g0.SendByRule(msg, rule)
	require.Error(t, err)
	require.Contains(t, err.Error(), "en heng")

	failOnAckRequest := func(c <-chan utils.ReceivedMessage, peerId int) {
		msg := <-c
		if msg == nil {
			return
		}
		t.Logf("peer%d shouldn't get a message", peerId)
	}
	g1Endpoint := fmt.Sprintf("localhost:%d", port1)
	g2Endpoint := fmt.Sprintf("localhost:%d", port2)
	rule.IsEligible = func(nm utils.NetworkMember) bool {
		return nm.InternalEndpoint == g1Endpoint || nm.InternalEndpoint == g2Endpoint
	}
	rule.MinAck = 1
	go failOnAckRequest(achCh3, 3)
	err = g0.SendByRule(msg, rule)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timed out")
	require.Contains(t, err.Error(), "2")
	ack(achCh1)
	ack(achCh2)

	rule.MaxPeers = 1
	waitForMessage := func(c <-chan utils.ReceivedMessage, f func()) {
		select {
		case msg := <-c:
			if msg == nil {
				return
			}
		case <-time.After(time.Second * 5):
			return
		}
		f()
	}

	var messageSent uint32
	go waitForMessage(achCh1, func() {
		atomic.AddUint32(&messageSent, 1)
	})
	go waitForMessage(achCh2, func() {
		atomic.AddUint32(&messageSent, 1)
	})
	err = g0.SendByRule(msg, rule)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timed out")
	require.Equal(t, uint32(1), messageSent)
}

func TestIdentityExpiration(t *testing.T) {
	var expirationTimeLock sync.RWMutex
	expirationTimes := map[string]time.Time{}

	port0, grpc0, certs0, secDialOpts0, _ := utils.CreateGRPCLayer()
	port1, grpc1, certs1, secDialOpts1, _ := utils.CreateGRPCLayer()
	port2, grpc2, certs2, secDialOpts2, _ := utils.CreateGRPCLayer()
	port3, grpc3, certs3, secDialOpts3, _ := utils.CreateGRPCLayer()
	port4, grpc4, certs4, secDialOpts4, _ := utils.CreateGRPCLayer()

	g0 := newGossipInstanceWithExpiration(expirationTimes, &expirationTimeLock, 0, port0, grpc0, certs0, secDialOpts0, 100)
	g1 := newGossipInstanceWithExpiration(expirationTimes, &expirationTimeLock, 1, port1, grpc1, certs1, secDialOpts1, 100, port0)
	g2 := newGossipInstanceWithExpiration(expirationTimes, &expirationTimeLock, 2, port2, grpc2, certs2, secDialOpts2, 100, port0)
	g3 := newGossipInstanceWithExpiration(expirationTimes, &expirationTimeLock, 3, port3, grpc3, certs3, secDialOpts3, 100, port0)
	g4 := newGossipInstanceWithExpiration(expirationTimes, &expirationTimeLock, 4, port4, grpc4, certs4, secDialOpts4, 100, port0)

	peers := []*gossipGRPC{g0, g1, g2, g3}

	idLast := fmt.Sprintf("peer%d", 4)
	expirationTimeLock.Lock()
	expirationTimes[idLast] = time.Now().Add(time.Second * 5)
	expirationTimeLock.Unlock()

	time.AfterFunc(time.Second*5, func() {
		for _, p := range peers {
			p.Node.mcs.(*naiveCryptoService).revoke(utils.PKIidType(idLast))
		}
	})

	seeAllNeighbors := func() bool {
		for i := 0; i < 4; i++ {
			if len(peers[i].Peers()) != 3 {
				return false
			}
		}
		return true
	}
	waitUntilOrFail(t, seeAllNeighbors, "waiting for all instances to form uniform membership")

	revokedPeerIndex := r.Intn(4)
	revokedPkiD := utils.PKIidType(fmt.Sprintf("peer%d", revokedPeerIndex))
	for i, p := range peers {
		if i == revokedPeerIndex {
			continue
		}
		p.Node.mcs.(*naiveCryptoService).revoke(revokedPkiD)
	}

	for i := 0; i < 4; i++ {
		if i == revokedPeerIndex {
			continue
		}
		peers[i].SuspectPeers(func(identity utils.PeerIdentityType) bool {
			return true
		})
	}

	ensureRevokedPeerIsIgnored := func() bool {
		for i := 0; i < 4; i++ {
			neighborsCount := len(peers[i].Peers())
			expectedNeighborCount := 2
			if i == revokedPeerIndex || i == 4 {
				expectedNeighborCount = 0
			}
			fmt.Printf("expected count: %d, but actually: %d\n", expectedNeighborCount, neighborsCount)
			if expectedNeighborCount != neighborsCount {
				fmt.Printf("【bad】expected count: %d, but actually: %d\n", expectedNeighborCount, neighborsCount)
				return false
			}
		}
		return true
	}
	waitUntilOrFail(t, ensureRevokedPeerIsIgnored, "waiting for all alive peers to ignore revoked peers")
	stopPeers(peers)
	g4.Stop()
}
