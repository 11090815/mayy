package gossip

import (
	"fmt"
	"math/rand"
	"os"
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
		},
		CommConfig: gossipcomm.Config{
			DialTimeout:  gossipcomm.DefaultDialTimeout,
			ConnTimeout:  gossipcomm.DefaultConnTimeout,
			RecvBuffSize: gossipcomm.DefaultRecvBuffSize,
			SendBuffSize: gossipcomm.DefaultSendBuffSize,
		},
	}
	identity := utils.PeerIdentityType(conf.InternalEndpoint)
	logger := utils.GetLogger(utils.GossipLogger, conf.ID, mlog.DebugLevel, true, true)
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
