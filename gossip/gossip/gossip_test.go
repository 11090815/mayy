package gossip

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/11090815/mayy/csp/factory"
	"github.com/11090815/mayy/gossip/discovery"
	"github.com/11090815/mayy/gossip/gossip/algo"
	"github.com/11090815/mayy/gossip/metrics"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/internal/pkg/comm"
	"github.com/11090815/mayy/protobuf/pgossip"
)

var (
	timeout           = time.Second * 180
	r                 *rand.Rand
	aliveTimeInterval = 1000 * time.Millisecond
	discoveryConfig   = discovery.Config{
		AliveTimeInterval:      aliveTimeInterval,
		AliveExpirationTimeout: 10 * aliveTimeInterval,
	}
	orgInChannelA = utils.OrgIdentityType("ORG1")
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
		peers = append(peers, fmt.Sprintf("127.0.0.1:%d", port))
	}
	return peers
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
		return []utils.OrgIdentityType{}
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

type gossipGRPC struct {
	*Node
	gRPCServer *comm.GRPCServer
}

func newGossipInstanceWithGrpcMcsMetrics(id int, port int, gRPCServer *comm.GRPCServer, certs *utils.TLSCertificates, secureDialOpts utils.PeerSecureDialOpts,
	maxMsgCount int, mcs utils.MessageCryptoService, metrics *metrics.GossipMetrics, bootPorts ...int) *gossipGRPC {
	conf := &Config{
		ID:         fmt.Sprintf("peer%d", id),
		PullConfig: algo.Config{},
		DiscoveryConfig: discovery.Config{
			BootstrapPeers: bootPeersWithPorts(bootPorts...),
		},
	}
}
