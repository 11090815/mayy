package election

import (
	"sync"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/metrics"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
)

type leaderElecMsg struct {
	*pgossip.LeadershipMessage
}

func (lem *leaderElecMsg) SenderID() utils.PKIidType {
	return utils.PKIidType(lem.PkiId)
}

func (lem *leaderElecMsg) IsDeclaration() bool {
	return lem.LeadershipMessage.IsDeclaration
}

func (lem *leaderElecMsg) IsProposal() bool {
	return !lem.IsDeclaration()
}

/* ------------------------------------------------------------------------------------------ */

// gossip Node 结构体会实现此接口。
type gossip interface {
	// PeersOfChannel 返回指定通道中所有活跃的 peer 节点。
	PeersOfChannel(channel utils.ChannelID) []utils.NetworkMember

	// Accept为匹配某个谓词的其他节点发送的消息返回专用只读通道。
	// 如果passThrough为假，则消息事先由八卦层处理。
	// 如果passThrough为真，则八卦层不会介入，消息可用于向发送者发送回复。
	Accept(acceptor utils.MessageAcceptor, passThrough bool) (<-chan *pgossip.GossipMessage, <-chan utils.ReceivedMessage)

	// Gossip 将给定的消息广播给网络中的其他节点。
	Gossip(msg *pgossip.GossipMessage)

	// IsInMyOrg 判断给定的网络节点是否与自己同属于一个组织。
	IsInMyOrg(member utils.NetworkMember) bool
}

/* ------------------------------------------------------------------------------------------ */

type adapter struct {
	gossip   gossip
	pkiID    utils.PKIidType
	incTime  uint64
	seqNum   uint64
	channel  utils.ChannelID
	logger   mlog.Logger
	stopCh   chan struct{}
	stopOnce sync.Once
	metrics  *metrics.ElectionMetrics
}
