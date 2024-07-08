package election

import (
	"bytes"
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

type leaderElectionAdapter interface {
	Gossip(*leaderElecMsg)

	Accept() <-chan *leaderElecMsg

	CreateMessage(isDeclaration bool) *leaderElecMsg

	// Peers 返回与自己在同一通道且在同一组织内的所有 peer 节点信息。
	Peers() []*utils.NetworkMember

	ReportMetrics(isLeader bool)
}

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

func (a *adapter) Gossip(msg *leaderElecMsg) {
	gossipMessage := &pgossip.GossipMessage{
		Tag:     pgossip.GossipMessage_CHAN_AND_ORG,
		Nonce:   0,
		Channel: a.channel,
		Content: &pgossip.GossipMessage_LeadershipMsg{
			LeadershipMsg: msg.LeadershipMessage,
		},
	}
	a.gossip.Gossip(gossipMessage)
}

func (a *adapter) Accept() <-chan *leaderElecMsg {
	var acceptor utils.MessageAcceptor = func(msg any) bool {
		return msg.(*pgossip.GossipMessage).Tag == pgossip.GossipMessage_CHAN_AND_ORG &&
			msg.(*pgossip.GossipMessage).GetLeadershipMsg() != nil &&
			bytes.Equal(msg.(*pgossip.GossipMessage).Channel, a.channel)
	}

	inCh, _ := a.gossip.Accept(acceptor, false)

	msgCh := make(chan *leaderElecMsg)
	go func(inCh <-chan *pgossip.GossipMessage, msgCh chan *leaderElecMsg, stopCh chan struct{}) {
		for {
			select {
			case <-stopCh:
				return
			case m, ok := <-inCh:
				if ok {
					msgCh <- &leaderElecMsg{LeadershipMessage: m.GetLeadershipMsg()}
				}
			}
		}
	}(inCh, msgCh, a.stopCh)

	return msgCh
}

func (a *adapter) CreateMessage(isDeclaration bool) *leaderElecMsg {
	a.seqNum++
	seqNum := a.seqNum
	leadershipMsg := &pgossip.LeadershipMessage{
		PkiId:         a.pkiID,
		IsDeclaration: isDeclaration,
		Timestamp: &pgossip.PeerTime{
			IncNum: a.incTime,
			SeqNum: seqNum,
		},
	}

	return &leaderElecMsg{LeadershipMessage: leadershipMsg}
}

// Peers 返回与自己在同一通道且在同一组织内的所有 peer 节点信息。
func (a *adapter) Peers() []*utils.NetworkMember {
	peers := a.gossip.PeersOfChannel(a.channel)

	var res []*utils.NetworkMember
	for _, peer := range peers {
		if a.gossip.IsInMyOrg(peer) {
			res = append(res, &peer)
		}
	}
	return res
}

func (a *adapter) ReportMetrics(isLeader bool) {
	var leadership float64 = 0.0
	if isLeader {
		leadership = 1.0
	}
	a.metrics.Declaration.With("channel", a.channel.String()).Set(leadership)
}

func (a *adapter) Stop() {
	a.stopOnce.Do(func() {
		close(a.stopCh)
	})
}
