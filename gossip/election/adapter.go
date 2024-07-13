/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package election

import (
	"bytes"
	"sync"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/metrics"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
)

type gossip interface {
	// PeersOfChannel returns the NetworkMembers considered alive in a channel
	PeersOfChannel(channel utils.ChannelID) []utils.NetworkMember

	// Accept returns a dedicated read-only channel for messages sent by other nodes that match a certain predicate.
	// If passThrough is false, the messages are processed by the gossip layer beforehand.
	// If passThrough is true, the gossip layer doesn't intervene and the messages
	// can be used to send a reply back to the sender
	Accept(acceptor utils.MessageAcceptor, passThrough bool) (<-chan *pgossip.GossipMessage, <-chan utils.ReceivedMessage)

	// Gossip sends a message to other peers to the network
	Gossip(msg *pgossip.GossipMessage)

	// IsInMyOrg checks whether a network member is in this peer's org
	IsInMyOrg(member utils.NetworkMember) bool
}

// LeaderElectionAdapter 在 leader 选举模块中被用来接收/发送消息。
type LeaderElectionAdapter interface {
	// Gossip gossips a message to other peers
	Gossip(*pgossip.GossipMessage)

	// Accept returns a channel that emits messages
	Accept() <-chan *pgossip.GossipMessage

	// CreateProposalMessage
	CreateMessage(isDeclaration bool) *pgossip.GossipMessage

	// Peers returns a list of peers considered alive
	Peers() []utils.NetworkMember

	// ReportMetrics sends a report to the metrics server about a leadership status
	ReportMetrics(isLeader bool)
}

type adapterImpl struct {
	gossip    gossip
	selfPKIid utils.PKIidType

	incTime uint64
	seqNum  uint64

	channel utils.ChannelID

	logger mlog.Logger

	doneCh   chan struct{}
	stopOnce *sync.Once
	metrics  *metrics.ElectionMetrics
}

// NewAdapter creates new leader election adapter
func NewAdapter(gossip gossip, pkiid utils.PKIidType, channel utils.ChannelID,
	metrics *metrics.ElectionMetrics, logger mlog.Logger) LeaderElectionAdapter {
	return &adapterImpl{
		gossip:    gossip,
		selfPKIid: pkiid,
		incTime:   uint64(time.Now().UnixNano()),
		seqNum:    uint64(0),
		channel:   channel,
		logger:    logger,
		doneCh:    make(chan struct{}),
		stopOnce:  &sync.Once{},
		metrics:   metrics,
	}
}

func (ai *adapterImpl) Gossip(msg *pgossip.GossipMessage) {
	ai.gossip.Gossip(msg)
}

func (ai *adapterImpl) Accept() <-chan *pgossip.GossipMessage {
	adapterCh, _ := ai.gossip.Accept(func(message interface{}) bool {
		// Get only leadership org and channel messages
		return message.(*pgossip.GossipMessage).Tag == pgossip.GossipMessage_CHAN_AND_ORG &&
			message.(*pgossip.GossipMessage).GetLeadershipMsg() != nil &&
			bytes.Equal(message.(*pgossip.GossipMessage).Channel, ai.channel)
	}, false)

	msgCh := make(chan *pgossip.GossipMessage)

	go func(inCh <-chan *pgossip.GossipMessage, outCh chan *pgossip.GossipMessage, stopCh chan struct{}) {
		for {
			select {
			case <-stopCh:
				return
			case gossipMsg, ok := <-inCh:
				if ok {
					outCh <- gossipMsg
				} else {
					return
				}
			}
		}
	}(adapterCh, msgCh, ai.doneCh)
	return msgCh
}

func (ai *adapterImpl) CreateMessage(isDeclaration bool) *pgossip.GossipMessage {
	ai.seqNum++
	seqNum := ai.seqNum

	leadershipMsg := &pgossip.LeadershipMessage{
		PkiId:         ai.selfPKIid,
		IsDeclaration: isDeclaration,
		Timestamp: &pgossip.PeerTime{
			IncNum: ai.incTime,
			SeqNum: seqNum,
		},
	}

	msg := &pgossip.GossipMessage{
		Nonce:   0,
		Tag:     pgossip.GossipMessage_CHAN_AND_ORG,
		Content: &pgossip.GossipMessage_LeadershipMsg{LeadershipMsg: leadershipMsg},
		Channel: ai.channel,
	}
	return msg
}

func (ai *adapterImpl) Peers() []utils.NetworkMember {
	peers := ai.gossip.PeersOfChannel(ai.channel)

	var res []utils.NetworkMember
	for _, peer := range peers {
		if ai.gossip.IsInMyOrg(peer) {
			res = append(res, peer)
		}
	}

	return res
}

func (ai *adapterImpl) ReportMetrics(isLeader bool) {
	var leadershipBit float64
	if isLeader {
		leadershipBit = 1
	}
	ai.metrics.Declaration.With("channel", string(ai.channel)).Set(leadershipBit)
}

func (ai *adapterImpl) Stop() {
	stopFunc := func() {
		close(ai.doneCh)
	}
	ai.stopOnce.Do(stopFunc)
}
