package protoext

import (
	"bytes"

	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
)

func NewGossipMessageComparator(blockStorageSize int) utils.MessageReplacingPolicy {
	return func(this, that any) utils.InfluenceResult {
		return invalidationPolicy(this, that, blockStorageSize)
	}
}

func invalidationPolicy(this, that any, blockStorageSize int) utils.InfluenceResult {
	thisMsg := this.(*SignedGossipMessage)
	thatMsg := that.(*SignedGossipMessage)

	if thisMsg.GetStateInfo() != nil && thatMsg.GetStateInfo() != nil {
		return stateInvalidationPolicy(thisMsg.GetStateInfo(), thatMsg.GetStateInfo())
	}

	if thisMsg.GetPeerIdentity() != nil && thatMsg.GetPeerIdentity() != nil {
		return identityInvalidationPolicy(thisMsg.GetPeerIdentity(), thatMsg.GetPeerIdentity())
	}

	if thisMsg.GetDataMsg() != nil && thatMsg.GetDataMsg() != nil {
		return dataInvalidationPolicy(thisMsg.GetDataMsg(), thatMsg.GetDataMsg(), blockStorageSize)
	}

	if thisMsg.GetAliveMsg() != nil && thatMsg.GetAliveMsg() != nil {
		return aliveInvalidationPolicy(thisMsg.GetAliveMsg(), thatMsg.GetAliveMsg())
	}

	if thisMsg.GetLeadershipMsg() != nil && thatMsg.GetLeadershipMsg() != nil {
		return leaderInvalidationPolicy(thisMsg.GetLeadershipMsg(), thatMsg.GetLeadershipMsg())
	}

	return utils.MessageNoAction
}

func stateInvalidationPolicy(thisMsg *pgossip.StateInfo, thatMsg *pgossip.StateInfo) utils.InfluenceResult {
	if !bytes.Equal(thisMsg.PkiId, thatMsg.PkiId) {
		return utils.MessageNoAction
	}
	return compareTimestamps(thisMsg.Timestamp, thatMsg.Timestamp)
}

func identityInvalidationPolicy(thisMsg *pgossip.PeerIdentity, thatMsg *pgossip.PeerIdentity) utils.InfluenceResult {
	if bytes.Equal(thisMsg.PkiId, thatMsg.PkiId) {
		return utils.MessageInvalidated
	}
	return utils.MessageNoAction
}

func dataInvalidationPolicy(thisMsg *pgossip.DataMessage, thatMsg *pgossip.DataMessage, blockStorageSize int) utils.InfluenceResult {
	if thisMsg.Payload.SeqNum == thatMsg.Payload.SeqNum {
		return utils.MessageInvalidated
	}

	diff := abs(thisMsg.Payload.SeqNum, thatMsg.Payload.SeqNum)
	if diff <= uint64(blockStorageSize) {
		return utils.MessageNoAction
	}

	if thisMsg.Payload.SeqNum > thatMsg.Payload.SeqNum {
		return utils.MessageInvalidates
	}

	return utils.MessageInvalidated
}

func aliveInvalidationPolicy(thisMsg *pgossip.AliveMessage, thatMsg *pgossip.AliveMessage) utils.InfluenceResult {
	if !bytes.Equal(thisMsg.Membership.PkiId, thatMsg.Membership.PkiId) {
		return utils.MessageNoAction
	}
	return compareTimestamps(thisMsg.Timestamp, thatMsg.Timestamp)
}

func leaderInvalidationPolicy(thisMsg *pgossip.LeadershipMessage, thatMsg *pgossip.LeadershipMessage) utils.InfluenceResult {
	if !bytes.Equal(thisMsg.PkiId, thatMsg.PkiId) {
		return utils.MessageNoAction
	}
	return compareTimestamps(thisMsg.Timestamp, thatMsg.Timestamp)
}

// compareTimestamps 基于时间戳的比较：总的原则是 IncNum 大的消息有效，有相同 IncNum 的消息，SeqNum 大的有效。
func compareTimestamps(thisTS *pgossip.PeerTime, thatTS *pgossip.PeerTime) utils.InfluenceResult {
	if thisTS.IncNum == thatTS.IncNum {
		if thisTS.SeqNum > thatTS.SeqNum {
			return utils.MessageInvalidates
		}
		return utils.MessageInvalidated
	}
	if thisTS.IncNum < thatTS.IncNum {
		return utils.MessageInvalidated
	}
	return utils.MessageInvalidates
}

// abs 计算 |a-b|
func abs(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
