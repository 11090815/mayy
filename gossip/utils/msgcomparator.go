package utils

import (
	"bytes"

	"github.com/11090815/mayy/protobuf/pgossip"
)

func NewGossipMessageComparator(blockStorageSize int) MessageReplacingPolicy {
	return func(this, that any) InfluenceResult {
		return invalidationPolicy(this, that, blockStorageSize)
	}
}

func invalidationPolicy(this, that any, blockStorageSize int) InfluenceResult {
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

	return MessageNoAction
}

func stateInvalidationPolicy(thisMsg *pgossip.StateInfo, thatMsg *pgossip.StateInfo) InfluenceResult {
	if !bytes.Equal(thisMsg.PkiId, thatMsg.PkiId) {
		return MessageNoAction
	}
	return compareTimestamps(thisMsg.Timestamp, thatMsg.Timestamp)
}

func identityInvalidationPolicy(thisMsg *pgossip.PeerIdentity, thatMsg *pgossip.PeerIdentity) InfluenceResult {
	if bytes.Equal(thisMsg.PkiId, thatMsg.PkiId) {
		return MessageInvalidated
	}
	return MessageNoAction
}

func dataInvalidationPolicy(thisMsg *pgossip.DataMessage, thatMsg *pgossip.DataMessage, blockStorageSize int) InfluenceResult {
	if thisMsg.Payload.SeqNum == thatMsg.Payload.SeqNum {
		return MessageInvalidated
	}

	diff := abs(thisMsg.Payload.SeqNum, thatMsg.Payload.SeqNum)
	if diff <= uint64(blockStorageSize) {
		return MessageNoAction
	}

	if thisMsg.Payload.SeqNum > thatMsg.Payload.SeqNum {
		return MessageInvalidates
	}

	return MessageInvalidated
}

func aliveInvalidationPolicy(thisMsg *pgossip.AliveMessage, thatMsg *pgossip.AliveMessage) InfluenceResult {
	if !bytes.Equal(thisMsg.Membership.PkiId, thatMsg.Membership.PkiId) {
		return MessageNoAction
	}
	return compareTimestamps(thisMsg.Timestamp, thatMsg.Timestamp)
}

func leaderInvalidationPolicy(thisMsg *pgossip.LeadershipMessage, thatMsg *pgossip.LeadershipMessage) InfluenceResult {
	if !bytes.Equal(thisMsg.PkiId, thatMsg.PkiId) {
		return MessageNoAction
	}
	return compareTimestamps(thisMsg.Timestamp, thatMsg.Timestamp)
}

// compareTimestamps 基于时间戳的比较：总的原则是 IncNum 大的消息有效，有相同 IncNum 的消息，SeqNum 大的有效。
func compareTimestamps(thisTS *pgossip.PeerTime, thatTS *pgossip.PeerTime) InfluenceResult {
	if thisTS.IncNum == thatTS.IncNum {
		if thisTS.SeqNum > thatTS.SeqNum {
			return MessageInvalidates
		}
		return MessageInvalidated
	}
	if thisTS.IncNum < thatTS.IncNum {
		return MessageInvalidated
	}
	return MessageInvalidates
}

// abs 计算 |a-b|
func abs(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
