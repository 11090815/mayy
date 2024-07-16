package comm

import (
	"fmt"

	"github.com/11090815/mayy/gossip/utils"
)

type (
	sendFunc func(peer *utils.RemotePeer, msg *utils.SignedGossipMessage)
	waitFunc func(*utils.RemotePeer) error
)

type ackSendOperation struct {
	snd        sendFunc
	waitForAck waitFunc
}

func newAckSendOperation(snd sendFunc, waitForAck waitFunc) *ackSendOperation {
	return &ackSendOperation{
		snd:        snd,
		waitForAck: waitForAck,
	}
}

func (aso *ackSendOperation) send(msg *utils.SignedGossipMessage, minAckNum int, peers ...*utils.RemotePeer) []SendResult {
	successAcks := 0
	results := []SendResult{}

	acks := make(chan SendResult, len(peers))

	for _, p := range peers {
		go func(p *utils.RemotePeer) {
			aso.snd(p, msg)
			err := aso.waitForAck(p)
			res := ""
			if err != nil {
				res = err.Error()
			}
			acks <- SendResult{
				RemotePeer: *p,
				result:     res,
			}
		}(p)
	}

	for {
		ack := <-acks
		results = append(results, SendResult{
			result:     ack.result,
			RemotePeer: ack.RemotePeer,
		})
		if ack.result == "" {
			successAcks++
		}
		if successAcks == minAckNum || len(results) == len(peers) {
			break
		}
	}

	return results
}

func interceptAcks(nextHandler handler, remotePeerID utils.PKIidType, pubsub *utils.PubSub) func(*utils.SignedGossipMessage) {
	return func(sgm *utils.SignedGossipMessage) {
		if sgm.GossipMessage.GetAck() != nil {
			topic := topicForAck(sgm.GossipMessage.Nonce, remotePeerID)
			pubsub.Publish(topic, sgm.GossipMessage.GetAck())
			return
		}
		nextHandler(sgm)
	}
}

func topicForAck(nonce uint64, pkiID utils.PKIidType) string {
	return fmt.Sprintf("%d-%s", nonce, pkiID.String())
}
