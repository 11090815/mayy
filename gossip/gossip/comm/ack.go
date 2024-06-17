package comm

import (
	"fmt"

	"github.com/11090815/mayy/gossip/protoext"
	"github.com/11090815/mayy/gossip/utils"
)

type (
	sendFunc func(peer *RemotePeer, msg *protoext.SignedGossipMessage)
	waitFunc func(*RemotePeer) error
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

func (aso *ackSendOperation) send(msg *protoext.SignedGossipMessage, minAckNum int, peers ...*RemotePeer) []SendResult {
	successAcks := 0
	results := []SendResult{}

	acks := make(chan SendResult, len(peers))

	for _, p := range peers {
		go func(p *RemotePeer) {
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

func interceptAcks(nextHandler handler, remotePeerID utils.PKIidType, pubsub *utils.PubSub) func(*protoext.SignedGossipMessage) {
	return func(sgm *protoext.SignedGossipMessage) {
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
