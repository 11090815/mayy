package comm

import (
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
)

type ReceivedMessageImpl struct {
	*utils.SignedGossipMessage
	conn     *connection
	connInfo *utils.ConnectionInfo
}

func (m *ReceivedMessageImpl) GetSourceEnvelope() *pgossip.Envelope {
	return m.Envelope
}

func (m *ReceivedMessageImpl) Respond(msg *pgossip.GossipMessage) {
	smsg, err := utils.NoopSign(msg)
	if err != nil {
		return
	}
	m.conn.send(smsg, func(err error) {}, blockingSend)
}

func (m *ReceivedMessageImpl) GetSignedGossipMessage() *utils.SignedGossipMessage {
	return m.SignedGossipMessage
}

func (m *ReceivedMessageImpl) GetConnectionInfo() *utils.ConnectionInfo {
	return m.connInfo
}

func (m *ReceivedMessageImpl) Ack(err error) {
	var errStr string
	if err != nil {
		errStr = err.Error()
	}
	ackMsg := &pgossip.GossipMessage{
		Nonce: m.GetSignedGossipMessage().Nonce,
		Content: &pgossip.GossipMessage_Ack{
			Ack: &pgossip.Acknowledgement{
				Error: errStr,
			},
		},
	}
	m.Respond(ackMsg)
}
