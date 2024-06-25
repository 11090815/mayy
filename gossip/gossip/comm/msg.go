package comm

import (
	"github.com/11090815/mayy/gossip/protoext"
	"github.com/11090815/mayy/protobuf/pgossip"
)

type ReceivedMessageImpl struct {
	*protoext.SignedGossipMessage
	conn     *connection
	connInfo *protoext.ConnectionInfo
}

func (m *ReceivedMessageImpl) GetSourceEnvelope() *pgossip.Envelope {
	return m.Envelope
}

func (m *ReceivedMessageImpl) Respond(msg *pgossip.GossipMessage) {
	smsg, err := protoext.NoopSign(msg)
	if err != nil {
		return
	}
	m.conn.send(smsg, func(err error) {}, blockingSend)
}

func (m *ReceivedMessageImpl) GetGossipMessage() *protoext.SignedGossipMessage {
	return m.SignedGossipMessage
}

func (m *ReceivedMessageImpl) GetConnectionInfo() *protoext.ConnectionInfo {
	return m.connInfo
}

func (m *ReceivedMessageImpl) Ack(err error) {
	var errStr string
	if err != nil {
		errStr = err.Error()
	}
	ackMsg := &pgossip.GossipMessage{
		Nonce: m.GetGossipMessage().Nonce,
		Content: &pgossip.GossipMessage_Ack{
			Ack: &pgossip.Acknowledgement{
				Error: errStr,
			},
		},
	}
	m.Respond(ackMsg)
}
