package utils

import (
	"fmt"

	"github.com/11090815/mayy/protobuf/pgossip"
)

type ReceivedMessage interface {
	// Respond 给发送此 ReceivedMessage 消息的人发送一个 GossipMessage。
	Respond(msg *pgossip.GossipMessage)

	// GetSignedGossipMessage 返回此 ReceivedMessage 底层的 GossipMessage。
	GetSignedGossipMessage() *SignedGossipMessage

	// GetSourceEnvelope 返回此 ReceivedMessage 内部的 Envelope。
	GetSourceEnvelope() *pgossip.Envelope

	// GetConnectionInfo 返回远程 peer 节点的信息。
	GetConnectionInfo() *ConnectionInfo

	// Ack 向发送方返回对消息的确认。
	Ack(err error)
}

/* ------------------------------------------------------------------------------------------ */

type ConnectionInfo struct {
	PkiID    PKIidType
	AuthInfo *AuthInfo
	Identity PeerIdentityType
	Endpoint string
}

func (info *ConnectionInfo) String() string {
	return fmt.Sprintf("{ConnectionInfo | Endpoint: %s; PKI-ID: %s}", info.Endpoint, info.PkiID.String())
}

/* ------------------------------------------------------------------------------------------ */

type AuthInfo struct {
	SignedData []byte
	Signature  []byte
}

/* ------------------------------------------------------------------------------------------ */

type EmittedGossipMessage struct {
	*SignedGossipMessage
	filter func(id PKIidType) bool
}
