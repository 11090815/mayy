package comm

import "github.com/11090815/mayy/gossip/protoext"

type ReceivedMessageImpl struct {
	*protoext.SignedGossipMessage
	conn     *connection
	connInfo *protoext.ConnectionInfo
}
