package discovery

import (
	"time"

	"github.com/11090815/mayy/gossip/protoext"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
)

type CryptoService interface {
	ValidateAliveMsg(message *protoext.SignedGossipMessage) bool

	SignMessage(m *pgossip.GossipMessage, internalEndpoint string) *pgossip.Envelope
}

type discoverySecurityAdapter struct {
	identity utils.PeerIdentityType
	includeIdentityPeriod time.Time
	idMapper utils.IdentityMapper
	securityAdvisor utils.SecurityAdvisor
	messageCryptoService utils.MessageCryptoService
	
}
