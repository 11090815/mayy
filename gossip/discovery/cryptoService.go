package discovery

import (
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
)

type CryptoService interface {
	ValidateAliveMsg(message *utils.SignedGossipMessage) bool

	SignMessage(m *pgossip.GossipMessage, internalEndpoint string) *pgossip.Envelope
}

/* ------------------------------------------------------------------------------------------ */

type discoverySecurityAdapter struct {
	identity              utils.PeerIdentityType
	includeIdentityPeriod time.Time
	idMapper              utils.IdentityMapper
	messageCryptoService  utils.MessageCryptoService
	logger                mlog.Logger
}

func newDiscoverySecurityAdapter(identity utils.PeerIdentityType, iip time.Time,
	idMapper utils.IdentityMapper, mcs utils.MessageCryptoService, logger mlog.Logger) *discoverySecurityAdapter {
	return &discoverySecurityAdapter{
		identity:              identity,
		includeIdentityPeriod: iip,
		idMapper:              idMapper,
		messageCryptoService:  mcs,
		logger:                logger,
	}
}

func (dsa *discoverySecurityAdapter) ValidateAliveMsg(sgm *utils.SignedGossipMessage) bool {
	aliveMsg := sgm.GetAliveMsg()
	if aliveMsg == nil || aliveMsg.Membership == nil || aliveMsg.Membership.PkiId == nil || !sgm.IsSigned() {
		dsa.logger.Errorf("Invalid alive message: %s.", utils.AliveMessageToString(aliveMsg))
		return false
	}

	var identity utils.PeerIdentityType

	if aliveMsg.Identity != nil {
		identity = aliveMsg.Identity
		claimedPKIID := aliveMsg.Membership.PkiId
		if err := dsa.idMapper.Put(claimedPKIID, identity); err != nil {
			dsa.logger.Errorf("Failed validating identity of %s, error: %s.", utils.AliveMessageToString(aliveMsg), err.Error())
			return false
		}
	} else {
		identity, _ = dsa.idMapper.Get(aliveMsg.Membership.PkiId)
		if identity != nil {
			dsa.logger.Debugf("Fetched identity of %s from identity store.", utils.MemberToString(aliveMsg.Membership))
		} else {
			dsa.logger.Errorf("Can't fetch certificate for %s.", utils.AliveMessageToString(aliveMsg))
			return false
		}
	}

	return dsa.validateAliveMsgSignature(sgm, identity)
}

func (dsa *discoverySecurityAdapter) SignMessage(gm *pgossip.GossipMessage, internalEndpoint string) *pgossip.Envelope {
	signer := func(msg []byte) ([]byte, error) {
		return dsa.messageCryptoService.Sign(msg)
	}

	if gm.GetAliveMsg() != nil && time.Now().Before(dsa.includeIdentityPeriod) {
		gm.GetAliveMsg().Identity = dsa.identity
	}
	sgm := &utils.SignedGossipMessage{
		GossipMessage: gm,
	}
	envelope, err := sgm.Sign(signer)
	if err != nil {
		dsa.logger.Errorf("Failed signing message %s, error: %s.", utils.GossipMessageToString(gm), err.Error())
		return nil
	}

	if internalEndpoint == "" {
		return envelope
	}

	utils.SignSecret(envelope, signer, &pgossip.Secret{
		Content: &pgossip.Secret_InternalEndpoint{
			InternalEndpoint: internalEndpoint,
		},
	})

	return envelope
}

func (dsa *discoverySecurityAdapter) validateAliveMsgSignature(sgm *utils.SignedGossipMessage, identity utils.PeerIdentityType) bool {
	verifier := func(identity utils.PeerIdentityType, signature, message []byte) error {
		return dsa.messageCryptoService.Verify(identity, signature, message)
	}

	if err := sgm.Verify(identity, verifier); err != nil {
		dsa.logger.Errorf("Failed verifying message %s, error: %s.", sgm.String(), err.Error())
		return false
	}

	return true
}
