package gossip

import (
	"bytes"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/gossip/pull"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
)

type certStore struct {
	selfIdentity utils.PeerIdentityType
	idMapper     utils.IdentityMapper
	pull         pull.PullMediator
	logger       mlog.Logger
	mcs          utils.MessageCryptoService
}

func newCertStore(puller pull.PullMediator, idMapper utils.IdentityMapper, selfIdentity utils.PeerIdentityType, mcs utils.MessageCryptoService, logger mlog.Logger) *certStore {
	selfPKIID := idMapper.GetPKIidOfCert(selfIdentity)
	cs := &certStore{
		selfIdentity: selfIdentity,
		idMapper:     idMapper,
		pull:         puller,
		logger:       logger,
		mcs:          mcs,
	}
	if err := idMapper.Put(selfPKIID, selfIdentity); err != nil {
		logger.Panicf("Failed putting self pki-id and identity to mapper: %s.", err.Error())
	}
	selfIdentityMsg, err := cs.createIdentityMessage()
	if err != nil {
		logger.Panicf("Failed creating self identity msg: %s.", err.Error())
	}
	puller.Add(selfIdentityMsg)
	// TODO fabric 这里写的是 RequestMsgType，应该是有问题的，我觉得应该是 ResponseMsgType
	puller.RegisterMsgHook(pull.ResponseMsgType, func(itemIDs []string, items []*utils.SignedGossipMessage, msg utils.ReceivedMessage) {
		for _, msg := range items {
			pkiID := utils.PKIidType(msg.GetPeerIdentity().PkiId)
			cert := utils.PeerIdentityType(msg.GetPeerIdentity().Cert)
			if err := cs.idMapper.Put(pkiID, cert); err != nil {
				cs.logger.Errorf("Failed adding identity: %s.", err.Error())
			}
		}
	})

	return cs
}

func (cs *certStore) handleMessage(msg utils.ReceivedMessage) {
	if dataUpdate := msg.GetSignedGossipMessage().GetDataUpdate(); dataUpdate != nil {
		for _, envelope := range dataUpdate.Data {
			sgm, err := utils.EnvelopeToSignedGossipMessage(envelope)
			if err != nil {
				cs.logger.Errorf("data update contains an invalid message: %s.", err.Error())
				return
			}
			if sgm.GetPeerIdentity() == nil {
				cs.logger.Warnf("Expect to get peer identity msg, but got %s.", sgm.String())
				return
			}
			if err := cs.validateIdentityMsg(sgm); err != nil {
				cs.logger.Errorf("Failed validating identity msg: %s.", err.Error())
				return
			}
		}
	}
	cs.pull.HandleMessage(msg)
}

func (cs *certStore) validateIdentityMsg(msg *utils.SignedGossipMessage) error {
	idMsg := msg.GetPeerIdentity()
	if idMsg == nil {
		return errors.NewError("the received identity msg is nil")
	}

	pkiID := utils.PKIidType(idMsg.PkiId)
	cert := utils.PeerIdentityType(idMsg.Cert)
	calculatedPKIID := cs.mcs.GetPKIidOfCert(cert)
	if !bytes.Equal(pkiID, calculatedPKIID) {
		return errors.NewErrorf("calculated pki-id doesn't match identity: calculated pki-id (%s), received pki-id (%s), identity (%s)", calculatedPKIID.String(), pkiID.String(), cert.String())
	}

	// 验证 SignedGossipMessage 内的签名
	verifier := func(peerIdentity utils.PeerIdentityType, signature, message []byte) error {
		return cs.mcs.Verify(peerIdentity, signature, message)
	}
	if err := msg.Verify(cert, verifier); err != nil {
		return errors.NewErrorf("failed verifying identity message: %s", err.Error())
	}

	return cs.mcs.ValidateIdentity(cert)
}

func (cs *certStore) createIdentityMessage() (*utils.SignedGossipMessage, error) {
	msg := &pgossip.GossipMessage{
		Channel: nil,
		Nonce:   0,
		Tag:     pgossip.GossipMessage_EMPTY,
		Content: &pgossip.GossipMessage_PeerIdentity{
			PeerIdentity: &pgossip.PeerIdentity{
				Cert:     cs.selfIdentity,
				Metadata: nil,
				PkiId:    cs.idMapper.GetPKIidOfCert(cs.selfIdentity),
			},
		},
	}

	signer := func(m []byte) ([]byte, error) {
		return cs.mcs.Sign(m)
	}
	sgm := &utils.SignedGossipMessage{
		GossipMessage: msg,
	}
	_, err := sgm.Sign(signer)
	return sgm, err
}

func (cs *certStore) suspectPeers(isSuspected utils.PeerSuspector) {
	cs.idMapper.SuspectPeers(isSuspected)
}

func (cs *certStore) stop() {
	cs.pull.Stop()
	cs.idMapper.Stop()
}
