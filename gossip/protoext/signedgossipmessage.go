package protoext

import (
	"encoding/hex"
	"fmt"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/protobuf/pgossip"
	"google.golang.org/protobuf/proto"
)

type SignFuncType func(msg []byte) ([]byte, error)

type VerifyFuncType func(peerIdentity, signature, message []byte) error

type SignedGossipMessage struct {
	*pgossip.Envelope
	*pgossip.GossipMessage
}

func (sgm *SignedGossipMessage) Sign(signFunc SignFuncType) (*pgossip.Envelope, error) {
	// 不要修改私密数据
	var secretEnvelope *pgossip.SecretEnvelope
	if sgm.Envelope != nil {
		secretEnvelope = sgm.Envelope.SecretEnvelope
	}
	sgm.Envelope = nil
	payload, err := proto.Marshal(sgm.GossipMessage)
	if err != nil {
		return nil, err
	}
	signature, err := signFunc(payload)
	if err != nil {
		return nil, err
	}

	envelope := &pgossip.Envelope{
		Payload:        payload,
		Signature:      signature,
		SecretEnvelope: secretEnvelope,
	}
	sgm.Envelope = envelope
	return envelope, nil
}

func (sgm *SignedGossipMessage) Verify(peerIdentity []byte, verifyFunc VerifyFuncType) error {
	if sgm.Envelope == nil {
		return errors.NewError("missing envelope")
	}
	if err := verifyFunc(peerIdentity, sgm.Envelope.Signature, sgm.Envelope.Payload); err != nil {
		return err
	}
	if sgm.Envelope.SecretEnvelope != nil {
		return verifyFunc(peerIdentity, sgm.Envelope.SecretEnvelope.Signature, sgm.Envelope.SecretEnvelope.Payload)
	}
	return nil
}

func (sgm *SignedGossipMessage) IsSigned() bool {
	return sgm.Envelope != nil && sgm.Envelope.Payload != nil && sgm.Envelope.Signature != nil
}

func (sgm *SignedGossipMessage) String() string {
	envelope := "Nil-Envelope"
	if sgm.Envelope != nil {
		var secretEnvelope string
		if sgm.SecretEnvelope != nil {
			secretEnvelopePayloadLen := len(sgm.SecretEnvelope.Payload)
			secretEnvelopeSignatureLen := len(sgm.SecretEnvelope.Signature)
			secretEnvelope = fmt.Sprintf("{SecretEnvelope | Payload: %dbytes; Signature %dbytes}", secretEnvelopePayloadLen, secretEnvelopeSignatureLen)
		}
		if secretEnvelope != "" {
			envelope = fmt.Sprintf("{{Envelope | Payload: %dbytes; Signature: %dbytes} %s}", len(sgm.Envelope.Payload), len(sgm.Envelope.Signature), secretEnvelope)
		} else {
			envelope = fmt.Sprintf("{Envelope | Payload: %dbytes; Signature: %dbytes}", len(sgm.Envelope.Payload), len(sgm.Envelope.Signature))
		}
	}

	gossipMessage := "Nil-GossipMessage"
	var isSimple bool = false
	if sgm.GossipMessage != nil {
		if sgm.GetRemoteStateRes() != nil {
			gossipMessage = RemoteStateResponseToString(sgm.GetRemoteStateRes())
		} else if sgm.GetDataMsg() != nil && sgm.GetDataMsg().Payload != nil {
			gossipMessage = PayloadToString(sgm.GetDataMsg().Payload)
		} else if sgm.GetDataUpdate() != nil {
			gossipMessage = DataUpdateToString(sgm.GetDataUpdate())
		} else if sgm.GetMemRes() != nil {
			gossipMessage = MembershipResponseToString(sgm.GetMemRes())
		} else if sgm.GetStateInfoSnapshot() != nil {
			gossipMessage = StateInfoSnapshotToString(sgm.GetStateInfoSnapshot())
		} else if sgm.GetRemotePvtDataRes() != nil {
			gossipMessage = RemotePvtDataResponseToString(sgm.GetRemotePvtDataRes())
		} else if sgm.GetAliveMsg() != nil {
			gossipMessage = AliveMessageToString(sgm.GetAliveMsg())
		} else if sgm.GetMemReq() != nil {
			gossipMessage = MembershipRequestToString(sgm.GetMemReq())
		} else if sgm.GetStateInfoPullReq() != nil {
			gossipMessage = StateInfoPullRequestToString(sgm.GetStateInfoPullReq())
		} else if sgm.GetStateInfo() != nil {
			gossipMessage = StateInfoToString(sgm.GetStateInfo())
		} else if sgm.GetDataDig() != nil {
			gossipMessage = DataDigestToString(sgm.GetDataDig())
		} else if sgm.GetDataReq() != nil {
			gossipMessage = DataRequestToString(sgm.GetDataReq())
		} else if sgm.GetLeadershipMsg() != nil {
			gossipMessage = LeadershipMessageToString(sgm.GetLeadershipMsg())
		} else if sgm.GetConnEstablish() != nil {
			gossipMessage = ConnEstablishToString(sgm.GetConnEstablish())
		} else if sgm.GetDataMsg() != nil {
			gossipMessage = DataMessageToString(sgm.GetDataMsg())
		} else {
			gossipMessage = sgm.GossipMessage.String()
			isSimple = true
		}
		if !isSimple {
			description := fmt.Sprintf("{Description | Channel: %s, Nonce: %d, Tag: %s}", ChannelToString(sgm.Channel), sgm.Nonce, sgm.Tag.String())
			gossipMessage = fmt.Sprintf("{%s %s}", description, gossipMessage)
		}
	}

	return fmt.Sprintf("{SignedGossipMessage | GossipMessage: %s; Envelope: %s}", gossipMessage, envelope)
}

/* ------------------------------------------------------------------------------------------ */

func SignSecret(envelope *pgossip.Envelope, signFunc SignFuncType, secret *pgossip.Secret) error {
	payload, err := proto.Marshal(secret)
	if err != nil {
		return err
	}
	signature, err := signFunc(payload)
	if err != nil {
		return err
	}
	envelope.SecretEnvelope = &pgossip.SecretEnvelope{
		Payload:   payload,
		Signature: signature,
	}
	return nil
}

func NoopSign(gm *pgossip.GossipMessage) (*SignedGossipMessage, error) {
	sgm := &SignedGossipMessage{
		GossipMessage: gm,
	}
	payload, err := proto.Marshal(sgm.GossipMessage)
	if err != nil {
		return nil, err
	}
	sgm.Envelope = &pgossip.Envelope{
		Payload: payload,
	}

	return sgm, nil
}

func EnvelopeToSignedGossipMessage(envelope *pgossip.Envelope) (*SignedGossipMessage, error) {
	if envelope == nil {
		return nil, errors.NewError("nil envelope")
	}
	gm := &pgossip.GossipMessage{}
	if err := proto.Unmarshal(envelope.Payload, gm); err != nil {
		return nil, err
	}
	return &SignedGossipMessage{
		GossipMessage: gm,
		Envelope:      envelope,
	}, nil
}

func InternalEndpoint(se *pgossip.SecretEnvelope) string {
	if se == nil {
		return ""
	}
	secret := &pgossip.Secret{}
	if err := proto.Unmarshal(se.Payload, secret); err != nil {
		return ""
	}
	return secret.GetInternalEndpoint()
}

func ChannelToString(channel []byte) string {
	if len(channel) == 0 {
		return "nil-channel"
	}
	return hex.EncodeToString(channel)
}
