package protoext

import (
	"encoding/hex"
	"fmt"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
	"google.golang.org/protobuf/proto"
)

type SignFuncType func(msg []byte) ([]byte, error)

type VerifyFuncType func(peerIdentity utils.PeerIdentityType, signature, message []byte) error

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

func (sgm *SignedGossipMessage) Verify(peerIdentity utils.PeerIdentityType, verifyFunc VerifyFuncType) error {
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
	envelope := EnvelopeToString(sgm.Envelope)

	gossipMessage := GossipMessageToString(sgm.GossipMessage)

	return fmt.Sprintf("{SignedGossipMessage | GossipMessage: %s; Envelope: %s}", gossipMessage, envelope)
}

func GossipMessageToString(gm *pgossip.GossipMessage) string {
	gossipMessage := "<nil>"
	var isSimple bool = false
	if gm != nil {
		if gm.GetRemoteStateRes() != nil {
			gossipMessage = RemoteStateResponseToString(gm.GetRemoteStateRes())
		} else if gm.GetDataMsg() != nil && gm.GetDataMsg().Payload != nil {
			gossipMessage = DataMessageToString(gm.GetDataMsg())
		} else if gm.GetDataUpdate() != nil {
			gossipMessage = DataUpdateToString(gm.GetDataUpdate())
		} else if gm.GetMemRes() != nil {
			gossipMessage = MembershipResponseToString(gm.GetMemRes())
		} else if gm.GetStateInfoSnapshot() != nil {
			gossipMessage = StateInfoSnapshotToString(gm.GetStateInfoSnapshot())
		} else if gm.GetRemotePvtDataRes() != nil {
			gossipMessage = RemotePvtDataResponseToString(gm.GetRemotePvtDataRes())
		} else if gm.GetAliveMsg() != nil {
			gossipMessage = AliveMessageToString(gm.GetAliveMsg())
		} else if gm.GetMemReq() != nil {
			gossipMessage = MembershipRequestToString(gm.GetMemReq())
		} else if gm.GetStateInfoPullReq() != nil {
			gossipMessage = StateInfoPullRequestToString(gm.GetStateInfoPullReq())
		} else if gm.GetStateInfo() != nil {
			gossipMessage = StateInfoToString(gm.GetStateInfo())
		} else if gm.GetDataDig() != nil {
			gossipMessage = DataDigestToString(gm.GetDataDig())
		} else if gm.GetDataReq() != nil {
			gossipMessage = DataRequestToString(gm.GetDataReq())
		} else if gm.GetLeadershipMsg() != nil {
			gossipMessage = LeadershipMessageToString(gm.GetLeadershipMsg())
		} else if gm.GetConnEstablish() != nil {
			gossipMessage = ConnEstablishToString(gm.GetConnEstablish())
		} else if gm.GetDataMsg() != nil {
			gossipMessage = DataMessageToString(gm.GetDataMsg())
		} else {
			gossipMessage = gm.String()
			isSimple = true
		}
		if !isSimple {
			description := fmt.Sprintf("{Description | Channel: %s, Nonce: %d, Tag: %s}", ChannelToString(gm.Channel), gm.Nonce, gm.Tag.String())
			gossipMessage = fmt.Sprintf("{%s %s}", description, gossipMessage)
		}
	}

	return gossipMessage
}

/* ------------------------------------------------------------------------------------------ */

// SignSecret 仅仅就是将 internal endpoint 作为签名信息进行签名，然后将签名信息和签名作为 SecretEnvelope 结构体的
// 两个字段。
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
