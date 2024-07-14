package utils

import (
	"encoding/hex"
	"fmt"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/protobuf/pgossip"
	"google.golang.org/protobuf/proto"
)

type SignFuncType func(msg []byte) ([]byte, error)

type VerifyFuncType func(peerIdentity PeerIdentityType, signature, message []byte) error

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

func (sgm *SignedGossipMessage) Verify(peerIdentity PeerIdentityType, verifyFunc VerifyFuncType) error {
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

/* ------------------------------------------------------------------------------------------ */

func MemberToString(m *pgossip.Member) string {
	if m == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{Member | Endpoint: %s; PKI-ID: %s}", m.Endpoint, hex.EncodeToString(m.PkiId))
}

func MembershipResponseToString(mr *pgossip.MembershipResponse) string {
	if mr == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{MembershipResponse | Alive-Number: %d; Dead-Number: %d}", len(mr.Alive), len(mr.Dead))
}

func AliveMessageToString(am *pgossip.AliveMessage) string {
	if am == nil {
		return "<nil>"
	}
	var identity string
	if len(am.Identity) == 0 {
		identity = "<nil>"
	} else if len(am.Identity) < 32 {
		identity = hex.EncodeToString(am.Identity)
	} else {
		identity = hex.EncodeToString(am.Identity[:8]) + "..." + hex.EncodeToString(am.Identity[len(am.Identity)-8:])
	}

	return fmt.Sprintf("{AliveMessage | Endpoint: %s; PKI-ID: %s; IncNum: %d; SeqNum: %d; Identity: %s}",
		am.Membership.Endpoint, hex.EncodeToString(am.Membership.PkiId), am.Timestamp.IncNum, am.Timestamp.SeqNum, identity)
}

func PayloadToString(p *pgossip.Payload) string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{Payload | SeqNum: %d; Data: %d byte(s); PrivateData: %d item(s)}", p.SeqNum, len(p.Data), len(p.PrivateData))
}

func DataUpdateToString(du *pgossip.DataUpdate) string {
	if du == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{DataUpdate | Nonce: %d; Data: %d item(s); MsgType: %s}", du.Nonce, len(du.Data), pgossip.PullMsgType_name[int32(du.MsgType)])
}

func StateInfoSnapshotToString(sis *pgossip.StateInfoSnapshot) string {
	if sis == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{StateInfoSnapshot | Elements: %d item(s)}", len(sis.Elements))
}

// TODO 弄清楚 MembershipRequest.SelfInformation 到底是什么
func MembershipRequestToString(mr *pgossip.MembershipRequest) string {
	if mr == nil {
		return "<nil>"
	}
	sgm, _ := EnvelopeToSignedGossipMessage(mr.SelfInformation)
	return fmt.Sprintf("{MembershipRequest | SelfInformation: %s}", AliveMessageToString(sgm.GetAliveMsg()))
}

func StateInfoPullRequestToString(sipr *pgossip.StateInfoPullRequest) string {
	if sipr == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{StateInfoPullRequest | Channel-MAC: %s}", hex.EncodeToString(sipr.Channel_MAC))
}

func StateInfoToString(si *pgossip.StateInfo) string {
	if si == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{StateInfo | PeerTime-IncNum: %d; PeerTime-SeqNum: %d; PKI-ID: %s; Channel-MAC: %s; LedgerHight: %d; LeftChannel: %v}",
		si.Timestamp.IncNum, si.Timestamp.SeqNum, hex.EncodeToString(si.PkiId), hex.EncodeToString(si.Channel_MAC), si.Properties.LedgerHeight, si.Properties.LeftChannel)
}

func DataDigestToString(dd *pgossip.DataDigest) string {
	if dd == nil {
		return "<nil>"
	}
	digests := "["
	for i, digest := range dd.Digests {
		digests = digests + fmt.Sprintf("%d:%s", i, string(digest))
		if i < len(dd.Digests)-1 {
			digests = digests + ", "
		}
	}
	digests = digests + "]"
	return fmt.Sprintf("{DataDigest | Nonce: %d; MsgType: %s; Digests: %s}", dd.Nonce, dd.MsgType.String(), digests)
}

func DataRequestToString(dr *pgossip.DataRequest) string {
	if dr == nil {
		return "<nil>"
	}
	digests := "["
	for i, digest := range dr.Digests {
		digests = digests + fmt.Sprintf("%d:%s", i, string(digest))
		if i < len(dr.Digests)-1 {
			digests = digests + ", "
		}
	}
	digests = digests + "]"
	return fmt.Sprintf("{DataDigest | Nonce: %d; MsgType: %s; Digests: %s}", dr.Nonce, dr.MsgType.String(), digests)
}

func LeadershipMessageToString(lm *pgossip.LeadershipMessage) string {
	if lm == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{LeadershipMessage | PKI-ID: %s; IsDeclaration: %v; PeerTime-IncNum: %d; PeerTime-SeqNum: %d}",
		hex.EncodeToString(lm.PkiId), lm.IsDeclaration, lm.Timestamp.IncNum, lm.Timestamp.SeqNum)
}

func RemotePvtDataResponseToString(rpdr *pgossip.RemotePvtDataResponse) string {
	if rpdr == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{RemotePvtDataResponse | Elements: %ditmes}", len(rpdr.Elements))
}

func RemoteStateResponseToString(rsr *pgossip.RemoteStateResponse) string {
	if rsr == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{RemoteStateResponse | Payloads: %ditems}", len(rsr.Payloads))
}

func ConnEstablishToString(ce *pgossip.ConnEstablish) string {
	if ce == nil {
		return "<nil>"
	}
	var identity string
	if len(ce.Identity) == 0 {
		identity = "<nil>"
	} else if len(ce.Identity) < 32 {
		identity = hex.EncodeToString(ce.Identity)
	} else {
		identity = hex.EncodeToString(ce.Identity[:8]) + "..." + hex.EncodeToString(ce.Identity[len(ce.Identity)-8:])
	}
	var certHash string
	if len(ce.TlsCertHash) == 0 {
		certHash = "<nil>"
	} else if len(ce.TlsCertHash) < 32 {
		certHash = hex.EncodeToString(ce.TlsCertHash)
	} else {
		certHash = hex.EncodeToString(ce.TlsCertHash[:8]) + "..." + hex.EncodeToString(ce.TlsCertHash[len(ce.TlsCertHash)-8:])
	}
	return fmt.Sprintf("{ConnEstablish | PKI-ID: %s, Identity: %s, TlsCertHash: %s, Probe: %v}", hex.EncodeToString(ce.PkiId), identity, certHash, ce.Probe)
}

func DataMessageToString(dm *pgossip.DataMessage) string {
	if dm == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{DataMessage | Payload: %s}", PayloadToString(dm.Payload))
}

func PropertiesToString(properties *pgossip.Properties) string {
	if properties == nil {
		return "<nil>"
	}
	var chaincodes []string
	for _, chaincode := range properties.Chaincodes {
		chaincodes = append(chaincodes, chaincode.Name)
	}

	return fmt.Sprintf("{Properties | LedgerHeight: %d; LeftChannel: %v; Chaincodes: %v}", properties.LedgerHeight, properties.LeftChannel, chaincodes)
}

func EnvelopeToString(envelope *pgossip.Envelope) string {
	if envelope == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{Envelope | Payload: %d byte(s); Signature: %d byte(s); SecretEnvelope: %s}",
		len(envelope.Payload), len(envelope.Signature), SecretEnvelopeToString(envelope.SecretEnvelope))
}

func SecretEnvelopeToString(se *pgossip.SecretEnvelope) string {
	if se == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{SecretEnvelope | Payload: %d byte(s); Signature: %d byte(s)}", len(se.Payload), len(se.Signature))
}

func PeerTimeToString(pt *pgossip.PeerTime) string {
	if pt == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{PeerTime | IncNum: %d; SeqNum: %d}", pt.IncNum, pt.SeqNum)
}

/* ------------------------------------------------------------------------------------------ */

func IsPullMsg(m *pgossip.GossipMessage) bool {
	return m.GetDataReq() != nil || m.GetDataUpdate() != nil || m.GetHello() != nil || m.GetDataDig() != nil
}

func GetPullMsgType(m *pgossip.GossipMessage) pgossip.PullMsgType {
	if helloMsg := m.GetHello(); helloMsg != nil {
		return helloMsg.MsgType
	}

	if dataReq := m.GetDataReq(); dataReq != nil {
		return dataReq.MsgType
	}

	if dataUpdate := m.GetDataUpdate(); dataUpdate != nil {
		return dataUpdate.MsgType
	}

	if dataDig := m.GetDataDig(); dataDig != nil {
		return dataDig.MsgType
	}

	return pgossip.PullMsgType_UNDEFINED
}
