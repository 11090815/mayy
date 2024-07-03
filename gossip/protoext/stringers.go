package protoext

import (
	"encoding/hex"
	"fmt"

	"github.com/11090815/mayy/protobuf/pgossip"
)

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
	return fmt.Sprintf("{Payload | SeqNum: %d; Data: %dbytes; PrivateData: %ditems}", p.SeqNum, len(p.Data), len(p.PrivateData))
}

func DataUpdateToString(du *pgossip.DataUpdate) string {
	if du == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{DataUpdate | Nonce: %d; Data: %ditems; MsgType: %s}", du.Nonce, len(du.Data), pgossip.PullMsgType_name[int32(du.MsgType)])
}

func StateInfoSnapshotToString(sis *pgossip.StateInfoSnapshot) string {
	if sis == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{StateInfoSnapshot | Elements: %ditems}", len(sis.Elements))
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
		digests = digests + fmt.Sprintf("%d:%s", i, hex.EncodeToString(digest))
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
		digests = digests + fmt.Sprintf("%d:%s", i, hex.EncodeToString(digest))
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
	return fmt.Sprintf("{Envelope | Payload: %dbytes; Signature: %dbytes; SecretEnvelope: %s}",
		len(envelope.Payload), len(envelope.Signature), SecretEnvelopeToString(envelope.SecretEnvelope))
}

func SecretEnvelopeToString(se *pgossip.SecretEnvelope) string {
	if se == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{SecretEnvelope | Payload: %dbytes; Signature: %dbytes}", len(se.Payload), len(se.Signature))
}

func PeerTimeToString(pt *pgossip.PeerTime) string {
	if pt == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{PeerTime | IncNum: %d; SeqNum: %d}", pt.IncNum, pt.SeqNum)
}
