package protoext

import (
	"encoding/hex"
	"fmt"

	"github.com/11090815/mayy/protobuf/pgossip"
)

func MemberToString(m *pgossip.Member) string {
	return fmt.Sprintf("{Member | Endpoint: %s; PKI-ID: %s}", m.Endpoint, hex.EncodeToString(m.PkiId))
}

func MembershipResponseToString(mr *pgossip.MembershipResponse) string {
	return fmt.Sprintf("{MembershipResponse | Alive-Number: %d; Dead-Number: %d}", len(mr.Alive), len(mr.Dead))
}

func AliveMessageToString(am *pgossip.AliveMessage) string {
	var identity string
	if len(am.Identity) == 0 {
		identity = "nil-identity"
	} else if len(am.Identity) < 32 {
		identity = hex.EncodeToString(am.Identity)
	} else {
		identity = hex.EncodeToString(am.Identity[:8]) + "..." + hex.EncodeToString(am.Identity[len(am.Identity)-8:])
	}

	return fmt.Sprintf("{AliveMessage | Endpoint: %s; PKI-ID: %s; PeerTime-IncNum: %d; PeerTime-SeqNum: %d; Identity: %s}",
		am.Membership.Endpoint, hex.EncodeToString(am.Membership.PkiId), am.Timestamp.IncNum, am.Timestamp.SeqNum, identity)
}

func PayloadToString(p *pgossip.Payload) string {
	if p == nil {
		return "nil-payload"
	}
	return fmt.Sprintf("{Payload | SeqNum: %d; Data: %dbytes; PrivateData: %ditems}", p.SeqNum, len(p.Data), len(p.PrivateData))
}

func DataUpdateToString(du *pgossip.DataUpdate) string {
	return fmt.Sprintf("{DataUpdate | Nonce: %d; Data: %ditems; MsgType: %s}", du.Nonce, len(du.Data), pgossip.PullMsgType_name[int32(du.MsgType)])
}

func StateInfoSnapshotToString(sis *pgossip.StateInfoSnapshot) string {
	return fmt.Sprintf("{StateInfoSnapshot | Elements: %ditems}", len(sis.Elements))
}

// TODO 弄清楚 MembershipRequest.SelfInformation 到底是什么
func MembershipRequestToString(mr *pgossip.MembershipRequest) string {
	return fmt.Sprintf("{MembershipRequest | Known: %d}", len(mr.Known))
}

func StateInfoPullRequestToString(sipr *pgossip.StateInfoPullRequest) string {
	return fmt.Sprintf("{StateInfoPullRequest | Channel-MAC: %s}", hex.EncodeToString(sipr.Channel_MAC))
}

func StateInfoToString(si *pgossip.StateInfo) string {
	return fmt.Sprintf("{StateInfo | PeerTime-IncNum: %d; PeerTime-SeqNum: %d; PKI-ID: %s; Channel-MAC: %s; LedgerHight: %d; LeftChannel: %v}",
		si.Timestamp.IncNum, si.Timestamp.SeqNum, hex.EncodeToString(si.PkiId), hex.EncodeToString(si.Channel_MAC), si.Properties.LedgerHeight, si.Properties.LeftChannel)
}

func DataDigestToString(dd *pgossip.DataDigest) string {
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
	return fmt.Sprintf("{LeadershipMessage | PKI-ID: %s; IsDeclaration: %v; PeerTime-IncNum: %d; PeerTime-SeqNum: %d}",
		hex.EncodeToString(lm.PkiId), lm.IsDeclaration, lm.Timestamp.IncNum, lm.Timestamp.SeqNum)
}

func RemotePvtDataResponseToString(rpdr *pgossip.RemotePvtDataResponse) string {
	return fmt.Sprintf("{RemotePvtDataResponse | Elements: %ditmes}", len(rpdr.Elements))
}

func RemoteStateResponseToString(rsr *pgossip.RemoteStateResponse) string {
	return fmt.Sprintf("{RemoteStateResponse | Payloads: %ditems}", len(rsr.Payloads))
}

func ConnEstablishToString(ce *pgossip.ConnEstablish) string {
	var identity string
	if len(ce.Identity) == 0 {
		identity = "nil-identity"
	} else if len(ce.Identity) < 32 {
		identity = hex.EncodeToString(ce.Identity)
	} else {
		identity = hex.EncodeToString(ce.Identity[:8]) + "..." + hex.EncodeToString(ce.Identity[len(ce.Identity)-8:])
	}
	var certHash string
	if len(ce.TlsCertHash) == 0 {
		certHash = "nil tls-cert"
	} else if len(ce.TlsCertHash) < 32 {
		certHash = hex.EncodeToString(ce.TlsCertHash)
	} else {
		certHash = hex.EncodeToString(ce.TlsCertHash[:8]) + "..." + hex.EncodeToString(ce.TlsCertHash[len(ce.TlsCertHash)-8:])
	}
	return fmt.Sprintf("{ConnEstablish | PKI-ID: %s, Identity: %s, TlsCertHash: %s, Probe: %v}", hex.EncodeToString(ce.PkiId), identity, certHash, ce.Probe)
}

func DataMessageToString(dm *pgossip.DataMessage) string {
	return fmt.Sprintf("{DataMessage | Payload: %s}", PayloadToString(dm.Payload))
}
