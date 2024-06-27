package discovery

import (
	"fmt"

	"github.com/11090815/mayy/gossip/protoext"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
	"google.golang.org/protobuf/proto"
)

// EnvelopeFilter 会过滤掉 SignedGossipMessage 中的部分信息得到一个 Envelope。
type EnvelopeFilter func(message *protoext.SignedGossipMessage) *pgossip.Envelope

// Sieve 决定了是否能将 SignedGossipMessage 发送给远程节点。
type Sieve func(message *protoext.SignedGossipMessage) bool

// DisclosurePolicy 定义了给定的远程对等体有资格了解哪些消息，以及从给定的 SignedGossipMessage 中有资格了解哪些消息。
type DisclosurePolicy func(remotePeer *NetworkMember) (Sieve, EnvelopeFilter)

type identifier func() (*PeerIdentification, error)

/* ------------------------------------------------------------------------------------------ */

type NetworkMember struct {
	Endpoint         string
	InternalEndpoint string
	Metadata         []byte
	PKIid            utils.PKIidType
	Properties       *pgossip.Properties
	*pgossip.Envelope
}

func (nm NetworkMember) Clone() NetworkMember {
	pkiIDClone := make([]byte, len(nm.PKIid))
	copy(pkiIDClone, nm.PKIid)
	metadataClone := make([]byte, len(nm.Metadata))
	copy(metadataClone, nm.Metadata)
	clone := NetworkMember{
		Endpoint:         nm.Endpoint,
		InternalEndpoint: nm.InternalEndpoint,
		Metadata:         metadataClone,
		PKIid:            pkiIDClone,
		Properties:       proto.Clone(nm.Properties).(*pgossip.Properties),
		Envelope:         proto.Clone(nm.Envelope).(*pgossip.Envelope),
	}

	return clone
}

func (nm NetworkMember) PreferredEndpoint() string {
	if nm.InternalEndpoint != "" {
		return nm.InternalEndpoint
	}
	return nm.Endpoint
}

func (nm NetworkMember) String() string {
	return fmt.Sprintf("{NetworkMember | Endpoint: %s; InternalEndpoint: %s; Metadata: %dbytes; PKI-ID: %s; Properties: %s; Envelope: %s}",
		nm.Endpoint, nm.InternalEndpoint, len(nm.Metadata), nm.PKIid.String(), protoext.PropertiesToString(nm.Properties), protoext.EnvelopeToString(nm.Envelope))
}

/* ------------------------------------------------------------------------------------------ */

type PeerIdentification struct {
	PKIid   utils.PKIidType
	SelfOrg bool // 用于表示是否与自己同属于同一组织
}

/* ------------------------------------------------------------------------------------------ */

// AnchorPeerTracker 给定一个节点的 endpoint，判断该节点是否是锚点。
type AnchorPeerTracker interface {
	IsAnchorPeer(endpoint string) bool
}

type CommService interface {
	// Gossip 广播。
	Gossip(msg *protoext.SignedGossipMessage)

	// SendToPeer 单播。
	SendToPeer(peer *NetworkMember, msg *protoext.SignedGossipMessage)
}
