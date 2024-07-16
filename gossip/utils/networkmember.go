package utils

import (
	"fmt"

	"github.com/11090815/mayy/protobuf/pgossip"
	"google.golang.org/protobuf/proto"
)

type NetworkMember struct {
	Endpoint          string
	InternalEndpoint  string
	Metadata          []byte
	PKIid             PKIidType
	Properties        *pgossip.Properties
	*pgossip.Envelope // 存储着 StateInfo 信息
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

func (nm NetworkMember) HasExternalEndpoint() bool {
	return nm.Endpoint != ""
}

func (nm NetworkMember) String() string {
	return fmt.Sprintf("{NetworkMember | Endpoint: %s; InternalEndpoint: %s; Metadata: %dbytes; PKI-ID: %s; Properties: %s; Envelope: %s}",
		nm.Endpoint, nm.InternalEndpoint, len(nm.Metadata), nm.PKIid.String(), PropertiesToString(nm.Properties), EnvelopeToString(nm.Envelope))
}

func (nm NetworkMember) SimpleString() string {
	return fmt.Sprintf("{PKI-ID: %s; Endpoint: %s; InternalEndpoint: %s}", nm.PKIid.String(), nm.Endpoint, nm.InternalEndpoint)
}

/* ------------------------------------------------------------------------------------------ */

type Members []NetworkMember

// ByID 将 Members ([]NetworkMember) 转化成 mapper: PKI-ID => NetworkMember。
func (members Members) ByID() map[string]NetworkMember {
	mapper := make(map[string]NetworkMember)
	for _, peer := range members {
		mapper[peer.PKIid.String()] = peer
	}
	return mapper
}

// Intersect 获得两个 Members 的交集。
func (members Members) Intersect(otherMembers Members) Members {
	var intersect Members
	otherMap := otherMembers.ByID()
	for _, peer := range members {
		if _, exists := otherMap[peer.PKIid.String()]; exists {
			intersect = append(intersect, peer)
		}
	}
	return intersect
}

func (members Members) Filter(filter func(peer NetworkMember) bool) Members {
	var res Members
	for _, peer := range members {
		if filter(peer) {
			res = append(res, peer)
		}
	}
	return res
}

// Map 对 Members 里的每个 NetworkMember 调用一次给定的函数。
func (members Members) Map(f func(NetworkMember) NetworkMember) Members {
	var res Members
	for _, peer := range members {
		res = append(res, f(peer))
	}
	return res
}

/* ------------------------------------------------------------------------------------------ */

type RemotePeer struct {
	Endpoint string
	PKIID    PKIidType
}

func (rp *RemotePeer) String() string {
	return fmt.Sprintf("{RemotePeer | Endpoint: %s; PKI-ID: %s}", rp.Endpoint, rp.PKIID.String())
}
