package utils

type RoutingFilter func(NetworkMember) bool

/* ------------------------------------------------------------------------------------------ */

var SelectNoncePolicy RoutingFilter = func(nm NetworkMember) bool {
	return false
}

var SelectAllPolicy RoutingFilter = func(nm NetworkMember) bool {
	return true
}

/* ------------------------------------------------------------------------------------------ */

// CombineRoutingFilters 根据给定的多个过滤规则 filters 构造一个复合的过滤规则，此过滤规则要求 peer 节点必须满足
// 所有给定的过滤规则才会返回 true。
func CombineRoutingFilters(filters ...RoutingFilter) RoutingFilter {
	return func(nm NetworkMember) bool {
		for _, filter := range filters {
			if !filter(nm) {
				return false
			}
		}
		return true
	}
}

// SelectMembers 从给定的 peers 随机选出 k 个满足给定过滤规则 filter 的 peer。
func SelectMembers(k int, peers []NetworkMember, filter RoutingFilter) []*NetworkMember {
	var res []*NetworkMember
	randomIndices := random.Perm(len(peers))

	for _, index := range randomIndices {
		if len(res) == k {
			break
		}
		if filter(peers[index]) {
			res = append(res, &NetworkMember{
				PKIid:            peers[index].PKIid,
				Endpoint:         peers[index].Endpoint,
				InternalEndpoint: peers[index].InternalEndpoint,
			})
		}
	}
	return res
}

func SelectPeers(k int, peers []NetworkMember, filter RoutingFilter) []*RemotePeer {
	var res []*RemotePeer
	randomIndices := random.Perm(len(peers))

	for _, index := range randomIndices {
		if len(res) == k {
			break
		}
		if filter(peers[index]) {
			res = append(res, &RemotePeer{
				PKIID:    peers[index].PKIid,
				Endpoint: peers[index].PreferredEndpoint(),
			})
		}
	}
	return res
}

// First 从给定的 peers 中选出第一个满足给定过滤规则 filter 的 peer 节点。
func First(peers []NetworkMember, filter RoutingFilter) *NetworkMember {
	for _, peer := range peers {
		if filter(peer) {
			return &NetworkMember{PKIid: peer.PKIid, Endpoint: peer.Endpoint, InternalEndpoint: peer.InternalEndpoint}
		}
	}
	return nil
}

// AnyMatch 给定多个 peer 节点 peers，过滤掉不满足任何给定过滤规则 filters 的 peer 节点，返回剩下的 peer 节点。
func AnyMatch(peers []NetworkMember, filters ...RoutingFilter) []NetworkMember {
	var res []NetworkMember
	for _, peer := range peers {
		for _, filter := range filters {
			if filter(peer) {
				res = append(res, peer)
				break
			}
		}
	}
	return res
}

/* ------------------------------------------------------------------------------------------ */

type SubChannelSelectionRule func(signature PeerSignature) bool

type PeerSignature struct {
	Signature    []byte
	Message      []byte
	PeerIdentity PeerIdentityType
}
