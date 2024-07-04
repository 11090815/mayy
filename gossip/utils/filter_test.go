package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectPolicies(t *testing.T) {
	require.True(t, SelectAllPolicy(NetworkMember{}))
	require.False(t, SelectNoncePolicy(NetworkMember{}))
}

func TestCombineRoutingFilters(t *testing.T) {
	nm := NetworkMember{
		Endpoint: "a",
		InternalEndpoint: "b",
	}
	var a RoutingFilter = func(nm NetworkMember) bool {
		return nm.Endpoint == "a"
	}
	var b RoutingFilter = func(nm NetworkMember) bool {
		return nm.InternalEndpoint == "b"
	}

	require.True(t, CombineRoutingFilters(a, b)(nm))
	require.False(t, CombineRoutingFilters(a, b, SelectNoncePolicy)(nm))
	require.False(t, CombineRoutingFilters(a, b)(NetworkMember{Endpoint: "a"}))
}

func TestAnyMatch(t *testing.T) {
	p1 := NetworkMember{Endpoint: "a"}	
	p2 := NetworkMember{Endpoint: "b"}	
	p3 := NetworkMember{Endpoint: "c"}	
	p4 := NetworkMember{Endpoint: "d"}

	peers := []NetworkMember{p1, p2, p3, p4}

	var pA RoutingFilter = func(nm NetworkMember) bool {
		return nm.Endpoint == "a"
	}

	var pB RoutingFilter = func(nm NetworkMember) bool {
		return nm.Endpoint == "b"
	}

	matched := AnyMatch(peers, pA, pB)
	require.Len(t, matched, 2)
	require.Contains(t, peers, p1)
	require.Contains(t, peers, p2)
}

func TestFirst(t *testing.T) {
	var peers []NetworkMember = []NetworkMember{}
	require.Nil(t, First(nil, SelectAllPolicy))
	require.Nil(t, First(peers, SelectAllPolicy))

	p1 := NetworkMember{Endpoint: "a"}
	p2 := NetworkMember{Endpoint: "b"}
	peers = append(peers, []NetworkMember{p1, p2}...)

	require.Equal(t, p1.Endpoint, First(peers, SelectAllPolicy).Endpoint)
	require.Equal(t, p2.Endpoint, First(peers, func(nm NetworkMember) bool {
		return nm.Endpoint == "b"
	}).Endpoint)
}

func TestSelectPeers(t *testing.T) {
	var pA RoutingFilter = func(nm NetworkMember) bool {
		return nm.Endpoint == "b"
	}

	var pB RoutingFilter = func(nm NetworkMember) bool {
		return nm.InternalEndpoint == "1"
	}

	var pC RoutingFilter = func(nm NetworkMember) bool {
		return len(nm.PKIid) == 0
	}
	
	p1 := NetworkMember{Endpoint: "a", InternalEndpoint: "1"}	
	p2 := NetworkMember{Endpoint: "b", InternalEndpoint: "2"}	
	p3 := NetworkMember{Endpoint: "c", InternalEndpoint: "1"}
	peers := []NetworkMember{p1, p2, p3}

	require.Len(t, SelectPeers(3, peers, pA), 1)
	require.Len(t, SelectPeers(3, peers, pB), 2)

	require.Len(t, SelectPeers(3, peers, CombineRoutingFilters(pA, pB)), 0)
	require.Len(t, SelectPeers(1, peers, pC), 1)
	require.Len(t, SelectPeers(2, peers, pC), 2)
	require.Len(t, SelectPeers(3, peers, pC), 3)
}
