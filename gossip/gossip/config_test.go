package gossip

import (
	"testing"
	"time"

	"github.com/11090815/mayy/gossip/discovery"
	"github.com/11090815/mayy/gossip/election"
	"github.com/11090815/mayy/gossip/gossip/algo"
	"github.com/11090815/mayy/gossip/gossip/channel"
	"github.com/11090815/mayy/gossip/gossip/comm"
	"github.com/stretchr/testify/require"
)

func TestGlobalConfig(t *testing.T) {
	internalEndpoint := "0.0.0.0:7051"
	bootstrapPeers := []string{"127.0.0.1:2048", "127.0.0.1:2049", "127.0.0.1:2050"}
	cfg, err := GlobalGossipConfig(internalEndpoint, nil, bootstrapPeers[1:]...)
	require.NoError(t, err)

	expectedCfg := &Config{
		ID:                         internalEndpoint,
		BindPort:                   7051,
		SkipBlockVerification:      false,
		PropagateIterations:        1,
		PropagatePeerNum:           3,
		MaxPropagationBurstSize:    10,
		MaxPropagationBurstLatency: 10 * time.Millisecond,
		ExternalEndpoint:           "0.0.0.0:7052",
		PublishCertPeriod:          10 * time.Second,
		TLSCerts:                   nil,
		InternalEndpoint:           internalEndpoint,
		PullConfig: algo.Config{
			DigestWaitTime:   time.Second,
			RequestWaitTime:  1500 * time.Millisecond,
			ResponseWaitTime: 2 * time.Second,
		},
		CommConfig: comm.Config{
			DialTimeout:  3 * time.Second,
			ConnTimeout:  2 * time.Second,
			RecvBuffSize: 200,
			SendBuffSize: 200,
		},
		ChannelConfig: channel.Config{
			MaxBlockCountToStore:           10,
			PullInterval:                   4 * time.Second,
			PullPeerNum:                    3,
			PublishStateInfoInterval:       4 * time.Second,
			RequestStateInfoInterval:       4 * time.Second,
			TimeForMembershipTracker:       5 * time.Second,
			LeadershipMsgExpirationTimeout: 100 * time.Second,
			BlockExpirationTimeout:         400 * time.Second,
			StateInfoCacheSweepInterval:    20 * time.Second,
			PullEngineConfig: algo.Config{
				DigestWaitTime:   time.Second,
				RequestWaitTime:  1500 * time.Millisecond,
				ResponseWaitTime: 2 * time.Second,
			},
		},
		ElectionConfig: election.ElectionConfig{
			LeaderAliveThreshold:     10 * time.Second,
			StartupGracePeriod:       15 * time.Second,
			MembershipSampleInterval: time.Second,
			LeaderElectionDuration:   5 * time.Second,
		},
		DiscoveryConfig: discovery.Config{
			ReconnectInterval:            25 * time.Second,
			MaxConnectionAttempts:        120,
			AliveTimeInterval:            5 * time.Second,
			AliveExpirationTimeout:       25 * time.Second,
			AliveExpirationCheckInterval: 2500 * time.Millisecond,
			MsgExpirationFactor:          20,
			BootstrapPeers:               bootstrapPeers,
		},
	}

	require.Equal(t, cfg, expectedCfg)
}
