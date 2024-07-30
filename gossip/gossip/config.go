package gossip

import (
	"net"
	"strconv"
	"time"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/gossip/discovery"
	"github.com/11090815/mayy/gossip/election"
	"github.com/11090815/mayy/gossip/gossip/algo"
	"github.com/11090815/mayy/gossip/gossip/channel"
	"github.com/11090815/mayy/gossip/gossip/comm"
	"github.com/11090815/mayy/gossip/utils"
)

type Config struct {
	// BindPort 只在测试时使用的绑定的端口号。
	BindPort int

	// ID 用于表示 gossip 实例的 id。
	ID string

	// PropagateIterations 定义了将消息推送给 peer 节点的次数。
	PropagateIterations int

	// PropagatePeerNum 定义了将消息推送给的 peer 节点的个数。
	PropagatePeerNum int

	// MaxPropagationBurstSize 定义了在触发向远程对等点推送之前存储的最大消息数。
	MaxPropagationBurstSize int

	// MaxPropagationBurstLatency 定义了连续消息推送之间的最大时间间隔。
	MaxPropagationBurstLatency time.Duration

	// SkipBlockVerification 控制是否验证区块消息。
	SkipBlockVerification bool

	// PublishCertPeriod
	PublishCertPeriod time.Duration

	// TLSCerts 存储着 peer 节点的 tls 证书。
	TLSCerts *utils.TLSCertificates

	// InternalEndpoint 是同组织内其他节点知道的网络地址。
	InternalEndpoint string

	// ExternalEndpoint 是组织外的其他节点可以知道的网络地址。
	ExternalEndpoint string

	PullConfig algo.Config

	ChannelConfig channel.Config

	CommConfig comm.Config

	DiscoveryConfig discovery.Config

	ElectionConfig election.ElectionConfig
}

func GlobalGossipConfig(endpoint string, certs *utils.TLSCertificates, bootPeers ...string) (*Config, error) {
	c := &Config{}

	_, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return c, errors.NewErrorf("failed loading config: %s", err.Error())
	}

	portInt, err := strconv.ParseInt(port, 10, 64)
	if err != nil {
		return c, errors.NewErrorf("failed loading config: %s", err.Error())
	}
	c.BindPort = int(portInt)
	c.ID = endpoint
	c.PropagateIterations = utils.GetIntOrDefault("PEER.GOSSIP.PropagateIterations", 1)
	c.PropagatePeerNum = utils.GetIntOrDefault("PEER.GOSSIP.PropagatePeerNum", 3)
	c.MaxPropagationBurstSize = utils.GetIntOrDefault("PEER.GOSSIP.MaxPropagationBurstSize", 10)
	c.MaxPropagationBurstLatency = utils.GetDurationOrDefault("PEER.GOSSIP.MaxPropagationBurstLatency", 10*time.Millisecond)
	c.SkipBlockVerification = utils.GetBool("PEER.GOSSIP.SkipBlockVerification")
	c.PublishCertPeriod = utils.GetDurationOrDefault("PEER.GOSSIP.PublishCertPeriod", 10*time.Second)
	c.TLSCerts = certs
	c.InternalEndpoint = endpoint
	c.ExternalEndpoint = utils.GetString("PEER.GOSSIP.ExternalEndpoint")

	c.PullConfig.DigestWaitTime = utils.GetDurationOrDefault("PEER.GOSSIP.PULL.DigestWaitTime", algo.DefaultDigestWaitTime)
	c.PullConfig.RequestWaitTime = utils.GetDurationOrDefault("PEER.GOSSIP.PULL.RequestWaitTime", algo.DefaultRequestWaitTime)
	c.PullConfig.ResponseWaitTime = utils.GetDurationOrDefault("PEER.GOSSIP.PULL.ResponseWaitTime", algo.DefaultResponseWaitTime)

	c.CommConfig.DialTimeout = utils.GetDurationOrDefault("PEER.GOSSIP.COMM.DialTimeout", comm.DefaultDialTimeout)
	c.CommConfig.ConnTimeout = utils.GetDurationOrDefault("PEER.GOSSIP.COMM.ConnTimeout", comm.DefaultConnTimeout)
	c.CommConfig.RecvBuffSize = utils.GetIntOrDefault("PEER.GOSSIP.COMM.RecvBuffSize", comm.DefaultRecvBuffSize)
	c.CommConfig.SendBuffSize = utils.GetIntOrDefault("PEER.GOSSIP.COMM.SendBuffSize", comm.DefaultSendBuffSize)

	c.ElectionConfig.LeaderAliveThreshold = utils.GetDurationOrDefault("PEER.GOSSIP.ELECTION.LeaderAliveThreshold", election.DefLeaderAliveThreshold*10)
	c.ElectionConfig.LeaderElectionDuration = utils.GetDurationOrDefault("PEER.GOSSIP.ELECTION.LeaderElectionDuration", election.DefLeaderElectionDuration)
	c.ElectionConfig.MembershipSampleInterval = utils.GetDurationOrDefault("PEER.GOSSIP.ELECTION.MembershipSampleInterval", election.DefMembershipSampleInterval)
	c.ElectionConfig.StartupGracePeriod = utils.GetDurationOrDefault("PEER.GOSSIP.ELECTION.StartupGracePeriod", election.DefStartupGracePeriod)

	c.DiscoveryConfig.ReconnectInterval = utils.GetDurationOrDefault("PEER.GOSSIP.DISCOVERY.ReconnectInterval", 25*time.Second)
	c.DiscoveryConfig.MaxConnectionAttempts = utils.GetIntOrDefault("PEER.GOSSIP.DISCOVERY.MaxConnectionAttempts", discovery.DefaultMaxConnectAttempts)
	c.DiscoveryConfig.AliveTimeInterval = utils.GetDurationOrDefault("PEER.GOSSIP.DISCOVERY.AliveTimeInterval", discovery.DefaultAliveTimeInterval)
	c.DiscoveryConfig.AliveExpirationTimeout = utils.GetDurationOrDefault("PEER.GOSSIP.DISCOVERY.AliveExpirationTimeout", 5*c.DiscoveryConfig.AliveTimeInterval)
	c.DiscoveryConfig.AliveExpirationCheckInterval = c.DiscoveryConfig.AliveExpirationTimeout / 10
	c.DiscoveryConfig.MsgExpirationFactor = utils.GetIntOrDefault("PEER.GOSSIP.DISCOVERY.MsgExpirationFactor", discovery.DefaultMsgExpirationFactor)
	c.DiscoveryConfig.BootstrapPeers = utils.GetStringSliceOrDefault("PEER.GOSSIP.DISCOVERY.BootstrapPeers", bootPeers)

	c.ChannelConfig.MaxBlockCountToStore = utils.GetIntOrDefault("PEER.GOSSIP.CHANNEL.MaxBlockCountToStore", 10)
	c.ChannelConfig.PullInterval = utils.GetDurationOrDefault("PEER.GOSSIP.CHANNEL.PullInterval", 4*time.Second)
	c.ChannelConfig.PullPeerNum = utils.GetIntOrDefault("PEER.GOSSIP.CHANNEL.PullPeerNum", 3)
	c.ChannelConfig.PublishStateInfoInterval = utils.GetDurationOrDefault("PEER.GOSSIP.CHANNEL.PublishStateInfoInterval", 4*time.Second)
	c.ChannelConfig.RequestStateInfoInterval = utils.GetDurationOrDefault("PEER.GOSSIP.CHANNEL.RequestStateInfoInterval", 4*time.Second)
	c.ChannelConfig.TimeForMembershipTracker = utils.GetDurationOrDefault("PEER.GOSSIP.CHANNEL.TimeForMembershipTracker", 5*time.Second)
	c.ChannelConfig.BlockExpirationTimeout = utils.GetDurationOrDefault("PEER.GOSSIP.CHANNEL.BlockExpirationTimeout", 400*time.Second)
	c.ChannelConfig.LeadershipMsgExpirationTimeout = utils.GetDurationOrDefault("PEER.GOSSIP.CHANNEL.LeadershipMsgExpirationTimeout", channel.DefaultLeadershipMsgExpirationTimeout)
	c.ChannelConfig.StateInfoCacheSweepInterval = utils.GetDurationOrDefault("PEER.GOSSIP.CHANNEL.StateInfoCacheSweepInterval", 5*c.ChannelConfig.PullInterval)
	c.ChannelConfig.PullEngineConfig = c.PullConfig

	return c, nil
}
