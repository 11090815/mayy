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

	// PublishCertPeriod gossip 节点在启动时，会在当前时间 now 加上 PublishCertPeriod，得到
	// includeIdentityPeriod，然后 discovery 在签署 alive 消息时，如果签署时的时间早于
	// includeIdentityPeriod，则会将关于节点身份证书 的 identity 放到 alive 消息中。
	PublishCertPeriod time.Duration

	// TLSCerts 存储着 peer 节点的 tls 证书，在 communicate authenticate 时用于验证 client-server 端的身份。
	TLSCerts *utils.TLSCertificates

	// InternalEndpoint 是同组织内其他节点知道的网络地址。
	InternalEndpoint string

	// ExternalEndpoint 是组织外的其他节点可以知道的网络地址。
	ExternalEndpoint string

	// PullConfig
	//	1. DigestWaitTime time.Duration
	//	2. RequestWaitTime time.Duration
	//	3. ResponseWaitTime time.Duration
	PullConfig algo.Config

	// ChannelConfig
	//	1. MaxBlockCountToStore int
	//	2. PullPeerNum int
	//	3. PullInterval time.Duration
	//	4. PublishStateInfoInterval time.Duration
	//	5. RequestStateInfoInterval time.Duration
	//	6. BlockExpirationTimeout time.Duration
	//	7. StateInfoCacheSweepInterval time.Duration
	//	8. TimeForMembershipTracker time.Duration
	//	9. LeadershipMsgExpirationTimeout time.Duration
	//	10. PullEngineConfig algo.Config
	ChannelConfig channel.Config

	// CommConfig
	//	1. DialTimeout time.Duration
	//	2. ConnTimeout time.Duration
	//	3. RecvBuffSize int
	//	4. SendBuffSize int
	CommConfig comm.Config

	// DiscoveryConfig
	//	1. AliveTimeInterval time.Duration
	//	2. AliveExpirationTimeout time.Duration
	//	3. AliveExpirationCheckInterval time.Duration
	//	4. ReconnectInterval time.Duration
	//	5. MaxConnectionAttempts int
	//	6. MsgExpirationFactor int
	//	7. BootstrapPeers []string
	DiscoveryConfig discovery.Config

	// ElectionConfig
	//	1. StartupGracePeriod time.Duration
	//	2. MembershipSampleInterval time.Duration
	//	3. LeaderAliveThreshold time.Duration
	//	4. LeaderElectionDuration time.Duration
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
