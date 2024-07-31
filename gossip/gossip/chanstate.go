package gossip

import (
	"bytes"
	"sync"
	"sync/atomic"

	"github.com/11090815/mayy/gossip/discovery"
	"github.com/11090815/mayy/gossip/gossip/channel"
	"github.com/11090815/mayy/gossip/metrics"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
)

type channelState struct {
	stopping int32
	mutex    *sync.RWMutex
	channels map[string]channel.GossipChannel
	node     *Node
}

// lookupChannelForReceivedMsg 根据传入的 ReceivedMessage 获取相应的 GossipChannel：
//	a. 如果收到的 ReceivedMessage 蕴含 state info pull req 消息，则根据 req 消息内的 Channel_MAC 从 channel state 中获取对应的 GossipChannel，否则转到 b；
//	b. 提取 ReceivedMessage 中的 GossipMessage 消息，如果 GossipMessage 含有的消息不是 state info 消息，则根据 GossipMessage 消息中的 channel id 从 channel state 中获取对应的 GossipChannel，否则转到 c；
// 	c. 从 GossipMessage 消息中提取蕴含的 state info 消息，然后根据 state info 消息中的 Channel_MAC 从 channel state 中获取对应的 GossipChannel。
func (cs *channelState) lookupChannelForReceivedMsg(msg utils.ReceivedMessage) channel.GossipChannel {
	if msg.GetSignedGossipMessage().GetStateInfoPullReq() != nil {
		req := msg.GetSignedGossipMessage().GetStateInfoPullReq()
		mac := req.Channel_MAC
		pkiID := msg.GetConnectionInfo().PkiID
		return cs.getGossipChannelByMAC(mac, pkiID)
	}
	return cs.lookupChannelForGossipMsg(msg.GetSignedGossipMessage().GossipMessage)
}

// lookupChannelForGossipMsg 根据传入的 GossipMessage 获取相应的 GossipChannel：
//	a. 如果 GossipMessage 含有的消息不是 state info 消息，则根据 GossipMessage 消息中的 channel id 从 channel state 中获取对应的 GossipChannel，否则转到 b；
//	b. 从 GossipMessage 消息中提取蕴含的 state info 消息，然后根据 state info 消息中的 Channel_MAC 从 channel state 中获取对应的 GossipChannel。
func (cs *channelState) lookupChannelForGossipMsg(msg *pgossip.GossipMessage) channel.GossipChannel {
	if msg.GetStateInfo() == nil {
		return cs.getGossipChannelByChannelID(msg.Channel)
	}
	stateInfoMsg := msg.GetStateInfo()
	return cs.getGossipChannelByMAC(stateInfoMsg.Channel_MAC, stateInfoMsg.PkiId)
}

func (cs *channelState) getGossipChannelByMAC(receivedMAC []byte, pkiID utils.PKIidType) channel.GossipChannel {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	for chName, ch := range cs.channels {
		mac := utils.GenerateMAC(pkiID, utils.ChannelID(chName))
		if bytes.Equal(receivedMAC, mac) {
			return ch
		}
	}
	return nil
}

func (cs *channelState) getGossipChannelByChannelID(channelID utils.ChannelID) channel.GossipChannel {
	if cs.isStopped() {
		return nil
	}
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	return cs.channels[channelID.String()]
}

func (cs *channelState) joinChannel(joinMsg utils.JoinChannelMessage, channelID utils.ChannelID, metrics *metrics.MembershipMetrics) {
	if cs.isStopped() {
		return
	}
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	if ch, exists := cs.channels[channelID.String()]; !exists {
		pkiID := cs.node.communication.GetPKIid()
		gAdapter := &channelAdapter{Node: cs.node, Discovery: cs.node.disc}
		newCh := channel.NewGossipChannel(pkiID, cs.node.selfOrg, cs.node.mcs, channelID, gAdapter, joinMsg, metrics, cs.node.logger)
		cs.channels[channelID.String()] = newCh
	} else {
		ch.ConfigureChannel(joinMsg)
	}
}

func (cs *channelState) stop() {
	if cs.isStopped() {
		return
	}
	atomic.StoreInt32(&cs.stopping, 1)
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	for _, ch := range cs.channels {
		ch.Stop()
	}
}

func (cs *channelState) isStopped() bool {
	return atomic.LoadInt32(&cs.stopping) == int32(1)
}

/* ------------------------------------------------------------------------------------------ */

type channelAdapter struct {
	*Node
	discovery.Discovery
}

func (adapter *channelAdapter) GetConf() channel.Config {
	return channel.Config{
		MaxBlockCountToStore:        adapter.conf.ChannelConfig.MaxBlockCountToStore,
		PublishStateInfoInterval:    adapter.conf.ChannelConfig.PublishStateInfoInterval,
		PullInterval:                adapter.conf.ChannelConfig.PullInterval,
		PullPeerNum:                 adapter.conf.ChannelConfig.PullPeerNum,
		RequestStateInfoInterval:    adapter.conf.ChannelConfig.RequestStateInfoInterval,
		BlockExpirationTimeout:      adapter.conf.ChannelConfig.BlockExpirationTimeout,
		StateInfoCacheSweepInterval: adapter.conf.ChannelConfig.StateInfoCacheSweepInterval,
		TimeForMembershipTracker:    adapter.conf.ChannelConfig.TimeForMembershipTracker,
		PullEngineConfig:            adapter.conf.PullConfig,
	}
}

func (adapter *channelAdapter) Sign(msg *pgossip.GossipMessage) (*utils.SignedGossipMessage, error) {
	signer := func(msg []byte) ([]byte, error) {
		return adapter.mcs.Sign(msg)
	}
	sgm := &utils.SignedGossipMessage{
		GossipMessage: msg,
	}
	e, err := sgm.Sign(signer)
	if err != nil {
		return nil, err
	}
	return &utils.SignedGossipMessage{
		Envelope:      e,
		GossipMessage: msg,
	}, nil
}

func (adapter *channelAdapter) Gossip(msg *utils.SignedGossipMessage) {
	adapter.emitter.Add(utils.NewEmittedGossipMessage(msg, func(pt utils.PKIidType) bool {
		return true
	}))
}

func (adapter *channelAdapter) Forward(msg utils.ReceivedMessage) {
	adapter.emitter.Add(utils.NewEmittedGossipMessage(msg.GetSignedGossipMessage(), msg.GetConnectionInfo().PkiID.IsNotSameFilter))
}

func (adapter *channelAdapter) Send(msg *utils.SignedGossipMessage, peers ...*utils.RemotePeer) {
	adapter.communication.Send(msg, peers...)
}

func (adapter *channelAdapter) ValidateStateInfoMessage(msg *utils.SignedGossipMessage) error {
	return adapter.validateStateInfoMsg(msg)
}

func (adapter *channelAdapter) GetOrgOfPeer(pkiID utils.PKIidType) utils.OrgIdentityType {
	return adapter.getOrgOfPeer(pkiID)
}

func (adapter *channelAdapter) GetIdentityByPKIID(pkiID utils.PKIidType) utils.PeerIdentityType {
	if identity, err := adapter.idMapper.Get(pkiID); err == nil {
		return identity
	} else {
		return nil
	}
}

func (adapter *channelAdapter) DeMultiplex(msg any) {
	adapter.demux.DeMultiplex(msg)
}
