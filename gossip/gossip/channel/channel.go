package channel

import (
	"bytes"
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/election"
	"github.com/11090815/mayy/gossip/gossip/algo"
	"github.com/11090815/mayy/gossip/gossip/msgstore"
	"github.com/11090815/mayy/gossip/gossip/pull"
	"github.com/11090815/mayy/gossip/metrics"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
	"github.com/11090815/mayy/protoutil"
)

const DefaultLeadershipMsgExpirationTimeout = election.DefLeaderAliveThreshold * 10

type Config struct {
	// MaxBlockCountToStore 内存缓冲区中能允许存储的区块数量。
	MaxBlockCountToStore int
	// PullPeerNum 向 PullPeerNum 个节点发送请求状态信息的请求。
	PullPeerNum int
	// PullInterval 每隔 PullInterval 这段时间就给其他节点发送 Hello 消息，抓取其他节点的 digests。
	PullInterval time.Duration
	// PublishStateInfoInterval 每隔这段时间就给其他节点广播自己的状态信息。
	PublishStateInfoInterval time.Duration
	// RequestStateInfoInterval 每隔这段时间就向其他 PullPeerNum 个节点请求状态信息。
	RequestStateInfoInterval time.Duration
	// BlockExpirationTimeout 是区块在内存存储区内的保质期，超过这个保质期，区块就过期了。
	BlockExpirationTimeout time.Duration
	// StateInfoCacheSweepInterval 每隔这段时间，就清除掉存储在本地的那些无法确认消息创造者身份的状态消息。
	StateInfoCacheSweepInterval time.Duration
	// TimeForMembershipTracker 每隔这段时间，就汇报一下当前 view 下 membership 的变化情况。
	TimeForMembershipTracker time.Duration
	// LeadershipMsgExpirationTimeout 是 leadership 消息在内存存储区内的保质期，超过这个保质期，leadership 消息就过期了。
	LeadershipMsgExpirationTimeout time.Duration
	PullEngineConfig               algo.Config
}

/* ------------------------------------------------------------------------------------------ */

func NewGossipChannel(pkiID utils.PKIidType, org utils.OrgIdentityType, mcs utils.MessageCryptoService, channelID utils.ChannelID,
	adapter Adapter, joinMsg utils.JoinChannelMessage, metrics *metrics.MembershipMetrics, logger mlog.Logger) GossipChannel {
	gc := &gossipChannel{
		incTime:                   uint64(time.Now().UnixNano()),
		selfOrg:                   org,
		pkiID:                     pkiID,
		mcs:                       mcs,
		adapter:                   adapter,
		stopCh:                    make(chan struct{}),
		shouldGossipStateInfo:     int32(0),
		stateInfoPublishScheduler: time.NewTicker(adapter.GetConf().PublishStateInfoInterval),
		stateInfoRequestScheduler: time.NewTicker(adapter.GetConf().RequestStateInfoInterval),
		orgs:                      make([]utils.OrgIdentityType, 0),
		channelID:                 channelID,
		logger:                    logger,
		mutex:                     &sync.RWMutex{},
	}

	comparator := utils.NewGossipMessageComparator(adapter.GetConf().MaxBlockCountToStore)
	gc.blocksPuller = gc.createBlockPuller()
	seqNumFromMsg := func(m any) string {
		return fmt.Sprintf("%d", m.(*utils.SignedGossipMessage).GetDataMsg().Payload.SeqNum)
	}
	gc.blockMsgStore = msgstore.NewMessageStoreExpirable(comparator, func(m any) {
		gc.logger.Debugf("Removing No.%s block from blocks puller.", seqNumFromMsg(m))
		gc.blocksPuller.Remove(seqNumFromMsg(m))
	}, gc.adapter.GetConf().BlockExpirationTimeout, nil, nil, func(a any) {
		gc.logger.Debugf("Removing No.%s block from blocks puller.", seqNumFromMsg(a))
		gc.blocksPuller.Remove(seqNumFromMsg(a))
	})

	// hashPeerExpiredInMembership 如果在本地找不到消息创造者的证书，就返回 true。
	hashPeerExpiredInMembership := func(a any) bool {
		pid := a.(*utils.SignedGossipMessage).GetStateInfo().PkiId
		return gc.adapter.Lookup(pid) == nil
	}

	verifyStateInfoMsg := func(msg *utils.SignedGossipMessage, orgs ...utils.OrgIdentityType) bool {
		stateInfo := msg.GetStateInfo()
		pid := utils.PKIidType(stateInfo.PkiId)
		if bytes.Equal(gc.pkiID, pid) {
			// 自己的状态信息消息不需要验证
			return true
		}

		peerIdentity := adapter.GetIdentityByPKIID(pid)
		if len(peerIdentity) == 0 {
			gc.logger.Warnf("Identity for peer %s doesn't exist.", pid.String())
			return false
		}
		isOrgInChannel := func(org utils.OrgIdentityType) bool {
			if len(orgs) == 0 {
				if !gc.IsOrgInChannel(org) {
					return false
				}
			} else {
				found := false
				for _, o := range orgs {
					if bytes.Equal(o, org) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
			return true
		}

		o := gc.adapter.GetOrgOfPeer(pid)
		if !isOrgInChannel(o) {
			// 状态信息消息的发送者所在的机构不在本通道内，那么此状态信息消息是无效的。
			gc.logger.Warnf("Peer's organization (%s) is not in the channel.", o.String())
			return false
		}
		if err := gc.mcs.VerifyByChannel(channelID, peerIdentity, msg.Signature, msg.Payload); err != nil {
			gc.logger.Warnf("Peer %s is not eligible for channel %s: %s.", pid.String(), channelID.String(), err.Error())
			return false
		}
		return true
	}

	gc.stateInfoMsgStore = newStateInfoCache(gc.adapter.GetConf().StateInfoCacheSweepInterval, hashPeerExpiredInMembership, verifyStateInfoMsg)

	gc.updateProperties(1, nil, false)
	gc.setupSignedStateInfoMessage()

	ttl := adapter.GetConf().LeadershipMsgExpirationTimeout
	policy := utils.NewGossipMessageComparator(0)

	gc.leaderMsgStore = msgstore.NewMessageStoreExpirable(policy, msgstore.Noop, ttl, nil, nil, nil)
	gc.ConfigureChannel(joinMsg)

	go gc.periodicalInvocation(gc.publishStateInfo, gc.stateInfoPublishScheduler.C)
	go gc.periodicalInvocation(gc.requestStateInfo, gc.stateInfoRequestScheduler.C)

	ticker := time.NewTicker(gc.adapter.GetConf().TimeForMembershipTracker)
	gc.membershipTracker = &membershipTracker{
		getPeersToTrack: gc.GetPeers,
		report:          gc.logger.Infof,
		stopChan:        make(chan struct{}),
		tickerC:         ticker.C,
		metrics:         metrics,
		channelID:       channelID,
	}
	go gc.membershipTracker.trackMembershipChanges()

	return gc
}

type GossipChannel interface {
	// Self 返回自己当前的状态。
	Self() *utils.SignedGossipMessage

	// GetPeers 返回与自己在同一组织且未离开通道且允许给该节点发送区块的节点。
	GetPeers() utils.Members

	// PeerFilter 接收一个 SubChannelSelectionRule 并返回一个 RoutingFilter，它只选择匹配给定条件的 peer 节点身份。
	// 猜测：如果 peer 节点过去给我们发送过签名正确的状态消息，则将此 peer 节点过滤出来。
	PeerFilter(utils.SubChannelSelectionRule) utils.RoutingFilter

	// IsMemberInChannel 判断给定的 peer 节点是否在通道内。
	IsMemberInChannel(member utils.NetworkMember) bool

	// IsOrgInChannel 判断给定的组织是否在通道内。
	IsOrgInChannel(org utils.OrgIdentityType) bool

	UpdateLedgerHeight(height uint64)

	// UpdateChaincodes 更新 peer 节点发送给通道内其他 peer 节点的链码。
	UpdateChaincodes(chaincodes []*pgossip.Chaincode)

	// ShouldGetBlocksForThisChannel
	ShouldGetBlocksForThisChannel(member utils.NetworkMember) bool

	// HandleMessages 处理来自于其他 peer 节点的消息。
	HandleMessage(utils.ReceivedMessage)

	// AddToMsgStore 将 gossip 消息添加到内存中。
	AddToMsgStore(*utils.SignedGossipMessage)

	// ConfigureChannel (重新)配置有资格进入该通道的组织列表
	ConfigureChannel(utils.JoinChannelMessage)

	// LeaveChannel 让 peer 节点离开通道。
	LeaveChannel()

	Stop()
}

func (gc *gossipChannel) Self() *utils.SignedGossipMessage {
	gc.mutex.RLock()
	defer gc.mutex.RUnlock()
	return gc.selfStateInfoSignedMsg
}

// GetPeers 返回与自己在同一组织且未离开通道且允许给该节点发送区块的节点。
func (gc *gossipChannel) GetPeers() utils.Members {
	var members utils.Members
	if gc.hasLeftChannel() {
		return members
	}

	for _, member := range gc.adapter.GetMembership() {
		stateInfo := gc.stateInfoMsgStore.MsgByID(member.PKIid)
		if stateInfo == nil {
			continue
		}
		properties := stateInfo.GetStateInfo().Properties
		if properties != nil && properties.LeftChannel {
			// 已经离开 channel 的 member，就不算在内了。
			continue
		}
		member.Properties = stateInfo.GetStateInfo().Properties
		member.Envelope = stateInfo.Envelope
		members = append(members, member)
	}
	return members
}

func (gc *gossipChannel) PeerFilter(pred utils.SubChannelSelectionRule) utils.RoutingFilter {
	return func(nm utils.NetworkMember) bool {
		peerIdentity := gc.adapter.GetIdentityByPKIID(nm.PKIid)
		if len(peerIdentity) == 0 {
			return false
		}
		stateInfo := gc.stateInfoMsgStore.MsgByID(nm.PKIid)
		if stateInfo == nil {
			return false
		}

		// TODO: 验证状态消息的签名是否正确？
		return pred(utils.PeerSignature{
			Message:      stateInfo.Payload,
			Signature:    stateInfo.Signature,
			PeerIdentity: peerIdentity,
		})
	}
}

// IsMemberInChannel 如果该成员所在的组织在通道内，那么此成员就一定在通道内。
func (gc *gossipChannel) IsMemberInChannel(member utils.NetworkMember) bool {
	org := gc.adapter.GetOrgOfPeer(member.PKIid)
	if org == nil {
		return false
	}
	return gc.IsOrgInChannel(org)
}

// IsOrgInChannel 判断给定的组织是否在通道内。
func (gc *gossipChannel) IsOrgInChannel(org utils.OrgIdentityType) bool {
	gc.mutex.RLock()
	defer gc.mutex.RUnlock()
	for _, orgOfChan := range gc.orgs {
		if bytes.Equal(org, orgOfChan) {
			return true
		}
	}
	return false
}

// UpdateLedgerHeight 更新账本的区块高度，然后将 shouldGossipStateInfo 标志位设置成 1.
func (gc *gossipChannel) UpdateLedgerHeight(height uint64) {
	gc.mutex.Lock()
	defer gc.mutex.Unlock()

	var chaincodes []*pgossip.Chaincode
	var leftChannel bool
	if stateInfo := gc.selfStateInfoMsg; stateInfo != nil {
		leftChannel = stateInfo.GetStateInfo().Properties.LeftChannel
		chaincodes = stateInfo.GetStateInfo().Properties.Chaincodes
	}
	gc.updateProperties(height, chaincodes, leftChannel)
	atomic.StoreInt32(&gc.shouldGossipStateInfo, 1)
}

func (gc *gossipChannel) UpdateChaincodes(chaincodes []*pgossip.Chaincode) {
	defer gc.publishSignedStateInfoMessage()
	gc.mutex.Lock()
	defer gc.mutex.Unlock()

	var ledgerHeight uint64 = 1
	var leftChannel bool
	if prevStateInfoMsg := gc.selfStateInfoMsg; prevStateInfoMsg != nil {
		ledgerHeight = prevStateInfoMsg.GetStateInfo().Properties.LedgerHeight
		leftChannel = prevStateInfoMsg.GetStateInfo().Properties.LeftChannel
	}
	gc.updateProperties(ledgerHeight, chaincodes, leftChannel)
	atomic.StoreInt32(&gc.shouldGossipStateInfo, 1)
}

// ShouldGetBlocksForThisChannel 如果根据给定的节点标识符，能在本地找到该节点的身份证书，且这个节点给我们发送过消息，
// 则该节点就可以从此通道内获取区块。
func (gc *gossipChannel) ShouldGetBlocksForThisChannel(member utils.NetworkMember) bool {
	peerIdentity := gc.adapter.GetIdentityByPKIID(member.PKIid)
	if len(peerIdentity) == 0 {
		gc.logger.Warnf("Identity for peer %s doesn't exist.", member.PKIid.String())
		return false
	}
	msg := gc.stateInfoMsgStore.MsgByID(member.PKIid)
	return msg != nil
}

// HandleMessage 如果收到的消息是 pull 类型的，那么此消息的发送者必须和自己在同一 org 内，否则会直接忽略掉。
func (gc *gossipChannel) HandleMessage(msg utils.ReceivedMessage) {
	if !gc.verifyMsg(msg) {
		gc.logger.Warnf("Failed verifying message: %s.", utils.GossipMessageToString(msg.GetSignedGossipMessage().GossipMessage))
		return
	}

	sgm := msg.GetSignedGossipMessage()
	if !utils.IsChannelRestricted(sgm.GossipMessage) {
		gc.logger.Warnf("Got message %s, it is not channel restricted, discarding it.", utils.GossipMessageToString(sgm.GossipMessage))
		return
	}

	orgId := gc.adapter.GetOrgOfPeer(msg.GetConnectionInfo().PkiID)
	if len(orgId) == 0 {
		gc.logger.Warnf("The peer sent message %s belongs to an unknown organization, discarding it.", utils.GossipMessageToString(sgm.GossipMessage))
		return
	}
	if !gc.IsOrgInChannel(orgId) {
		gc.logger.Warnf("The peer sent message %s belongs to an organization (%s) which is not eligible for the channel %s, discarding it.", utils.GossipMessageToString(sgm.GossipMessage), orgId.String(), gc.channelID.String())
		return
	}

	if sgm.GetStateInfoPullReq() != nil {
		msg.Respond(gc.createStateInfoSnapshot(orgId))
		return
	}

	if sgm.GetStateInfoSnapshot() != nil {
		gc.handleStateInfoSnapshot(sgm.GossipMessage, msg.GetConnectionInfo().PkiID)
		return
	}

	if sgm.GetDataMsg() != nil || sgm.GetStateInfo() != nil {
		added := false

		if dataMsg := sgm.GetDataMsg(); dataMsg != nil {
			payload := dataMsg.Payload
			if payload == nil {
				gc.logger.Warnf("The payload of DataMsg sent by %s is empty.", msg.GetConnectionInfo().PkiID.String())
				return
			}
			if !gc.blockMsgStore.CheckValid(sgm) {
				return
			}
			if !gc.verifyBlock(sgm.GossipMessage, msg.GetConnectionInfo().PkiID) {
				gc.logger.Warnf("Failed verifying block %s sent by %s.", utils.DataMessageToString(dataMsg), msg.GetConnectionInfo().PkiID.String())
				return
			}
			gc.mutex.Lock()
			added = gc.blockMsgStore.Add(sgm)
			if added {
				gc.logger.Debugf("Add %s to the block puller.", sgm.String())
				gc.blocksPuller.Add(sgm)
			}
			gc.mutex.Unlock()
		} else {
			added = gc.stateInfoMsgStore.Add(sgm)
		}

		if added {
			gc.adapter.Forward(msg)
			gc.adapter.DeMultiplex(sgm)
		}
		return
	}

	// 将 pull 消息存储到 PullStore 里
	if utils.IsPullMsg(sgm.GossipMessage) && utils.GetPullMsgType(sgm.GossipMessage) == pgossip.PullMsgType_BLOCK_MSG {
		if gc.hasLeftChannel() {
			gc.logger.Infof("We have left the channel, so we have to discard the pull message %s from %s.", sgm.String(), msg.GetConnectionInfo().PkiID.String())
			return
		}

		if gc.stateInfoMsgStore.MsgByID(msg.GetConnectionInfo().PkiID) == nil {
			gc.logger.Infof("Because we don't have StateInfo message of peer %s, so we have no way of validating its eligibility in the channel %s.", msg.GetConnectionInfo().PkiID.String(), gc.channelID.String())
			return
		}
		if !gc.eligibleForChannelAndSameOrg(utils.NetworkMember{PKIid: msg.GetConnectionInfo().PkiID}) {
			gc.logger.Warnf("Peer %s is not eligible for pulling blocks from channel %s.", msg.GetConnectionInfo().PkiID.String(), gc.channelID.String())
			return
		}
		if dataUpdate := sgm.GetDataUpdate(); dataUpdate != nil {
			var msgs []*utils.SignedGossipMessage
			var envelopes []*pgossip.Envelope
			var filteredEnvelopes []*pgossip.Envelope
			for _, envelope := range dataUpdate.Data {
				signedMsg, err := utils.EnvelopeToSignedGossipMessage(envelope)
				if err != nil {
					gc.logger.Warnf("DataUpdate message contains an invalid envelope: %s.", err.Error())
					return
				}
				if !bytes.Equal(signedMsg.Channel, gc.channelID) {
					gc.logger.Warnf("DataUpdate contains an envelope from a different channel %s, should be from %s.", utils.ChannelToString(signedMsg.Channel), gc.channelID.String())
					return
				}
				if !gc.blockMsgStore.CheckValid(signedMsg) {
					continue
				}
				if !gc.verifyBlock(signedMsg.GossipMessage, msg.GetConnectionInfo().PkiID) {
					return
				}
				msgs = append(msgs, signedMsg)
				envelopes = append(envelopes, envelope)
			}
			gc.mutex.Lock()
			defer gc.mutex.Unlock()

			for i, signedMsg := range msgs {
				envelope := envelopes[i]
				added := gc.blockMsgStore.Add(signedMsg)
				if !added {
					continue
				}
				filteredEnvelopes = append(filteredEnvelopes, envelope)
			}
			sgm.GetDataUpdate().Data = filteredEnvelopes
		}
		gc.blocksPuller.HandleMessage(msg)
	}

	if leadership := sgm.GetLeadershipMsg(); leadership != nil {
		orgOfSender := gc.adapter.GetOrgOfPeer(msg.GetConnectionInfo().PkiID)
		if !bytes.Equal(gc.selfOrg, orgOfSender) {
			gc.logger.Warnf("Received a leadership message from %s that belongs to a foreign organization %s.", msg.GetConnectionInfo().PkiID.String(), orgOfSender.String())
			return
		}
		orgOfMsgCreator := gc.adapter.GetOrgOfPeer(leadership.PkiId)
		if !bytes.Equal(gc.selfOrg, orgOfMsgCreator) {
			gc.logger.Warnf("Received leadership message created by %s that belongs to a foreign organization %s.", utils.PKIidType(leadership.PkiId).String(), orgOfMsgCreator.String())
			return
		}
		added := gc.leaderMsgStore.Add(sgm)
		if added {
			gc.adapter.DeMultiplex(sgm)
		}
	}
}

func (gc *gossipChannel) AddToMsgStore(sgm *utils.SignedGossipMessage) {
	if dataMsg := sgm.GetDataMsg(); dataMsg != nil {
		gc.mutex.Lock()
		defer gc.mutex.Unlock()
		added := gc.blockMsgStore.Add(sgm)
		if added {
			gc.logger.Debugf("Add block %s to the block store.", utils.DataMessageToString(dataMsg))
			gc.blocksPuller.Add(sgm)
		}
	}

	if sgm.GetStateInfo() != nil {
		gc.stateInfoMsgStore.Add(sgm)
	}
}

func (gc *gossipChannel) ConfigureChannel(joinMsg utils.JoinChannelMessage) {
	gc.mutex.Lock()
	defer gc.mutex.Unlock()

	if len(joinMsg.Orgs()) == 0 {
		gc.logger.Warn("Received join channel message with empty set of organizations.")
		return
	}

	if gc.joinMsg == nil {
		gc.joinMsg = joinMsg
	}

	if gc.joinMsg.SequenceNumber() > joinMsg.SequenceNumber() {
		gc.logger.Warn("Already have a more updated JoinChannel message: %d > %d.", gc.joinMsg.SequenceNumber(), joinMsg.SequenceNumber())
		return
	}

	gc.orgs = joinMsg.Orgs()
	gc.joinMsg = joinMsg
	gc.stateInfoMsgStore.validate(joinMsg.Orgs())
}

func (gc *gossipChannel) LeaveChannel() {
	gc.mutex.Lock()
	defer gc.mutex.Unlock()

	atomic.StoreInt32(&gc.leftChannel, 1)

	var chaincodes []*pgossip.Chaincode
	var height uint64
	if prevStateInfoMsg := gc.selfStateInfoMsg; prevStateInfoMsg != nil {
		chaincodes = prevStateInfoMsg.GetStateInfo().Properties.Chaincodes
		height = prevStateInfoMsg.GetStateInfo().Properties.LedgerHeight
	}
	gc.updateProperties(height, chaincodes, true)
	atomic.StoreInt32(&gc.shouldGossipStateInfo, 1)
}

func (gc *gossipChannel) Stop() {
	close(gc.stopCh)
	close(gc.membershipTracker.stopChan)
	gc.blocksPuller.Stop()
	gc.stateInfoPublishScheduler.Stop()
	gc.stateInfoRequestScheduler.Stop()
	gc.leaderMsgStore.Stop()
	gc.stateInfoMsgStore.Stop()
	gc.blockMsgStore.Stop()
}

/* ------------------------------------------------------------------------------------------ */

type Adapter interface {
	Sign(*pgossip.GossipMessage) (*utils.SignedGossipMessage, error)

	GetConf() Config

	// Gossip 在通道内广播消息。
	Gossip(*utils.SignedGossipMessage)

	// Forward 将消息转发给下一跳。（只转发区块和状态信息）
	Forward(utils.ReceivedMessage)

	// DeMultiplex 将消息分发给相关订阅者。
	DeMultiplex(any)

	GetMembership() utils.Members

	Lookup(utils.PKIidType) *utils.NetworkMember

	Send(msg *utils.SignedGossipMessage, peers ...*utils.RemotePeer)

	ValidateStateInfoMessage(*utils.SignedGossipMessage) error

	// GetOrgOfPeer 获取给定 peer 节点的组织标识。
	GetOrgOfPeer(utils.PKIidType) utils.OrgIdentityType

	// GetIdentityByPKIID 根据 peer 节点的身份标识符，获取节点的证书信息。
	GetIdentityByPKIID(utils.PKIidType) utils.PeerIdentityType
}

type gossipChannel struct {
	adapter Adapter

	// 状态信息
	selfOrg                utils.OrgIdentityType
	selfStateInfoMsg       *pgossip.GossipMessage
	selfStateInfoSignedMsg *utils.SignedGossipMessage
	ledgerHeight           uint64
	incTime                uint64
	pkiID                  utils.PKIidType
	leftChannel            int32
	stopCh                 chan struct{}
	shouldGossipStateInfo  int32 // 每次更新完状态后，此标志为就会被置为 1，每广播过一次状态信息，此标志为就会被置为 0。

	stateInfoMsgStore *stateInfoCache
	leaderMsgStore    msgstore.MessageStore
	blockMsgStore     msgstore.MessageStore

	channelID    utils.ChannelID
	logger       mlog.Logger
	mcs          utils.MessageCryptoService
	orgs         []utils.OrgIdentityType
	blocksPuller pull.PullMediator
	joinMsg      utils.JoinChannelMessage

	stateInfoPublishScheduler *time.Ticker
	stateInfoRequestScheduler *time.Ticker

	membershipTracker *membershipTracker

	mutex *sync.RWMutex
}

// GetMembership 只返回那些在本地能找到身份证书且能从本通道内获得区块的 peer 节点。
func (gc *gossipChannel) GetMembership() utils.Members {
	if gc.hasLeftChannel() {
		gc.logger.Warnf("We %s have left the gossip channel.", gc.pkiID.String())
		return nil
	}
	var members utils.Members
	for _, member := range gc.adapter.GetMembership() {
		if gc.eligibleForChannelAndSameOrg(member) {
			members = append(members, member)
		}
	}
	return members
}

/* ------------------------------------------------------------------------------------------ */

// eligibleForChannelAndSameOrg 判断给定的 peer 节点所来自的 org 与我所在的 org 是否一样，并且还要判断此节点之前
// 有没有给我们发送过状态信息，同时还要判断此节点是否有合法的证书存储在我们本地，前面三者都满足的情况下，此方法返回 true。
func (gc *gossipChannel) eligibleForChannelAndSameOrg(that utils.NetworkMember) bool {
	sameOrg := func(that utils.NetworkMember) bool {
		return bytes.Equal(gc.adapter.GetOrgOfPeer(that.PKIid), gc.selfOrg)
	}
	return utils.CombineRoutingFilters(gc.ShouldGetBlocksForThisChannel, sameOrg)(that)
}

func (gc *gossipChannel) hasLeftChannel() bool {
	return atomic.LoadInt32(&gc.leftChannel) == int32(1)
}

// updateProperties 更新一下本地账本高度，然后更新一下自己的状态信息：selfStateInfoMsg。
func (gc *gossipChannel) updateProperties(ledgerHeight uint64, chaincodes []*pgossip.Chaincode, leftChannel bool) {
	stateInfoMsg := &pgossip.StateInfo{
		Channel_MAC: utils.GenerateMAC(gc.pkiID, gc.channelID),
		PkiId:       gc.pkiID,
		Timestamp: &pgossip.PeerTime{
			IncNum: gc.incTime,
			SeqNum: uint64(time.Now().UnixNano()),
		},
		Properties: &pgossip.Properties{
			LedgerHeight: ledgerHeight,
			LeftChannel:  leftChannel,
			Chaincodes:   chaincodes,
		},
	}
	m := &pgossip.GossipMessage{
		Tag: pgossip.GossipMessage_CHAN_OR_ORG,
		Content: &pgossip.GossipMessage_StateInfo{
			StateInfo: stateInfoMsg,
		},
	}
	gc.ledgerHeight = ledgerHeight
	gc.selfStateInfoMsg = m
}

func (gc *gossipChannel) createStateInfoRequest() (*utils.SignedGossipMessage, error) {
	return utils.NoopSign(&pgossip.GossipMessage{
		Tag:     pgossip.GossipMessage_CHAN_OR_ORG,
		Nonce:   0,
		Channel: gc.channelID,
		Content: &pgossip.GossipMessage_StateInfoPullReq{
			StateInfoPullReq: &pgossip.StateInfoPullRequest{
				Channel_MAC: utils.GenerateMAC(gc.pkiID, gc.channelID),
			},
		},
	})
}

// createStateInfoSnapshot 如果自己与请求者不在同一组织内，就将与请求者不在统一组织的节点状态信息发送给请求者，
// 或者如果请求者与自己在同一组织，就将自己所了解的所有节点的状态信息发送给请求者。或者自己与请求者不在同一组织
// 内，但自己所了解的其他节点如果与请求者在同一组织内，且自己知道那些节点的 external endpoint，那么就将这些节
// 点的状态信息发送给请求者。
func (gc *gossipChannel) createStateInfoSnapshot(requestOrg utils.OrgIdentityType) *pgossip.GossipMessage {
	sameOrg := bytes.Equal(gc.selfOrg, requestOrg)
	rawElements := gc.stateInfoMsgStore.Get()
	elements := []*pgossip.Envelope{}
	for _, rawElement := range rawElements {
		sgm := rawElement.(*utils.SignedGossipMessage)
		orgOfCurrentMsg := gc.adapter.GetOrgOfPeer(sgm.GetStateInfo().PkiId)

		// 如果请求者与自己在同一组织内，或者状态消息来自于其他组织，那么就将此状态信息告诉给请求者。
		if sameOrg || !bytes.Equal(orgOfCurrentMsg, gc.selfOrg) {
			elements = append(elements, sgm.Envelope)
			continue
		}

		// 如果状态消息的发送者没有 external endpoint，则此消息不告诉给请求者。
		if member := gc.adapter.Lookup(sgm.GetStateInfo().PkiId); member == nil || member.Endpoint == "" {
			continue
		}

		elements = append(elements, sgm.Envelope)
	}
	return &pgossip.GossipMessage{
		Channel: gc.channelID,
		Tag:     pgossip.GossipMessage_CHAN_OR_ORG,
		Nonce:   0,
		Content: &pgossip.GossipMessage_StateInfoSnapshot{
			StateInfoSnapshot: &pgossip.StateInfoSnapshot{
				Elements: elements,
			},
		},
	}
}

// createBlockPuller 只拉取区块号比我们目前账本高度高的区块。
func (gc *gossipChannel) createBlockPuller() pull.PullMediator {
	config := pull.PullConfig{
		MsgType:           pgossip.PullMsgType_BLOCK_MSG,
		Channel:           gc.channelID,
		PeerCountToSelect: gc.adapter.GetConf().PullPeerNum,
		PullInterval:      gc.adapter.GetConf().PullInterval,
		Tag:               pgossip.GossipMessage_CHAN_AND_ORG,
		PullEngineConfig: algo.Config{
			DigestWaitTime:   gc.adapter.GetConf().PullEngineConfig.DigestWaitTime,
			RequestWaitTime:  gc.adapter.GetConf().PullEngineConfig.RequestWaitTime,
			ResponseWaitTime: gc.adapter.GetConf().PullEngineConfig.ResponseWaitTime,
		},
	}

	identifierExtractor := func(sgm *utils.SignedGossipMessage) string {
		dataMsg := sgm.GetDataMsg()
		if dataMsg == nil || dataMsg.Payload == nil {
			gc.logger.Warn("Non-data block or with empty payload.")
			return ""
		}
		return fmt.Sprintf("%d", dataMsg.Payload.SeqNum)
	}

	adapter := &pull.PullAdapter{
		Sender:               gc.adapter,
		MembershipService:    gc,
		IdentitfierExtractor: identifierExtractor,
		MsgConsumer: func(message *utils.SignedGossipMessage) {
			gc.adapter.DeMultiplex(message)
		},
	}

	adapter.IngressDigestFilter = func(digestMsg *pgossip.DataDigest) *pgossip.DataDigest {
		gc.mutex.RLock()
		height := gc.ledgerHeight
		gc.mutex.RUnlock()
		digests := digestMsg.Digests
		digestMsg.Digests = nil
		for i := range digests {
			seqNum, err := strconv.ParseInt(string(digests[i]), 10, 64)
			if err != nil {
				gc.logger.Errorf("Failed parsing digest: %s.", err.Error())
				continue
			}
			if seqNum >= int64(height) {
				digestMsg.Digests = append(digestMsg.Digests, digests[i])
			}
		}
		return digestMsg
	}
	return pull.NewPullMediator(config, adapter, gc.logger)
}

// verifyMsg 验证收到的消息的基本属性是否正确。
func (gc *gossipChannel) verifyMsg(msg utils.ReceivedMessage) bool {
	if msg == nil {
		gc.logger.Warn("The received message is nil.")
		return false
	}

	sgm := msg.GetSignedGossipMessage()
	if sgm == nil {
		gc.logger.Warn("The received message content is nil.")
		return false
	}

	// 这里的验证顺序与 fabric 不同，导致传递的状态信息消息，必须附带 channel-id。
	channelID := utils.ChannelID(sgm.Channel)
	if !bytes.Equal(channelID, gc.channelID) {
		gc.logger.Warnf("The received message comes from the different channel %s.", channelID)
		return false
	}

	if msg.GetConnectionInfo().PkiID == nil {
		gc.logger.Warn("The received message has nil PKI-ID.")
		return false
	}

	if stateInfo := sgm.GetStateInfo(); stateInfo != nil {
		expectedMAC := utils.GenerateMAC(stateInfo.PkiId, gc.channelID)
		if !bytes.Equal(expectedMAC, stateInfo.Channel_MAC) {
			gc.logger.Warn("StateInfo message contains wrong Channel_MAC %x, expected %x.", stateInfo.Channel_MAC, expectedMAC)
			return false
		}
		return true
	}

	if stateInfoPullRequest := sgm.GetStateInfoPullReq(); stateInfoPullRequest != nil {
		expectedMAC := utils.GenerateMAC(msg.GetConnectionInfo().PkiID, gc.channelID)
		if !bytes.Equal(expectedMAC, stateInfoPullRequest.Channel_MAC) {
			gc.logger.Warnf("StateInfoPullReq message contains wrong Channel_MAC %x, expected %x.", stateInfoPullRequest.Channel_MAC, expectedMAC)
			return false
		}
		return true
	}

	return true
}

func (gc *gossipChannel) verifyBlock(msg *pgossip.GossipMessage, sender utils.PKIidType) bool {
	dataMsg := msg.GetDataMsg()
	if dataMsg == nil {
		gc.logger.Warnf("Received from %s a DataMsg which contains a non-block GossipMessage: %s.", sender.String(), utils.GossipMessageToString(msg))
		return false
	}
	payload := dataMsg.Payload
	if payload == nil {
		gc.logger.Warnf("Received an unexpected DataMsg without payload from %s.", sender.String())
		return false
	}
	seqNum := payload.SeqNum
	rawBlockData := payload.Data
	block, err := protoutil.UnmarshalBlock(rawBlockData)
	if err != nil {
		gc.logger.Errorf("Received improperly encoded block from %s in DataMsg: %s.", sender.String(), err.Error())
		return false
	}
	if err = gc.mcs.VerifyBlock(msg.Channel, seqNum, block); err != nil {
		gc.logger.Errorf("Received invalid block from %s in DataMsg: %s.", sender.String(), err.Error())
		return false
	}

	return true
}

func (gc *gossipChannel) periodicalInvocation(fn func(), c <-chan time.Time) {
	for {
		select {
		case <-c:
			fn()
		case <-gc.stopCh:
			return
		}
	}
}

// setupSignedStateInfoMessage 提取出自己的状态信息，然后对此状态信息进行签名，将签过名的
// 状态信息保存下来，并返回出来。
func (gc *gossipChannel) setupSignedStateInfoMessage() (*utils.SignedGossipMessage, error) {
	gc.mutex.RLock()
	stateInfoMsg := gc.selfStateInfoMsg
	gc.mutex.RUnlock()

	signedStateInfoMsg, err := gc.adapter.Sign(stateInfoMsg)
	if err != nil {
		gc.logger.Errorf("Failed signing state info message: %s.", err.Error())
		return nil, err
	}
	gc.mutex.Lock()
	gc.selfStateInfoSignedMsg = signedStateInfoMsg
	gc.mutex.Unlock()

	return signedStateInfoMsg, nil
}

// requestStateInfo 随机挑选通道内的 PullPeerNum 个成员，向他们发送状态 request 消息。
func (gc *gossipChannel) requestStateInfo() {
	req, err := gc.createStateInfoRequest()
	if err != nil {
		gc.logger.Warnf("Failed creating request message for state info: %s.", err.Error())
		return
	}
	endpoints := utils.SelectPeers(gc.adapter.GetConf().PullPeerNum, gc.adapter.GetMembership(), gc.IsMemberInChannel)
	gc.adapter.Send(req, endpoints...)
}

// publishStateInfo 此方法用于阶段性的向通道内其他节点广播自己的状态信息，在每个阶段中，如果
// 自己的状态没有发生改变，就不广播自己的状态信息。每次广播过状态消息后，都会将 shouldGossipStateInfo 标志位设置成 0。
func (gc *gossipChannel) publishStateInfo() {
	if atomic.LoadInt32(&gc.shouldGossipStateInfo) == int32(0) {
		return
	}

	if len(gc.adapter.GetMembership()) == 0 {
		gc.logger.Debug("Empty membership, no need to publish StateInfo message.")
		return
	}

	gc.publishSignedStateInfoMessage()
	atomic.StoreInt32(&gc.shouldGossipStateInfo, 0)
}

// publishSignedStateInfoMessage 广播自己的状态信息。
func (gc *gossipChannel) publishSignedStateInfoMessage() {
	signedStateInfoMsg, err := gc.setupSignedStateInfoMessage()
	if err != nil {
		gc.logger.Errorf("Failed setting up signed state info message: %s.", err.Error())
		return
	}
	gc.stateInfoMsgStore.Add(signedStateInfoMsg)
	gc.adapter.Gossip(signedStateInfoMsg)
}

func (gc *gossipChannel) handleStateInfoSnapshot(m *pgossip.GossipMessage, sender utils.PKIidType) {
	channelName := gc.channelID.String()
	for _, envelope := range m.GetStateInfoSnapshot().Elements {
		signedStateInfo, err := utils.EnvelopeToSignedGossipMessage(envelope)
		if err != nil {
			gc.logger.Warnf("Channel %s: state info snapshot contains an invalid message: %s.", channelName, err.Error())
			return
		}
		stateInfo := signedStateInfo.GetStateInfo()
		if stateInfo == nil {
			gc.logger.Warnf("Channel %s: there is a element in state info snapshot isn't the StateInfo message, which was sent by sender %s.", channelName, sender.String())
			return
		}
		orgID := gc.adapter.GetOrgOfPeer(stateInfo.PkiId)
		if orgID == nil {
			gc.logger.Warnf("Channel %s: there is a StateInfo message without organization identity, which was sent by sender %s.", channelName, sender.String())
			return
		}
		if !gc.IsOrgInChannel(orgID) {
			gc.logger.Warnf("Channel %s: there is a StateInfo message from a not eligible organization %s, which was sent by sender %s.", channelName, orgID.String(), sender.String())
			return
		}
		expectedMAC := utils.GenerateMAC(stateInfo.PkiId, gc.channelID)
		if !bytes.Equal(stateInfo.Channel_MAC, expectedMAC) {
			gc.logger.Warnf("Channel %s: there is a StateInfo message sent by sender %s with unexpected MAC %x, expected %x.", channelName, sender.String(), stateInfo.Channel_MAC, expectedMAC)
			return
		}
		if err := gc.adapter.ValidateStateInfoMessage(signedStateInfo); err != nil {
			gc.logger.Warnf("Channel %s: there is a invalid StateInfo message sent by sender %s, the error is %s.", channelName, sender.String(), err.Error())
			return
		}
		if gc.adapter.Lookup(stateInfo.PkiId) == nil {
			gc.logger.Warnf("Channel %s: the received StateInfo message is about a unknown peer %s, we should ignore it.", channelName, utils.PKIidType(stateInfo.PkiId).String())
			continue
		}
		gc.stateInfoMsgStore.Add(signedStateInfo)
	}
}

/* ------------------------------------------------------------------------------------------ */

// membershipPredicate 基于一组可选的组织标识符，验证给定的状态信息是否适合于当前通道。
type membershipPredicate func(sgm *utils.SignedGossipMessage, orgs ...utils.OrgIdentityType) bool

type stateInfoCache struct {
	*utils.MembershipStore
	msgstore.MessageStore
	verify   membershipPredicate
	stopChan chan struct{}
}

func newStateInfoCache(clearInterval time.Duration, shouldPurge func(any) bool, verifyFunc membershipPredicate) *stateInfoCache {
	membershipStore := utils.NewMembershipStore()
	comparatorPolicy := utils.NewGossipMessageComparator(0)

	cache := &stateInfoCache{
		verify:          verifyFunc,
		MembershipStore: membershipStore,
		stopChan:        make(chan struct{}),
	}
	invalidationTrigger := func(m any) {
		pkiID := m.(*utils.SignedGossipMessage).GetStateInfo().PkiId
		membershipStore.Remove(pkiID)
	}
	cache.MessageStore = msgstore.NewMessageStore(comparatorPolicy, invalidationTrigger)

	go func() {
		for {
			select {
			case <-cache.stopChan:
				return
			case <-time.After(clearInterval):
				cache.Purge(shouldPurge) // 清除掉那些在本地找不到消息创造者身份证书的消息。
			}
		}
	}()

	return cache
}

func (sic *stateInfoCache) Add(msg *utils.SignedGossipMessage) bool {
	if !sic.verify(msg) {
		return false
	}
	added := sic.MessageStore.Add(msg)
	if added {
		pkiID := msg.GetStateInfo().PkiId
		sic.MembershipStore.Put(pkiID, msg)
	}
	return added
}

func (sic *stateInfoCache) validate(orgs []utils.OrgIdentityType) {
	for _, msg := range sic.Get() {
		sgm := msg.(*utils.SignedGossipMessage)
		if !sic.verify(sgm, orgs...) {
			sic.delete(sgm)
		}
	}
}

func (sic *stateInfoCache) delete(sgm *utils.SignedGossipMessage) {
	sic.Purge(func(a any) bool {
		pkiID := a.(*utils.SignedGossipMessage).GetStateInfo().PkiId
		return bytes.Equal(pkiID, sgm.GetStateInfo().PkiId)
	})
	sic.Remove(sgm.GetStateInfo().PkiId)
}

/* ------------------------------------------------------------------------------------------ */

type membershipTracker struct {
	getPeersToTrack func() utils.Members
	report          func(format string, args ...any)
	stopChan        chan struct{}
	tickerC         <-chan time.Time
	metrics         *metrics.MembershipMetrics
	channelID       utils.ChannelID
}

func endpoints(members utils.Members) [][]string {
	var curView [][]string
	for _, member := range members {
		internal := member.InternalEndpoint
		external := member.Endpoint
		var endpoints []string
		if internal != external {
			endpoints = append(endpoints, external, internal)
		} else {
			endpoints = append(endpoints, external)
		}
		curView = append(curView, endpoints)
	}
	return curView
}

func (mt *membershipTracker) checkIfPeersChanged(prevPeers utils.Members, currPeers utils.Members, prevSetPeers map[string]struct{}, currSetPeers map[string]struct{}) {
	var currView [][]string

	// 把不在 currSetPeers 里但在 prevPeers 里的节点挑出来，也就是说把当前这个时候消失的旧节点挑出来
	wereInPrev := endpoints(prevPeers.Filter(func(peer utils.NetworkMember) bool {
		_, exists := currSetPeers[peer.PKIid.String()]
		return !exists
	}))

	// 把不在 prevSetPeers 里但在 currPeers 里的节点挑出来，也就是说把当前这个时候新出现的节点挑出来
	newInCurr := endpoints(currPeers.Filter(func(peer utils.NetworkMember) bool {
		_, exists := prevSetPeers[peer.PKIid.String()]
		return !exists
	}))

	currView = endpoints(currPeers)

	if !reflect.DeepEqual(wereInPrev, newInCurr) {
		if len(wereInPrev) == 0 {
			mt.report("Membership view has changed, peers went online: %s, current view: %s.", newInCurr, currView)
		} else if len(newInCurr) == 0 {
			mt.report("Membership view has changed, peers went offline: %s, current view: %s.", wereInPrev, currView)
		} else {
			mt.report("Membership view has changed, peers went online: %s, peers went offline: %s, current view: %s.", newInCurr, wereInPrev, currView)
		}
	}
}

func (mt *membershipTracker) createSetOfPeers(peers utils.Members) map[string]struct{} {
	set := make(map[string]struct{})
	for _, peer := range peers {
		set[peer.PKIid.String()] = struct{}{}
	}
	return set
}

func (mt *membershipTracker) trackMembershipChanges() {
	prevPeers := mt.getPeersToTrack()
	prevSetPeers := mt.createSetOfPeers(prevPeers)

	for {
		select {
		case <-mt.stopChan:
			return
		case <-mt.tickerC:
			currPeers := mt.getPeersToTrack()
			mt.metrics.Total.With("channel", mt.channelID.String()).Set(float64(len(currPeers)))
			currSetPeers := mt.createSetOfPeers(currPeers)
			mt.checkIfPeersChanged(prevPeers, currPeers, prevSetPeers, currSetPeers)
			prevPeers = currPeers
			prevSetPeers = mt.createSetOfPeers(prevPeers)
		}
	}
}
