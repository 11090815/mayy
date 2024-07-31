package gossip

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/discovery"
	"github.com/11090815/mayy/gossip/gossip/algo"
	"github.com/11090815/mayy/gossip/gossip/channel"
	"github.com/11090815/mayy/gossip/gossip/comm"
	"github.com/11090815/mayy/gossip/gossip/msgstore"
	"github.com/11090815/mayy/gossip/gossip/pull"
	"github.com/11090815/mayy/gossip/metrics"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
	"google.golang.org/protobuf/proto"
)

const (
	presumedDeadChanSize = 100
	acceptChanSize       = 100
)

/* ------------------------------------------------------------------------------------------ */

type channelRoutingFilterFactory func(channel.GossipChannel) utils.RoutingFilter

/* ------------------------------------------------------------------------------------------ */

type SendRule struct {
	Timeout time.Duration
	// MinAck 规定了将此消息发送出去后，至少要受到多少个回应。
	MinAck int
	// MaxPeers 规定了将此消息发送给最多多少个节点。
	MaxPeers int
	// IsEligible 用来表示一个特定的 peer 节点是否有权力收到此消息。
	IsEligible utils.RoutingFilter
	// Channel 规定将此消息发送到哪个通道。
	Channel utils.ChannelID
}

func (sr SendRule) String() string {
	return fmt.Sprintf("{SendRule | Timeout: %sms; MinAck: %d; MaxPeers: %d; Channel: %s}", sr.Timeout.Milliseconds(), sr.MinAck, sr.MaxPeers, sr.Channel.String())
}

/* ------------------------------------------------------------------------------------------ */

type Node struct {
	selfIdentity utils.PeerIdentityType
	selfOrg      utils.OrgIdentityType
	// discovery 在签署 alive 消息时，如果签署时的时间早于 includeIdentityPeriod，则会将关于节点身份证书
	// 的 identity 放到 alive 消息中。
	includeIdentityPeriod time.Time

	cs           *certStore
	idMapper     utils.IdentityMapper
	presumedDead chan utils.PKIidType
	conf         Config

	disc           discovery.Discovery
	discAdapter    discovery.DiscoveryAdapter
	discSecAdapter discovery.DiscoverySecurityAdapter
	communication  comm.Comm
	demux          *comm.ChannelDeMultiplexer
	emitter        utils.BatchingEmitter
	secAdvisor     utils.SecurityAdvisor
	chanState      *channelState
	mcs            utils.MessageCryptoService
	certPuller     pull.PullMediator

	stateInfoMsgStore msgstore.MessageStore
	gossipMetrics     *metrics.GossipMetrics
	logger            mlog.Logger

	stopSignal *sync.WaitGroup
	stopFlag   int32
	toDieChan  chan struct{}
}

// IdentityInfo 返回所有网络邻居节点的身份信息，包括每个节点的：pki-id、cert、org。
func (node *Node) IdentityInfo() utils.PeerIdentitySet {
	return node.idMapper.IdentityInfo()
}

func (node *Node) SendByRule(sgm *utils.SignedGossipMessage, rule SendRule) error {
	if rule.MaxPeers == 0 {
		return nil
	}
	if rule.Timeout == 0 {
		return errors.NewErrorf("The rule %s didn't specify the timeout.", rule.String())
	}

	if rule.IsEligible == nil {
		rule.IsEligible = utils.SelectAllPolicy
	}

	membership := node.disc.GetMembership()

	if len(rule.Channel) > 0 {
		ch := node.chanState.getGossipChannelByChannelID(rule.Channel)
		if ch == nil {
			return errors.NewErrorf("requested to send for channel %s, but this channel doesn't exist.", rule.Channel.String())
		}
		membership = ch.GetPeers()
	}

	// 从给定的节点中选出最少 MaxPeers 个符合 IsEligible 规则的节点出来。
	peers2send := utils.SelectPeers(rule.MaxPeers, membership, rule.IsEligible)
	if len(peers2send) < rule.MinAck {
		return errors.NewErrorf("requested to send to at least %d peers, but only %d suitable peers exist", rule.MinAck, len(peers2send))
	}

	results := node.communication.SendWithAck(sgm, rule.Timeout, rule.MinAck, peers2send...)

	for _, result := range results {
		if result.Error() == "" {
			continue
		}
		node.logger.Errorf("Failed sending to %s: %s.", result.Endpoint, result.Error())
	}

	if results.AckCount() < rule.MinAck {
		return errors.NewError(results.String())
	}

	return nil
}

func (node *Node) Gossip(msg *pgossip.GossipMessage) {
	if err := utils.IsTagValid(msg); err != nil {
		node.logger.Panicf("Unable to gossip message with invalid tag: %s.", err.Error())
	}
	sgm := &utils.SignedGossipMessage{
		GossipMessage: msg,
	}

	var err error
	if msg.GetDataMsg() != nil {
		sgm, err = utils.NoopSign(msg)
	} else {
		sgm.Sign(func(msg []byte) ([]byte, error) {
			return node.mcs.Sign(msg)
		})
	}
	if err != nil {
		node.logger.Errorf("Failed signing message (%s): %s.", utils.GossipMessageToString(msg), err.Error())
		return
	}

	if utils.IsChannelRestricted(msg) {
		ch := node.chanState.getGossipChannelByChannelID(msg.Channel)
		if ch == nil {
			node.logger.Warnf("Failed gossiping channel rectricted message (%s): we don't have such chanel (%s).", utils.GossipMessageToString(msg), utils.ChannelID(msg.Channel).String())
			return
		}
		if msg.GetDataMsg() != nil {
			ch.AddToMsgStore(sgm)
		}
	}

	if node.conf.PropagateIterations == 0 {
		return
	}

	node.emitter.Add(utils.NewEmittedGossipMessage(sgm, func(pt utils.PKIidType) bool { return true }))
}

// Send 调用 Comm 模块的 Send 方法向若干个 peer 节点发送消息。
func (node *Node) Send(msg *pgossip.GossipMessage, peers ...*utils.RemotePeer) {
	sgm, err := utils.NoopSign(msg)
	if err != nil {
		node.logger.Errorf("Failed creating SignedGossipMessage: %s.", err.Error())
		return
	}
	node.communication.Send(sgm, peers...)
}

// Peers 返回此 gossip node 所知道的网络成员信息。
func (node *Node) Peers() utils.Members {
	return node.disc.GetMembership()
}

// PeersOfChannel 返回指定通道内的 peer 节点。
func (node *Node) PeersOfChannel(channelID utils.ChannelID) utils.Members {
	ch := node.chanState.getGossipChannelByChannelID(channelID)
	if ch == nil {
		node.logger.Warnf("Channel %s does not exist.", channelID.String())
		return nil
	}
	return ch.GetPeers()
}

// SelfMembershipInfo 获取该 gossip node 的个人信息。
func (node *Node) SelfMembershipInfo() utils.NetworkMember {
	return node.disc.Self()
}

// SelfChannelInfo 根据给定的 channel id，获取对应的 channel 信息。
func (node *Node) SelfChannelInfo(channelID utils.ChannelID) *utils.SignedGossipMessage {
	ch := node.chanState.getGossipChannelByChannelID(channelID)
	if ch == nil {
		return nil
	}
	return ch.Self()
}

// PeerFilter 接收一个 SubChannelSelectionRule 并返回一个 RoutingFilter，它只选择匹配给定条件的 peer 节点，并且这些节点在之前发布过它们的状态信息。
func (node *Node) PeerFilter(channel utils.ChannelID, pred utils.SubChannelSelectionRule) (utils.RoutingFilter, error) {
	ch := node.chanState.getGossipChannelByChannelID(channel)
	if ch == nil {
		return nil, errors.NewErrorf("Channel %s does not exist.", channel.String())
	}
	return ch.PeerFilter(pred), nil
}

func (node *Node) UpdateMetadata(md []byte) {
	node.disc.UpdateMetadata(md)
}

// UpdateLedgerHeight 根据给定的 channelID，从 channel state 中找到对应的 channel，更新此 channel 的 ledger height。
func (node *Node) UpdateLedgerHeight(height uint64, channelID utils.ChannelID) {
	ch := node.chanState.getGossipChannelByChannelID(channelID)
	if ch == nil {
		node.logger.Warnf("We don't have such channel: %s.", channelID.String())
		return
	}
	ch.UpdateLedgerHeight(height)
}

// UpdateChaincodes 根据给定的 channelID，从 channel state 中找到对应的 channel，更新此 channel 的 chaincodes。
func (node *Node) UpdateChaincodes(chaincodes []*pgossip.Chaincode, channelID utils.ChannelID) {
	ch := node.chanState.getGossipChannelByChannelID(channelID)
	if ch == nil {
		node.logger.Warnf("We don't have such channel: %s.", channelID.String())
		return
	}
	ch.UpdateChaincodes(chaincodes)
}

// Accept 如果传入的 passThrough 等于 true，则返回的第一个消息通道等于 nil，否则返回的第二个通道等于 nil。
func (node *Node) Accept(acceptor utils.MessageAcceptor, passThrough bool) (<-chan *pgossip.GossipMessage, <-chan utils.ReceivedMessage) {
	if passThrough {
		return nil, node.communication.Accept(acceptor)
	}

	acceptByType := func(o any) bool {
		if gossipMsg, isGossipMsg := o.(*pgossip.GossipMessage); isGossipMsg {
			return acceptor(gossipMsg)
		}
		if sgm, isSignedMsg := o.(*utils.SignedGossipMessage); isSignedMsg {
			return acceptor(sgm.GossipMessage)
		}
		node.logger.Warnf("Expect *GossipMessage and *SignedGossipMessage, but got %T.", o)
		return false
	}

	inCh := node.demux.AddChannel(acceptByType)
	outCh := make(chan *pgossip.GossipMessage, acceptChanSize)
	go func() {
		defer close(outCh)
		for {
			select {
			case <-node.toDieChan:
				return
			case m, isOpen := <-inCh:
				if !isOpen {
					return
				}
				select {
				case <-node.toDieChan:
					return
				case outCh <- m.(*utils.SignedGossipMessage).GossipMessage:
				}
			}
		}
	}()
	return outCh, nil
}

// IsInMyOrg 给定一个网络成员，判断此成员是否与 node 自己同属于一个组织。
func (node *Node) IsInMyOrg(member utils.NetworkMember) bool {
	if member.PKIid == nil {
		return false
	}
	if org := node.getOrgOfPeer(member.PKIid); org != nil {
		return bytes.Equal(node.selfOrg, org)
	}
	return false
}

func (node *Node) Stop() {
	if node.isStopped() {
		return
	}
	atomic.StoreInt32(&node.stopFlag, 1)
	node.logger.Info("Stopping gossip node instance.")
	close(node.toDieChan)
	node.stopSignal.Wait()
	node.chanState.stop()
	node.discAdapter.Stop()
	node.disc.Stop()
	node.cs.stop()
	node.emitter.Stop()
	node.demux.Close()
	node.stateInfoMsgStore.Stop()
	node.communication.Stop()
}

/* ------------------------------------------------------------------------------------------ */

// gossipBatch 广播以下消息：
//  1. block
//  2. state info
//  3. leadership
//  4. org restricted msg
//  5. alive msg
func (node *Node) gossipBatch(msgs []*utils.EmittedGossipMessage) {
	if node.disc == nil {
		node.logger.Error("Discovery instance has not been initialized yet, aborting!")
		return
	}

	var blocks []*utils.EmittedGossipMessage
	var stateInfoMsgs []*utils.EmittedGossipMessage
	var orgMsgs []*utils.EmittedGossipMessage
	var leadershipMsgs []*utils.EmittedGossipMessage

	isBlock := func(o any) bool {
		return o.(*utils.EmittedGossipMessage).GetDataMsg() != nil
	}

	isStateInfo := func(o any) bool {
		return o.(*utils.EmittedGossipMessage).GetStateInfo() != nil
	}

	aliveMsgsWithNoEndpointAndInOurOrg := func(o any) bool {
		msg := o.(*utils.EmittedGossipMessage)
		if msg.GetAliveMsg() == nil {
			return false
		}
		member := msg.GetAliveMsg().Membership
		return member.Endpoint == "" && node.IsInMyOrg(utils.NetworkMember{PKIid: member.PkiId})
	}

	isOrgRestricted := func(o any) bool {
		return aliveMsgsWithNoEndpointAndInOurOrg(o) || utils.IsOrgRestricted(o.(*utils.EmittedGossipMessage).GossipMessage)
	}

	isLeadership := func(o any) bool {
		return o.(*utils.EmittedGossipMessage).GetLeadershipMsg() != nil
	}

	// 广播区块。
	blocks, msgs = partitionMessages(isBlock, msgs)
	node.gossipInChan(blocks, func(gc channel.GossipChannel) utils.RoutingFilter {
		return utils.CombineRoutingFilters(gc.ShouldGetBlocksForThisChannel, gc.IsMemberInChannel, node.IsInMyOrg)
	})

	// 广播 leadership 消息。
	leadershipMsgs, msgs = partitionMessages(isLeadership, msgs)
	node.gossipInChan(leadershipMsgs, func(gc channel.GossipChannel) utils.RoutingFilter {
		return utils.CombineRoutingFilters(gc.ShouldGetBlocksForThisChannel, gc.IsMemberInChannel, node.IsInMyOrg)
	})

	// 广播 state info 消息。
	stateInfoMsgs, msgs = partitionMessages(isStateInfo, msgs)
	for _, stateInfo := range stateInfoMsgs {
		peerSelector := node.IsInMyOrg
		ch := node.chanState.lookupChannelForGossipMsg(stateInfo.GossipMessage)
		if ch != nil && node.hasExternalEndpoint(stateInfo.GetStateInfo().PkiId) {
			peerSelector = ch.IsMemberInChannel
		}
		peerSelector = utils.CombineRoutingFilters(peerSelector, func(nm utils.NetworkMember) bool {
			return stateInfo.Filter(nm.PKIid)
		})
		peers2send := utils.SelectPeers(node.conf.PropagatePeerNum, node.disc.GetMembership(), peerSelector)
		node.communication.Send(stateInfo.SignedGossipMessage, peers2send...)
	}

	// 广播我们组织内的消息。
	orgMsgs, msgs = partitionMessages(isOrgRestricted, msgs)
	peers2send := utils.SelectPeers(node.conf.PropagatePeerNum, node.disc.GetMembership(), node.IsInMyOrg)
	for _, orgMsg := range orgMsgs {
		node.communication.Send(orgMsg.SignedGossipMessage, node.removeSelfLoop(orgMsg, peers2send)...)
	}

	// 光比剩余的 alive msg。
	for _, msg := range msgs {
		if msg.GetAliveMsg() == nil {
			node.logger.Warnf("Unexpected message: %s.", msg.SignedGossipMessage.String())
			continue
		}
		selectByOriginOrg := node.peersByOriginalOrPolicy(utils.NetworkMember{PKIid: msg.GetAliveMsg().Membership.PkiId})
		selector := utils.CombineRoutingFilters(selectByOriginOrg, func(nm utils.NetworkMember) bool {
			return msg.Filter(nm.PKIid)
		})
		peers2send := utils.SelectPeers(node.conf.PropagatePeerNum, node.disc.GetMembership(), selector)
		node.sendAndFilterSecrets(msg.SignedGossipMessage, peers2send...)
	}
}

// sendAndFilterSecrets 遍历每个给定的 peer 节点，如果给定的消息是来自于其他组织的 alive msg，并且当前
// 遍历到的 peer 节点没有 external endpoint，那么就跳过该节点，不给该节点发送此 alive msg；否则如果当前
// 遍历到的 peer 节点不在 node 所在的组织内，那么就不会将 SecretEnvelope 部分发送给此 peer 节点。
func (node *Node) sendAndFilterSecrets(msg *utils.SignedGossipMessage, peers ...*utils.RemotePeer) {
	for _, peer := range peers {
		aliveMsgFromForeignOrg := msg.GetAliveMsg() != nil && !node.IsInMyOrg(utils.NetworkMember{PKIid: msg.GetAliveMsg().Membership.PkiId})
		if aliveMsgFromForeignOrg && !node.hasExternalEndpoint(peer.PKIID) {
			continue
		}

		clonedMsg := &utils.SignedGossipMessage{}
		clonedMsg.GossipMessage = msg.GossipMessage
		clonedMsg.Envelope = msg.Envelope

		if !node.IsInMyOrg(utils.NetworkMember{PKIid: peer.PKIID}) {
			clonedMsg.Envelope = proto.Clone(msg.Envelope).(*pgossip.Envelope)
			clonedMsg.Envelope.SecretEnvelope = nil
		}
		node.communication.Send(clonedMsg, peer)
	}
}

// gossipInChan 方法给定若干个 EmittedGossipMessage 和一个能根据 channel 制定 RoutingFilter 策略的 chanRoutingFactory，
// 首先，我们能够明确的是每个 EmittedGossipMessage 都属于一个特定的 channel，那么，我们先从所有 EmittedGossipMessage 中提
// 取出所有 channel，然后遍历每个 channel，在每次遍历的时候，我们找出所有属于当前 channel 的 EmittedGossipMessage 消息，然
// 后，我们还要根据当前的 channel 找到 GossipChannel，然后我们从这个 GossipChannel 中找出若干个节点，将所有属于当前 channel
// 的 EmittedGossipMessage 消息发送给上一步找出的若干个节点。之后遍历下一个 channel，重复上述的步骤，直到将所有 EmittedGossipMessage
// 消息发送完毕。
func (node *Node) gossipInChan(messages []*utils.EmittedGossipMessage, chanRoutingFactory channelRoutingFilterFactory) {
	if len(messages) == 0 {
		return
	}
	totalChannels := extractChannels(messages)
	var channel utils.ChannelID
	var messagesOfChannel []*utils.EmittedGossipMessage
	for len(totalChannels) > 0 {
		channel, totalChannels = totalChannels[0], totalChannels[1:]
		grabMsgs := func(o any) bool {
			return bytes.Equal(o.(*utils.EmittedGossipMessage).Channel, channel)
		}
		// 找出所有属于通道 channel 的消息。
		messagesOfChannel, messages = partitionMessages(grabMsgs, messages)
		if len(messagesOfChannel) == 0 {
			continue
		}
		ch := node.chanState.getGossipChannelByChannelID(channel)
		if ch == nil {
			node.logger.Warnf("Unable to find channel %s.", channel.String())
			continue
		}
		membership := node.disc.GetMembership()
		var peers2send []*utils.RemotePeer
		if messagesOfChannel[0].GetLeadershipMsg() != nil {
			peers2send = utils.SelectPeers(len(membership), membership, chanRoutingFactory(ch))
		} else {
			peers2send = utils.SelectPeers(node.conf.PropagatePeerNum, membership, chanRoutingFactory(ch))
		}

		for _, msg := range messagesOfChannel {
			filteredPeers := node.removeSelfLoop(msg, peers2send)
			node.communication.Send(msg.SignedGossipMessage, filteredPeers...)
		}
	}
}

// removeSelfLoop 删除那些不能接收给定消息的节点。
func (node *Node) removeSelfLoop(msg *utils.EmittedGossipMessage, peers []*utils.RemotePeer) []*utils.RemotePeer {
	var result []*utils.RemotePeer
	for _, peer := range peers {
		if msg.Filter(peer.PKIID) {
			result = append(result, peer)
		}
	}
	return result
}

func (node *Node) isStopped() bool {
	return atomic.LoadInt32(&node.stopFlag) == int32(1)
}

// newDiscoveryAdapter 根据 node 配置文件信息实例化一个 discovery adapter，discovery 的广播和转播功能由 node
// 的 BatchingEmitter 定义。
func (node *Node) newDiscoveryAdapter() discovery.DiscoveryAdapter {
	return discovery.NewDiscoveryAdapter(node.communication, node.conf.PropagateIterations, node.emitter, node.presumedDead, node.disclosurePolicy)
}

// newDiscoverySecurityAdapter 新建一个针对 discovery 模块的 security 适配器，用于签署和验证 alive 消息。
func (node *Node) newDiscoverySecurityAdapter() discovery.DiscoverySecurityAdapter {
	return discovery.NewDiscoverySecurityAdapter(node.selfIdentity, node.includeIdentityPeriod, node.idMapper, node.mcs, node.logger)
}

// createCertStorePuller 创建一个 cert puller，根据配置文件信息，调整 pull interval 等参数配置，
// pull adapter 里的 MsgConsumer 的功能是将 peer 的 pki-id 和 identity 保存到 idMapper 里，且
// pull adapter 里的 EgressDigestFilter 用 sameOrgOrOurOrgPullFilter 方法定义。
func (node *Node) createCertStorePuller() pull.PullMediator {
	conf := pull.PullConfig{
		MsgType:           pgossip.PullMsgType_IDENTITY_MSG,
		Channel:           utils.ChannelID{},
		PeerCountToSelect: node.conf.ChannelConfig.PullPeerNum,
		PullInterval:      node.conf.ChannelConfig.PullInterval,
		Tag:               pgossip.GossipMessage_EMPTY,
		PullEngineConfig: algo.Config{
			DigestWaitTime:   node.conf.PullConfig.DigestWaitTime,
			RequestWaitTime:  node.conf.PullConfig.RequestWaitTime,
			ResponseWaitTime: node.conf.PullConfig.ResponseWaitTime,
		},
	}
	pkiIDFromMsg := func(msg *utils.SignedGossipMessage) string {
		identityMsg := msg.GetPeerIdentity()
		if identityMsg == nil || identityMsg.PkiId == nil {
			return ""
		}
		return utils.PKIidType(identityMsg.PkiId).String()
	}

	certConsumer := func(msg *utils.SignedGossipMessage) {
		identityMsg := msg.GetPeerIdentity()
		if identityMsg == nil || identityMsg.Cert == nil || identityMsg.PkiId == nil {
			node.logger.Warnf("Invalid peer identity: %s.", msg.String())
			return
		}
		if err := node.idMapper.Put(identityMsg.PkiId, identityMsg.Cert); err != nil {
			node.logger.Errorf("Failed putting peer identity (%s) into mapper: %s.", msg.String(), err.Error())
		} else {
			node.logger.Debugf("Learned of a new peer identity: %s.", msg.String())
		}
	}

	adapter := &pull.PullAdapter{
		Sender:               node.communication,
		MembershipService:    node.disc,
		IdentitfierExtractor: pkiIDFromMsg,
		MsgConsumer:          certConsumer,
		EgressDigestFilter:   node.sameOrgOrOurOrgPullFilter,
	}
	return pull.NewPullMediator(conf, adapter, node.logger)
}

// sameOrgOrOurOrgPullFilter 方法根据 ReceivedMessage 制定 PullFilter，PullEngine 用它确定哪些节点的 identity
// 能被发送给发送 Hello 消息的节点：
//
//	a. 如果 Hello 消息的产生者所属的组织是不明确的，那么制定的 PullFilter 恒返回 false，否则转到 b；
//	b. 如果 Hello 消息的产生者所属的组织与 node 自身所属的组织一样，那么制定的 PullFilter 恒返回 true，否则转到 c;
//	c. 如果 PullFilter 中传入的 pki-id 所属的组织 org 不明确，则 PullFilter 恒返回 false，否则转到 d；
//	d. 如果 PullFilter 中传入的 pki-id 所对应的节点不具有 external endpoint，则 PullFilter 恒返回 false，否则转到 e；
//	e. 如果 PullFilter 中传入的 pki-id 所对应的节点所属的组织与 node 自身所属的组织一样，或者 pki-id 所对应的节点所属的组织与 Hello 消息的产生者所属的组织一样，则 PullFilter 返回 true。
func (node *Node) sameOrgOrOurOrgPullFilter(msg utils.ReceivedMessage) func(string) bool {
	orgOfReceivedMsgProducer := node.secAdvisor.OrgByPeerIdentity(msg.GetConnectionInfo().Identity)
	if len(orgOfReceivedMsgProducer) == 0 {
		node.logger.Warnf("Failed determining org of received msg (%s).", msg.GetConnectionInfo().String())
		return func(s string) bool {
			return false
		}
	}

	if bytes.Equal(node.selfOrg, orgOfReceivedMsgProducer) {
		return func(s string) bool {
			return true
		}
	}

	return func(item string) bool {
		pkiID := utils.PKIidType(item)
		orgOfMsg := node.getOrgOfPeer(pkiID)
		if len(orgOfMsg) == 0 {
			node.logger.Warnf("Failed determining org of %s.", pkiID.String())
			return false
		}
		// 不要向外部组织的 peer 透露已经死亡的 peer 或没有外部 endpoint 的 peer 的身份。
		if !node.hasExternalEndpoint(pkiID) {
			return false
		}
		return bytes.Equal(orgOfMsg, node.selfOrg) || bytes.Equal(orgOfMsg, orgOfReceivedMsgProducer)
	}
}

// connect2BootstrapPeers 方法试图与 bootstrap peers 建立连接，并且会向对方发送 membership request 消息，
// 试图获得网络中其他成员信息。
func (node *Node) connect2BootstrapPeers() {
	for _, endpoint := range node.conf.DiscoveryConfig.BootstrapPeers {
		endpoint := endpoint
		identifier := func() (*discovery.PeerIdentification, error) {
			remotePeerIdentity, err := node.communication.Handshake(&utils.RemotePeer{Endpoint: endpoint})
			if err != nil {
				return nil, errors.NewErrorf("failed connecting to bootstrap peer %s: %s", endpoint, err.Error())
			}
			sameOrg := bytes.Equal(node.selfOrg, node.secAdvisor.OrgByPeerIdentity(remotePeerIdentity))
			if !sameOrg {
				return nil, errors.NewErrorf("peer %s is not in our org, it shouldn't be a bootstrap peer", endpoint)
			}
			pkiID := node.mcs.GetPKIidOfCert(remotePeerIdentity)
			if len(pkiID) == 0 {
				return nil, errors.NewErrorf("unable to extract pki-id of remote peer with identity %s", remotePeerIdentity.String())
			}
			return &discovery.PeerIdentification{PKIid: pkiID, SelfOrg: sameOrg}, nil
		}
		node.disc.Connect(utils.NetworkMember{InternalEndpoint: endpoint, Endpoint: endpoint}, identifier)
	}
}

// hasExternalEndpoint 方法根据给定节点的 pki-id 判断此节点是否具有 external endpoint。
func (node *Node) hasExternalEndpoint(pkiID utils.PKIidType) bool {
	if nm := node.disc.Lookup(pkiID); nm != nil {
		return nm.HasExternalEndpoint()
	}
	return false
}

// validateLeadershipMsg 方法与 validateStateInfoMsg 不一样，该方法利用 mcs 的 Verify 方法验证 leadership
// 消息中的签名是否合法。
func (node *Node) validateLeadershipMsg(msg *utils.SignedGossipMessage) error {
	pkiID := msg.GetLeadershipMsg().PkiId
	if len(pkiID) == 0 {
		return errors.NewErrorf("empty pki-id, failed validating leadership msg: %s", msg.String())
	}
	identity, err := node.idMapper.Get(pkiID)
	if err != nil {
		return errors.NewErrorf("failed validating leadership msg: %s", err.Error())
	}
	return msg.Verify(identity, func(peerIdentity utils.PeerIdentityType, signature, message []byte) error {
		return node.mcs.Verify(identity, signature, message)
	})
}

// validateStateInfoMsg 方法主要利用 idMapper 里的 Verify 方法来验证 state info 消息中的
// 签名是否合法。
func (node *Node) validateStateInfoMsg(msg *utils.SignedGossipMessage) error {
	verifier := func(identity utils.PeerIdentityType, signature, message []byte) error {
		pkiID := node.idMapper.GetPKIidOfCert(identity)
		return node.idMapper.Verify(pkiID, signature, message)
	}
	identity, err := node.idMapper.Get(msg.GetStateInfo().PkiId)
	if err != nil {
		return errors.NewErrorf("failed validating state info msg: %s", err.Error())
	}
	return msg.Verify(identity, verifier)
}

// disclosurePolicy 方法实例化一个转发消息的策略：
//  1. Sieve（是否将一个给定消息 message 转发给给定的 remote peer）
//     a. 如果 remote peer 的组织是未知的，Sieve 恒返回 false，否则转 b；
//     b. 如果给定的 message 内蕴含的不是 alive msg，则直接引起程序的 panic，否则转 c；
//     c. 如果 message 的创造者所属的组织是不明确的，那么程序将拒绝转发来历不明的消息，所以 Sieve 恒返回 false，否则转 d；
//     d. 如果 message 的创造者所属的组织 org 与 node 自身所属的组织不一样，且 org 与 remote peer 所属的组织也不一样，则 Sieve 恒返回 false，否则转 e；
//     e. 如果 message 的创造者所属的组织 org 与 remote peer 所属的组织一样，则 Sieve 恒返回 true，否则转 f；
//     f. 如果 message 的创造者所属的组织 org 与 node 自身所属的组织不一样，但 message 的 Endpoint 和 remote peer 的 Endpoint 都是公开的话，则 Sieve 恒返回 true。
//  2. EnvelopeFilter（决定给定的 Envelope 里的 SecretEnvelope 部分，是否有必要披露给给定的 remote peer）
//     a. 如果 remote peer 的组织是未知的，则 EnvelopeFilter 不会对给定的 Envelope 做任何处理，否则转 b；
//     b. 如果 remote peer 的组织与 node 自身所属的组织不一样，则 EnvelopeFilter 不会让 Envelope 的 SecretEnvelope 部分被 remote peer 获取到，否则转 c；
//     c. 如果 remote peer 的组织与 node 自身所属的组织一样，则 EnvelopeFilter 不会对给定的 Envelope 做任何处理。
func (node *Node) disclosurePolicy(remotePeer *utils.NetworkMember) (discovery.Sieve, discovery.EnvelopeFilter) {
	orgOfRemotePeer := node.getOrgOfPeer(remotePeer.PKIid)
	if len(orgOfRemotePeer) == 0 {
		node.logger.Warnf("Unable to determine organization of peer: %s.", remotePeer.String())
		return func(message *utils.SignedGossipMessage) bool {
				return false
			}, func(message *utils.SignedGossipMessage) *pgossip.Envelope {
				return message.Envelope
			}
	}

	return func(message *utils.SignedGossipMessage) bool {
			// 收到的 gossip message 必须是 alive message！
			if message.GetAliveMsg() == nil {
				node.logger.Panicf("Programming panic, this should be used only on alive message, not %s.", message.String())
			}
			org := node.getOrgOfPeer(message.GetAliveMsg().Membership.PkiId)
			if len(org) == 0 {
				node.logger.Warnf("Unable to determine origin organization of message: %s. Don't disseminate messages who's origin org is unknown.", message.String())
				return false
			}
			fromSameForeignOrg := bytes.Equal(orgOfRemotePeer, org)
			fromMyOrg := bytes.Equal(node.selfOrg, org)

			// 如果创造此消息的组织与 remote peer 的组织和我自己的组织都不一样，那么我就不会把这个消息转给 remote peer。
			if !(fromMyOrg || fromSameForeignOrg) {
				return false
			}
			// 如果创造此消息的组织与 remote peer 的组织是同一个组织的话，或者，
			// 创造此消息的组织与 remote peer 的组织不是同一个组织，而这也说明
			// 创造此消息的组织与我自己的组织是同一个组织，那么当此消息的网络地址
			// 和 remote peer 的网络地址如果都公开的话，那么就将此消息转给 remote peer。
			return fromSameForeignOrg || message.GetAliveMsg().Membership.Endpoint != "" && remotePeer.Endpoint != ""
		}, func(message *utils.SignedGossipMessage) *pgossip.Envelope {
			envelope := proto.Clone(message.Envelope).(*pgossip.Envelope)
			if !bytes.Equal(node.selfOrg, orgOfRemotePeer) {
				envelope.SecretEnvelope = nil
			}
			return envelope
		}
}

func (node *Node) peersByOriginalOrPolicy(peer utils.NetworkMember) utils.RoutingFilter {
	orgOfPeer := node.getOrgOfPeer(peer.PKIid)
	if len(orgOfPeer) == 0 {
		node.logger.Warnf("Unable to determine organization of peer: %s.", peer.String())
		return utils.SelectNonePolicy
	}

	if bytes.Equal(node.selfOrg, orgOfPeer) {
		// 与自己属于同一个组织，所以分配给它的权限很大
		return utils.SelectAllPolicy
	}

	return func(nm utils.NetworkMember) bool {
		org := node.getOrgOfPeer(nm.PKIid)
		if len(org) == 0 {
			return false
		}
		isFromMyOrg := bytes.Equal(node.selfOrg, org)
		return isFromMyOrg || bytes.Equal(orgOfPeer, org)
	}
}

func (node *Node) getOrgOfPeer(pkiID utils.PKIidType) utils.OrgIdentityType {
	cert, err := node.idMapper.Get(pkiID)
	if err != nil {
		return nil
	}
	return node.secAdvisor.OrgByPeerIdentity(cert)
}

/* ------------------------------------------------------------------------------------------ */

// partitionMessages 将给定的若干个消息分成两部分，返回的第一部分是满足给定的判断谓词 pred 的，返回的第二部分
// 则是不满足给定的判断谓词 pred 的。
func partitionMessages(pred utils.MessageAcceptor, msgs []*utils.EmittedGossipMessage) ([]*utils.EmittedGossipMessage, []*utils.EmittedGossipMessage) {
	s1 := []*utils.EmittedGossipMessage{}
	s2 := []*utils.EmittedGossipMessage{}

	for _, msg := range msgs {
		if pred(msg) {
			s1 = append(s1, msg)
		} else {
			s2 = append(s2, msg)
		}
	}
	return s1, s2
}

func extractChannels(msgs []*utils.EmittedGossipMessage) []utils.ChannelID {
	channels := make([]utils.ChannelID, 0)
	for _, msg := range msgs {
		if len(msg.Channel) == 0 {
			continue
		}
		samePred := func(a, b any) bool {
			return bytes.Equal(a.(utils.ChannelID), b.(utils.ChannelID))
		}
		if utils.IndexInSlice(channels, msg.Channel, samePred) == -1 {
			channels = append(channels, msg.Channel)
		}
	}
	return channels
}

// selectOnlyDiscoveryMessages 给定一个消息 m，该消息得是 ReceivedMessage，不然此方法恒返回 false，
// 接着判断此消息是否蕴含：alive、memReq、memRes 三种消息中的其中一种，如果蕴含的话，则此方法返回 true，
// 否则返回 false。
func selectOnlyDiscoveryMessages(m any) bool {
	msg, isGossipMsg := m.(utils.ReceivedMessage)
	if !isGossipMsg {
		return false
	}
	alive := msg.GetSignedGossipMessage().GetAliveMsg()
	memReq := msg.GetSignedGossipMessage().GetMemReq()
	memRes := msg.GetSignedGossipMessage().GetMemRes()

	selected := alive != nil || memReq != nil || memRes != nil
	return selected
}
