package pull

import (
	"sync"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/gossip/algo"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
)

type MsgType int

const (
	HelloMsgType MsgType = iota
	DigestMsgType
	RequestMsgType
	ResponseMsgType
)

/* ------------------------------------------------------------------------------------------ */

// MessageHook 会在收到一个特定的 pull 消息时被调用。
type MessageHook func(itemIDs []string, items []*utils.SignedGossipMessage, msg utils.ReceivedMessage)

// IngressDigestFilter 根据条件从远端对等体中筛选出符合规则的摘要。
type IngressDigestFilter func(digestMsg *pgossip.DataDigest) *pgossip.DataDigest

// EgressDigestFilter 过滤要发送给远端对等体的摘要，这里的 ReceivedMessage 内含有消息发送者的信息，那么可以根
// 据这个发送者的消息过滤掉不想发送的 digest 消息。
type EgressDigestFilter func(helloMsg utils.ReceivedMessage) func(digestItem string) bool

// byContext 根据给定的上下文信息，获取一个针对某个 digest 的过滤器，然后调用 EgressDigestFilter 过滤 digest。
func (edf EgressDigestFilter) byContext() algo.DigestFilter {
	return func(context any) func(digestItem string) bool {
		return func(digestItem string) bool {
			return edf(context.(utils.ReceivedMessage))(digestItem)
		}
	}
}

// MsgConsumer 用于处理 pulledMsg 中的每个区块数据。
type MsgConsumer func(message *utils.SignedGossipMessage)

// IdentitfierExtractor 从 SignedGossipMessage 中提取出标识符。
type IdentitfierExtractor func(*utils.SignedGossipMessage) string

/* ------------------------------------------------------------------------------------------ */

type Sender interface {
	Send(msg *utils.SignedGossipMessage, peers ...*utils.RemotePeer)
}

/* ------------------------------------------------------------------------------------------ */

// MembershipService 服务从其他活跃节点处获取网络节点成员信息。
type MembershipService interface {
	GetMembership() utils.Members
}

/* ------------------------------------------------------------------------------------------ */

type PullConfig struct {
	PullInterval      time.Duration
	Channel           utils.ChannelID
	PeerCountToSelect int // 初始化时向这么多个节点发送 pull 消息。
	Tag               pgossip.GossipMessage_Tag
	MsgType           pgossip.PullMsgType
	PullEngineConfig  algo.Config
}

/* ------------------------------------------------------------------------------------------ */

type PullAdapter struct {
	Sender            Sender
	MembershipService MembershipService
	// IdentitfierExtractor 从 SignedGossipMessage 中提取出标识符。
	IdentitfierExtractor IdentitfierExtractor
	MsgConsumer          MsgConsumer
	// EgressDigestFilter 过滤要发送给远端对等体的摘要。
	EgressDigestFilter EgressDigestFilter
	// IngressDigestFilter 根据条件从远端对等体中筛选出符合规则的摘要。
	IngressDigestFilter IngressDigestFilter
}

/* ------------------------------------------------------------------------------------------ */

type PullMediator interface {
	Stop()

	RegisterMsgHook(MsgType, MessageHook)

	Add(*utils.SignedGossipMessage)

	Remove(digest string)

	HandleMessage(msg utils.ReceivedMessage)
}

type pullMediator struct {
	mutex *sync.RWMutex
	*PullAdapter
	msgType2Hooks map[MsgType][]MessageHook
	config        PullConfig
	logger        mlog.Logger
	itemID2Msg    map[string]*utils.SignedGossipMessage
	engine        algo.PullEngine
}

func NewPullMediator(config PullConfig, adapter *PullAdapter, logger mlog.Logger) PullMediator {
	egressDigFilter := adapter.EgressDigestFilter
	acceptAllFilter := func(utils.ReceivedMessage) func(string) bool {
		return func(string) bool {
			return true
		}
	}
	if egressDigFilter == nil {
		egressDigFilter = acceptAllFilter
	}

	pm := &pullMediator{
		PullAdapter:   adapter,
		msgType2Hooks: make(map[MsgType][]MessageHook),
		config:        config,
		logger:        logger,
		itemID2Msg:    make(map[string]*utils.SignedGossipMessage),
		mutex:         &sync.RWMutex{},
	}

	pm.engine = algo.NewPullEngineWithFilter(pm, config.PullInterval, egressDigFilter.byContext(), config.PullEngineConfig, logger)

	if adapter.IngressDigestFilter == nil {
		adapter.IngressDigestFilter = func(digestMsg *pgossip.DataDigest) *pgossip.DataDigest {
			return digestMsg
		}
	}

	return pm
}

func (pm *pullMediator) HandleMessage(msg utils.ReceivedMessage) {
	if msg.GetSignedGossipMessage() == nil || !utils.IsPullMsg(msg.GetSignedGossipMessage().GossipMessage) {
		return
	}
	sgm := msg.GetSignedGossipMessage()
	msgType := utils.GetPullMsgType(sgm.GossipMessage)
	if msgType != pm.config.MsgType {
		return
	}

	itemIDs := []string{}
	items := []*utils.SignedGossipMessage{}
	var pullMsgType MsgType

	if helloMsg := sgm.GetHello(); helloMsg != nil {
		pullMsgType = HelloMsgType
		pm.engine.OnHello(helloMsg.Nonce, msg)
	} else if dataDig := sgm.GetDataDig(); dataDig != nil {
		filteredDigest := pm.IngressDigestFilter(dataDig)
		itemIDs = utils.BytesToStrings(filteredDigest.Digests)
		pullMsgType = DigestMsgType
		pm.engine.OnDigests(itemIDs, filteredDigest.Nonce, msg)
	} else if dataReq := sgm.GetDataReq(); dataReq != nil {
		itemIDs = utils.BytesToStrings(dataReq.Digests)
		pullMsgType = RequestMsgType
		pm.engine.OnReq(itemIDs, dataReq.Nonce, msg)
	} else if dataUpdate := sgm.GetDataUpdate(); dataUpdate != nil {
		itemIDs = make([]string, len(dataUpdate.Data))
		items = make([]*utils.SignedGossipMessage, len(dataUpdate.Data))
		pullMsgType = ResponseMsgType
		for i, pulledMsg := range dataUpdate.Data {
			m, err := utils.EnvelopeToSignedGossipMessage(pulledMsg)
			if err != nil {
				pm.logger.Errorf("Data update contains an invalid message: %s.", err.Error())
				return
			}
			pm.MsgConsumer(m)
			itemIDs[i] = pm.IdentitfierExtractor(m)
			items[i] = m
			pm.mutex.Lock()
			pm.itemID2Msg[itemIDs[i]] = m
			pm.logger.Debugf("Add %s to the memory item map, total items: %d.", itemIDs[i], len(pm.itemID2Msg))
			pm.mutex.Unlock()
		}
		pm.engine.OnRes(itemIDs, dataUpdate.Nonce)
	}

	for _, hook := range pm.hooksByMsgType(pullMsgType) {
		hook(itemIDs, items, msg)
	}
}

func (pm *pullMediator) RegisterMsgHook(pullMsgType MsgType, hook MessageHook) {
	pm.mutex.Lock()
	pm.msgType2Hooks[pullMsgType] = append(pm.msgType2Hooks[pullMsgType], hook)
	pm.mutex.Unlock()
}

func (pm *pullMediator) Add(msg *utils.SignedGossipMessage) {
	pm.mutex.Lock()
	itemID := pm.IdentitfierExtractor(msg)
	pm.itemID2Msg[itemID] = msg
	pm.engine.Add(itemID)
	pm.logger.Debugf("Add item %s, total items: %d.", itemID, len(pm.itemID2Msg))
	pm.mutex.Unlock()
}

func (pm *pullMediator) Remove(digest string) {
	pm.mutex.Lock()
	delete(pm.itemID2Msg, digest)
	pm.engine.Remove(digest)
	pm.logger.Debugf("Remove item %s, total items: %d.", digest, len(pm.itemID2Msg))
	pm.mutex.Unlock()
}

func (pm *pullMediator) Stop() {
	pm.engine.Stop()
}

func (pm *pullMediator) Hello(endpoint string, nonce uint64) {
	helloMsg := &pgossip.GossipMessage{
		Channel: pm.config.Channel,
		Tag:     pm.config.Tag,
		Content: &pgossip.GossipMessage_Hello{
			Hello: &pgossip.GossipHello{
				Nonce:    nonce,
				Metadata: nil,
				MsgType:  pm.config.MsgType,
			},
		},
	}
	sgm, err := utils.NoopSign(helloMsg)
	if err != nil {
		pm.logger.Errorf("Failed creating signed Hello message: %s.", err.Error())
		return
	}
	var object = endpoint
	if len(endpoint) == 0 {
		object = "unknown peer"
	}
	pm.logger.Debugf("Send %s hello message with nonce %d to %s.", pm.config.MsgType, nonce, object)
	pm.Sender.Send(sgm, pm.peersWithEndpoints(endpoint)...)
}

func (pm *pullMediator) SendDigest(digest []string, nonce uint64, context any) {
	digestMsg := &pgossip.GossipMessage{
		Channel: pm.config.Channel,
		Tag:     pm.config.Tag,
		Content: &pgossip.GossipMessage_DataDig{
			DataDig: &pgossip.DataDigest{
				MsgType: pm.config.MsgType,
				Nonce:   nonce,
				Digests: utils.StringsToBytes(digest),
			},
		},
	}

	remotePeer := context.(utils.ReceivedMessage).GetConnectionInfo()
	pm.logger.Debugf("Send %s digest message %s to %s@%s.", pm.config.MsgType, utils.DataDigestToString(digestMsg.GetDataDig()), remotePeer.PkiID, remotePeer.Endpoint)
	context.(utils.ReceivedMessage).Respond(digestMsg)
}

func (pm *pullMediator) SendReq(endpoint string, items []string, nonce uint64) {
	reqMsg := &pgossip.GossipMessage{
		Channel: pm.config.Channel,
		Tag:     pm.config.Tag,
		Content: &pgossip.GossipMessage_DataReq{
			DataReq: &pgossip.DataRequest{
				MsgType: pm.config.MsgType,
				Nonce:   nonce,
				Digests: utils.StringsToBytes(items),
			},
		},
	}
	sgm, err := utils.NoopSign(reqMsg)
	if err != nil {
		pm.logger.Errorf("Failed creating signed Data Request message: %s.", err.Error())
		return
	}
	if len(pm.peersWithEndpoints(endpoint)) == 0 {
		pm.logger.Debug("No peer to send Request message.")
		return
	}
	remotePeer := pm.peersWithEndpoints(endpoint)[0]
	pm.logger.Debugf("Send %s request %s to %s@%s.", pm.config.MsgType, utils.DataRequestToString(reqMsg.GetDataReq()), remotePeer.PKIID.String(), remotePeer.Endpoint)
	pm.Sender.Send(sgm, remotePeer)
}

func (pm *pullMediator) SendRes(items []string, nonce uint64, context any) {
	items2Send := []*pgossip.Envelope{}
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	for _, item := range items {
		if msg, exists := pm.itemID2Msg[item]; exists {
			items2Send = append(items2Send, msg.Envelope)
		}
	}
	dataUpdate := &pgossip.GossipMessage{
		Channel: pm.config.Channel,
		Tag:     pm.config.Tag,
		Content: &pgossip.GossipMessage_DataUpdate{
			DataUpdate: &pgossip.DataUpdate{
				MsgType: pm.config.MsgType,
				Nonce:   nonce,
				Data:    items2Send,
			},
		},
	}
	remotePeer := context.(utils.ReceivedMessage).GetConnectionInfo()
	pm.logger.Debugf("Send %s response message %s to %s@%s.", pm.config.MsgType, utils.DataUpdateToString(dataUpdate.GetDataUpdate()), remotePeer.PkiID.String(), remotePeer.Endpoint)
	context.(utils.ReceivedMessage).Respond(dataUpdate)
}

func (pm *pullMediator) peersWithEndpoints(endpoints ...string) []*utils.RemotePeer {
	peers := []*utils.RemotePeer{}
	for _, member := range pm.MembershipService.GetMembership() {
		for _, endpoint := range endpoints {
			if member.PreferredEndpoint() == endpoint {
				peers = append(peers, &utils.RemotePeer{PKIID: member.PKIid, Endpoint: endpoint})
			}
		}
	}
	return peers
}

func (pm *pullMediator) SelectPeers() []string {
	remotePeers := SelectEndpoints(pm.config.PeerCountToSelect, pm.MembershipService.GetMembership())
	endpoints := make([]string, len(remotePeers))
	for i, peer := range remotePeers {
		endpoints[i] = peer.Endpoint
	}
	return endpoints
}

func (pm *pullMediator) hooksByMsgType(msgType MsgType) []MessageHook {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.msgType2Hooks[msgType]
}

func SelectEndpoints(k int, peerPool []utils.NetworkMember) []*utils.RemotePeer {
	if len(peerPool) < k {
		k = len(peerPool)
	}

	indices := utils.GetRandomIndices(k, len(peerPool)-1)
	endpoints := make([]*utils.RemotePeer, len(indices))
	for i, index := range indices {
		endpoints[i] = &utils.RemotePeer{Endpoint: peerPool[index].PreferredEndpoint(), PKIID: peerPool[index].PKIid}
	}
	return endpoints
}
