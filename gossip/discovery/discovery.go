package discovery

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/gossip/comm"
	"github.com/11090815/mayy/gossip/gossip/msgstore"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultAliveTimeInterval            = 5 * time.Second
	DefaultAliveExpirationTimeout       = 25 * time.Second
	DefaultMsgExpirationFactor          = 20
	DefaultAliveExpirationCheckInterval = DefaultAliveExpirationTimeout / 10
	DefaultReconnectInterval            = 25 * time.Second
	DefaultMaxConnectAttempts           = 120
)

// EnvelopeFilter 会过滤掉 SignedGossipMessage 中的部分信息得到一个 Envelope。
type EnvelopeFilter func(message *utils.SignedGossipMessage) *pgossip.Envelope

// Sieve 决定了是否能将 SignedGossipMessage 发送给远程节点。
type Sieve func(message *utils.SignedGossipMessage) bool

// DisclosurePolicy 定义了给定的远程对等体是否有资格了解消息，以及从给定的 SignedGossipMessage 中有资格了解哪些消息。
type DisclosurePolicy func(remotePeer *utils.NetworkMember) (Sieve, EnvelopeFilter)

type identifier func() (*PeerIdentification, error)

/* ------------------------------------------------------------------------------------------ */

type PeerIdentification struct {
	PKIid   utils.PKIidType
	SelfOrg bool // 用于表示是否与自己同属于同一组织
}

/* ------------------------------------------------------------------------------------------ */

// AnchorPeerTracker 给定一个节点的 endpoint，判断该节点是否是锚点。
type AnchorPeerTracker interface {
	IsAnchorPeer(endpoint string) bool
	Update(channelName string, endpoints map[string]struct{})
}

type anchorPeerTracker struct {
	// allEndpoints 包含所有通道的所有锚点，channel-name => anchor peers。
	allEndpoints map[string]map[string]struct{}
	mutex        *sync.RWMutex
}

func (apt *anchorPeerTracker) IsAnchorPeer(endpoint string) bool {
	apt.mutex.RLock()
	defer apt.mutex.RUnlock()
	for _, endpointsForChannel := range apt.allEndpoints {
		if _, exists := endpointsForChannel[endpoint]; exists {
			return true
		}
	}
	return false
}

func (apt *anchorPeerTracker) Update(channelName string, endpoints map[string]struct{}) {
	apt.mutex.Lock()
	apt.allEndpoints[channelName] = endpoints
	apt.mutex.Unlock()
}

/* ------------------------------------------------------------------------------------------ */

type DiscoveryAdapter interface {
	// Gossip 广播。
	Gossip(msg *utils.SignedGossipMessage)

	// SendToPeer 单播。
	SendToPeer(peer *utils.NetworkMember, msg *utils.SignedGossipMessage)

	Ping(peer *utils.NetworkMember) bool

	Accept() <-chan utils.ReceivedMessage

	// ReceiveDiscoveryMessage 接收与 discovery 相关的消息。
	ReceiveDiscoveryMessage(msg utils.ReceivedMessage)

	PresumedDead() <-chan utils.PKIidType

	CloseConn(peer *utils.NetworkMember)

	// Forward 将消息转发给下一跳。
	Forward(msg utils.ReceivedMessage)

	// IdentitySwitch 返回一个通道，此通道内存放证书发生变化的节点的 ID。
	IdentitySwitch() <-chan utils.PKIidType

	Stop()
}

/* ------------------------------------------------------------------------------------------ */

type discoveryAdapter struct {
	c                comm.Comm
	presumedDead     chan utils.PKIidType
	incChan          chan utils.ReceivedMessage
	gossipFunc       func(msg *utils.SignedGossipMessage)
	forwardFunc      func(msg utils.ReceivedMessage)
	disclosurePolicy DisclosurePolicy
	stopping         int32
	stopOnce         sync.Once
}

func NewDiscoveryAdapter(c comm.Comm, propagateTimes int, emitter utils.BatchingEmitter, presumedDead chan utils.PKIidType, disclosurePolicy DisclosurePolicy) DiscoveryAdapter {
	adapter := &discoveryAdapter{
		c:            c,
		presumedDead: presumedDead,
		incChan:      make(chan utils.ReceivedMessage),
		gossipFunc: func(msg *utils.SignedGossipMessage) {
			if propagateTimes == 0 {
				return
			}
			emitter.Add(utils.NewEmittedGossipMessage(msg, func(pt utils.PKIidType) bool { return true }))
		},
		forwardFunc: func(msg utils.ReceivedMessage) {
			if propagateTimes == 0 {
				return
			}
			emitter.Add(utils.NewEmittedGossipMessage(msg.GetSignedGossipMessage(), msg.GetConnectionInfo().PkiID.IsNotSameFilter))
		},
		disclosurePolicy: disclosurePolicy,
		stopping:         int32(0),
	}

	return adapter
}

func (da *discoveryAdapter) Gossip(msg *utils.SignedGossipMessage) {
	if da.closed() {
		return
	}
	da.gossipFunc(msg)
}

func (da *discoveryAdapter) SendToPeer(peer *utils.NetworkMember, msg *utils.SignedGossipMessage) {
	if da.closed() {
		return
	}

	if memReq := msg.GetMemReq(); memReq != nil && len(peer.PKIid) != 0 {
		selfMsg, err := utils.EnvelopeToSignedGossipMessage(memReq.SelfInformation)
		if err != nil {
			panic(fmt.Sprintf("Tried to send a membership request with a malformed AliveMessage, error: %s.", err.Error()))
		}
		_, omitConcealedFields := da.disclosurePolicy(peer)
		selfMsg.Envelope = omitConcealedFields(selfMsg) // 处理一下，让我的部分信息不让别人知道
		memReq = &pgossip.MembershipRequest{
			SelfInformation: selfMsg.Envelope,
		}
		msgClone := proto.Clone(msg.GossipMessage).(*pgossip.GossipMessage)
		msgClone.Content = &pgossip.GossipMessage_MemReq{
			MemReq: memReq,
		}
		if msg, err = utils.NoopSign(msgClone); err != nil {
			return
		}
		da.c.Send(msg, &utils.RemotePeer{PKIID: peer.PKIid, Endpoint: peer.PreferredEndpoint()})
		return
	}
	da.c.Send(msg, &utils.RemotePeer{PKIID: peer.PKIid, Endpoint: peer.PreferredEndpoint()})
}

func (da *discoveryAdapter) Ping(peer *utils.NetworkMember) bool {
	if da.closed() {
		return false
	}
	return da.c.Probe(&utils.RemotePeer{PKIID: peer.PKIid, Endpoint: peer.PreferredEndpoint()}) == nil
}

func (da *discoveryAdapter) Accept() <-chan utils.ReceivedMessage {
	return da.incChan
}

func (da *discoveryAdapter) ReceiveDiscoveryMessage(msg utils.ReceivedMessage) {
	da.incChan <- msg
}

func (da *discoveryAdapter) PresumedDead() <-chan utils.PKIidType {
	return da.presumedDead
}

func (da *discoveryAdapter) CloseConn(peer *utils.NetworkMember) {
	da.c.CloseConn(&utils.RemotePeer{PKIID: peer.PKIid, Endpoint: peer.PreferredEndpoint()})
}

func (da *discoveryAdapter) Forward(msg utils.ReceivedMessage) {
	if da.closed() {
		return
	}
	da.forwardFunc(msg)
}

func (da *discoveryAdapter) IdentitySwitch() <-chan utils.PKIidType {
	return da.c.IdentitySwitch()
}

func (da *discoveryAdapter) Stop() {
	da.stopOnce.Do(func() {
		atomic.StoreInt32(&da.stopping, 1)
		close(da.incChan)
	})
}

func (da *discoveryAdapter) closed() bool {
	return atomic.LoadInt32(&da.stopping) == 1
}

/* ------------------------------------------------------------------------------------------ */

type Discovery interface {
	// Lookup 根据节点 ID 寻找节点。
	Lookup(pkiID utils.PKIidType) *utils.NetworkMember

	// Self 返回此实例的信息。
	Self() utils.NetworkMember

	// UpdateMetadata 更新此实例的元数据信息。
	UpdateMetadata([]byte)

	// UpdateEndpoint 更新此实例的 endpoint。
	UpdateEndpoint(string)

	// GetMembership 返回所有成员信息。
	GetMembership() utils.Members

	// InitiateSync 向 peerNum 个节点询问它们所掌握的成员信息，将这些信息同步过来。
	InitiateSync(peerNum int)

	// Connect 与节点建立连接，建立连接的方式就是给对方发送一个 membership request，如果发送不了，那就及时建立一个与对方的连接。
	Connect(member utils.NetworkMember, identifier identifier)

	Stop()
}

type gossipDiscoveryImpl struct {
	self         utils.NetworkMember
	selfAliveMsg *utils.SignedGossipMessage
	port         int
	incTime      uint64
	seqNum       uint64

	bootstrapPeers    []string
	anchorPeerTracker AnchorPeerTracker

	crypt   DiscoverySecurityAdapter
	adapter DiscoveryAdapter
	pubsub  *utils.PubSub

	logger mlog.Logger
	mutex  *sync.RWMutex

	aliveMembership *utils.MembershipStore
	// aliveLastTS：PKIid => *timestamp，当在 aliveExpirationTimeout 时间内没收到 peer 节点的 alive 消息时，会将 aliveLastTS 里的
	// peer 节点时间戳信息移入到 deadLastTS 里。
	aliveLastTS    map[string]*timestamp
	deadMembership *utils.MembershipStore
	deadLastTS     map[string]*timestamp // PKIid => *timestamp
	// id2Member：PKIid => *NetworkMember，存储了所有的 peer 节点的信息，无论此 peer 节点的状态是 dead 还是 alive，都会一直被存储在这里。
	id2Member map[string]*utils.NetworkMember
	msgStore  *aliveMsgStore

	// aliveTimeInterval 每隔这段时间，广播一次自己的 alive 消息
	aliveTimeInterval time.Duration
	// aliveExpirationTimeout 仅仅 aliveExpirationTimeout 的作用是：超过这么长时间没有收到某个 peer 节点的 alive 消息的话，
	// 就会断开与此节点之间建立的连接，aliveExpirationTimeout x aliveMsgExpirationFactor 是 alive 消息的过期时间，alive 消
	// 息的过期时间一到，就会将存储在 msgStore 里的过期 alive 消息删除掉。
	aliveExpirationTimeout       time.Duration
	aliveMsgExpirationFactor     int
	aliveExpirationCheckInterval time.Duration
	reconnectInterval            time.Duration

	// disclosurePolicy 根据 peer 节点的信息，决定是否给该 peer 节点发送 MembershipResponse 消息，以及即便应该发送 response 消息，
	// 也会决定要发送哪些 Membership 信息。
	disclosurePolicy DisclosurePolicy

	maxConnectAttempts int

	stopChan chan struct{}
}

type aliveMsgStore struct {
	msgstore.MessageStore
}

func newAliveMsgStore(d *gossipDiscoveryImpl) *aliveMsgStore {
	policy := utils.NewGossipMessageComparator(0)
	aliveMsgTTL := d.aliveExpirationTimeout * time.Duration(d.aliveMsgExpirationFactor)
	externalLock := func() { d.mutex.Lock() }
	externalUnlock := func() { d.mutex.Unlock() }

	callback := func(m any) {
		msg := m.(*utils.SignedGossipMessage)
		if msg.GetAliveMsg() == nil {
			return
		}
		membership := msg.GetAliveMsg().Membership
		id := utils.PKIidType(membership.PkiId)
		endpoint := membership.Endpoint
		internalEndpoint := utils.InternalEndpoint(msg.SecretEnvelope)
		if utils.Contains(internalEndpoint, d.bootstrapPeers) || d.anchorPeerTracker.IsAnchorPeer(internalEndpoint) ||
			utils.Contains(endpoint, d.bootstrapPeers) || d.anchorPeerTracker.IsAnchorPeer(endpoint) {
			d.logger.Warnf("Do not remove bootstrap or anchor peer endpoint %s from membership.", endpoint)
			return
		}
		d.logger.Infof("Remove member %s from membership.", utils.MemberToString(membership))
		d.remove(id)
	}

	s := &aliveMsgStore{
		MessageStore: msgstore.NewMessageStoreExpirable(policy, msgstore.NoopTrigger, aliveMsgTTL, externalLock, externalUnlock, callback),
	}

	return s
}

func (ams *aliveMsgStore) Add(msg any) bool {
	m := msg.(*utils.SignedGossipMessage)
	if m.GetAliveMsg() != nil {
		return ams.MessageStore.Add(msg)
	} else {
		panic(fmt.Sprintf("expected AliveMessage, but got %T", m.GossipMessage))
	}
}

func (ams *aliveMsgStore) CheckValid(msg any) bool {
	m := msg.(*utils.SignedGossipMessage)
	if m.GetAliveMsg() != nil {
		return ams.MessageStore.CheckValid(msg)
	} else {
		panic(fmt.Sprintf("expected AliveMessage, but got %T", m.GossipMessage))
	}
}

type timestamp struct {
	incTime  time.Time
	seqNum   uint64
	lastSeen time.Time
}

func (ts *timestamp) String() string {
	var incTime = "<nil>"
	var lastSeen = "<nil>"
	if !ts.incTime.IsZero() {
		incTime = ts.incTime.Format(time.RFC3339Nano)
	}
	if !ts.lastSeen.IsZero() {
		lastSeen = ts.lastSeen.Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("{timestamp | incTime: %s; seqNum: %d; lastSeen: %s}", incTime, ts.seqNum, lastSeen)
}

type Config struct {
	AliveTimeInterval            time.Duration
	AliveExpirationTimeout       time.Duration
	AliveExpirationCheckInterval time.Duration
	ReconnectInterval            time.Duration
	MaxConnectionAttempts        int
	// MsgExpirationFactor 定义了一个乘法因子，用来调节 alive 消息的过期时间。
	MsgExpirationFactor int
	// BootstrapPeers 在启动时需要连接到的 peer 节点。
	BootstrapPeers []string
}

func NewDiscoveryService(self utils.NetworkMember, adapter DiscoveryAdapter, crypt DiscoverySecurityAdapter, policy DisclosurePolicy,
	config Config, anchorPeerTracker AnchorPeerTracker, logger mlog.Logger) Discovery {
	gdi := &gossipDiscoveryImpl{
		self:                         self,
		incTime:                      uint64(time.Now().UnixNano()),
		seqNum:                       uint64(0),
		aliveLastTS:                  make(map[string]*timestamp),
		deadLastTS:                   make(map[string]*timestamp),
		id2Member:                    make(map[string]*utils.NetworkMember),
		aliveMembership:              utils.NewMembershipStore(),
		deadMembership:               utils.NewMembershipStore(),
		anchorPeerTracker:            anchorPeerTracker,
		adapter:                      adapter,
		crypt:                        crypt,
		mutex:                        &sync.RWMutex{},
		disclosurePolicy:             policy,
		logger:                       logger,
		stopChan:                     make(chan struct{}),
		pubsub:                       utils.NewPubSub(),
		aliveTimeInterval:            config.AliveTimeInterval,
		aliveExpirationTimeout:       config.AliveExpirationTimeout,
		aliveMsgExpirationFactor:     config.MsgExpirationFactor,
		reconnectInterval:            config.ReconnectInterval,
		aliveExpirationCheckInterval: config.AliveExpirationCheckInterval,
		bootstrapPeers:               config.BootstrapPeers,
		maxConnectAttempts:           config.MaxConnectionAttempts,
	}

	gdi.validateSelfConfig()
	gdi.msgStore = newAliveMsgStore(gdi)

	go gdi.periodicalCheckAlive()
	go gdi.periodicalReconnectToDead()
	go gdi.periodicalSendAlive()
	go gdi.handleEvents()
	go gdi.handleMessages()

	return gdi
}

func (gdi *gossipDiscoveryImpl) Lookup(pkiID utils.PKIidType) *utils.NetworkMember {
	if gdi.closed() {
		gdi.logger.Warn("Discovery service is already closed.")
		return nil
	}
	gdi.mutex.RLock()
	defer gdi.mutex.RUnlock()
	if bytes.Equal(pkiID, gdi.self.PKIid) {
		clone := gdi.self.Clone()
		return &clone
	}
	if nm, exists := gdi.id2Member[pkiID.String()]; exists {
		clone := nm.Clone()
		return &clone
	} else {
		return nil
	}
}

func (gdi *gossipDiscoveryImpl) Self() utils.NetworkMember {
	if gdi.closed() {
		gdi.logger.Warn("Discovery service is already closed.")
		return utils.NetworkMember{}
	}
	aliveMsg, _ := gdi.aliveMsgAndInternalEndpoint()
	envelope, _ := utils.NoopSign(aliveMsg)
	clone := gdi.self.Clone()
	clone.Envelope = envelope.Envelope
	return clone
}

func (gdi *gossipDiscoveryImpl) UpdateMetadata(metadata []byte) {
	if gdi.closed() {
		gdi.logger.Warn("Discovery service is already closed.")
		return
	}
	gdi.mutex.Lock()
	defer gdi.mutex.Unlock()
	gdi.self.Metadata = metadata
}

func (gdi *gossipDiscoveryImpl) UpdateEndpoint(endpoint string) {
	if gdi.closed() {
		gdi.logger.Warn("Discovery service is already closed.")
		return
	}
	gdi.mutex.Lock()
	gdi.self.Endpoint = endpoint
	gdi.mutex.Unlock()
}

func (gdi *gossipDiscoveryImpl) GetMembership() utils.Members {
	if gdi.closed() {
		gdi.logger.Warn("Discovery service is already closed.")
		return []utils.NetworkMember{}
	}
	gdi.mutex.RLock()
	defer gdi.mutex.RUnlock()
	var aliveMembers utils.Members
	for pkiID := range gdi.aliveLastTS {
		aliveMembers = append(aliveMembers, gdi.id2Member[pkiID].Clone())
	}
	return aliveMembers
}

// InitiateSync 主动给别人发送 MembershipRequest，然后根据别人反馈的 MembershipResponse 同步成员信息。
func (gdi *gossipDiscoveryImpl) InitiateSync(peerNum int) {
	if gdi.closed() {
		gdi.logger.Warn("Discovery service is already closed.")
		return
	}

	var peers2Send []*utils.NetworkMember

	gdi.mutex.RLock()
	n := gdi.aliveMembership.Size()
	t := peerNum
	if t > n {
		t = n
	}
	aliveMembersAsSlice := gdi.aliveMembership.ToSlice()
	for _, i := range utils.GetRandomIndices(t, n-1) { // 随机从自己 n 个邻居中挑 t 个，然后向他们发送 membership request。
		pulledPeer := aliveMembersAsSlice[i].GetAliveMsg().Membership
		var internalEndpoint string
		if aliveMembersAsSlice[i].Envelope.SecretEnvelope != nil {
			// 如果知道该节点的 internal endpoint，则优先向此地址发送 membership request。
			internalEndpoint = utils.InternalEndpoint(aliveMembersAsSlice[i].SecretEnvelope)
		}
		peers2Send = append(peers2Send, &utils.NetworkMember{
			Endpoint:         pulledPeer.Endpoint,
			InternalEndpoint: internalEndpoint,
			Metadata:         pulledPeer.Metadata,
			PKIid:            pulledPeer.PkiId,
		})
	}
	gdi.mutex.RUnlock()

	if len(peers2Send) == 0 {
		gdi.logger.Info("No peers to send, aborting membership sync.")
		return
	}

	req, err := gdi.createMembershipRequest(true)
	if err != nil {
		gdi.logger.Errorf("Failed creating membership request, error: %s.", err.Error())
		return
	}
	signedReq, err := utils.NoopSign(req)
	if err != nil {
		gdi.logger.Errorf("Failed creating SignedGossipMessage, error: %s.", err.Error())
		return
	}

	for _, mem := range peers2Send {
		gdi.adapter.SendToPeer(mem, signedReq)
	}
}

func (gdi *gossipDiscoveryImpl) Connect(member utils.NetworkMember, identifier identifier) {
	for _, endpoint := range []string{member.Endpoint, member.InternalEndpoint} {
		if gdi.isMyOwnEndpoint(endpoint) {
			return
		}
	}
	go func() {
		for i := 0; i < gdi.maxConnectAttempts && !gdi.closed(); i++ {
			id, err := identifier() // 这个地方会尝试与 member 进行握手，获取 member 的证书等身份信息
			if err != nil {
				if gdi.closed() {
					return
				}
				gdi.logger.Errorf("Couldn't fetch identity information for member %s, error: %s.", member.String(), err.Error())
				time.Sleep(gdi.reconnectInterval)
				continue
			}
			peer := &utils.NetworkMember{
				InternalEndpoint: member.InternalEndpoint,
				Endpoint:         member.Endpoint,
				PKIid:            id.PKIid,
			}
			req, err := gdi.createMembershipRequest(id.SelfOrg)
			if err != nil {
				gdi.logger.Errorf("Failed creating membership request, error: %s.", err.Error())
				continue
			}
			req.Nonce = utils.RandomUint64()
			signedReq, err := utils.NoopSign(req)
			if err != nil {
				gdi.logger.Errorf("Failed creating SignedGossipMessage, error: %s.", err.Error())
				continue
			}
			go gdi.sendUntilAcked(peer, signedReq)
			return
		}
	}()
}

func (gdi *gossipDiscoveryImpl) Stop() {
	select {
	case <-gdi.stopChan:
	default:
		close(gdi.stopChan)
		gdi.msgStore.Stop()
		gdi.logger.Info("Stop discovery service.")
	}
}

func (gdi *gossipDiscoveryImpl) validateSelfConfig() {
	if len(gdi.self.InternalEndpoint) == 0 {
		gdi.logger.Panic("Self internal endpoint is empty.")
	}
	internalEndpointSplit := strings.Split(gdi.self.InternalEndpoint, ":")
	if len(internalEndpointSplit) != 2 {
		gdi.logger.Panicf("Self internal endpoint %s isn't formatted as 'host:port'.", gdi.self.InternalEndpoint)
	}
	port, err := strconv.ParseInt(internalEndpointSplit[1], 10, 64)
	if err != nil {
		gdi.logger.Panicf("Self internal endpoint %s has an invalid port.", gdi.self.InternalEndpoint)
	}
	if port > int64(math.MaxUint16) {
		gdi.logger.Panicf("The port of the self internal endpoint %s takes more than 16 bits.", gdi.self.InternalEndpoint)
	}
	gdi.port = int(port)
}

func (gdi *gossipDiscoveryImpl) periodicalReconnectToDead() {
	for !gdi.closed() {
		wg := &sync.WaitGroup{}

		for _, member := range gdi.copyLastSeen(gdi.deadLastTS) {
			wg.Add(1)
			go func(nm utils.NetworkMember) {
				defer wg.Done()
				if gdi.adapter.Ping(&nm) {
					gdi.logger.Debugf("Member %s is responding, we can send membership request to it.", nm.SimpleString())
					gdi.sendMembershipRequestWithoutAck(&nm, true)
				} else {
					gdi.logger.Debugf("Member %s is still dead.", nm.SimpleString())
				}
			}(member)
		}

		wg.Wait()
		time.Sleep(gdi.reconnectInterval)
	}
}

func (gdi *gossipDiscoveryImpl) periodicalCheckAlive() {
	for !gdi.closed() {
		time.Sleep(gdi.aliveExpirationCheckInterval)
		dead := gdi.getDeadMembers()
		if len(dead) > 0 {
			gdi.logger.Debugf("There are %d dead member(s) in this view.", len(dead))
			gdi.expireDeadMembers(dead)
		}
	}
}

func (gdi *gossipDiscoveryImpl) periodicalSendAlive() {
	for !gdi.closed() {
		time.Sleep(gdi.aliveTimeInterval)
		if gdi.aliveMembership.Size() == 0 {
			gdi.logger.Debug("Empty membership, no one to send a heartbeat to.")
			continue
		}
		msg, err := gdi.createSignedAliveMessage(true)
		if err != nil {
			gdi.logger.Errorf("Failed creating alive message, error: %s.", err.Error())
			return
		}
		gdi.mutex.Lock()
		gdi.selfAliveMsg = msg
		gdi.mutex.Unlock()
		gdi.adapter.Gossip(msg)
	}
}

func (gdi *gossipDiscoveryImpl) handleEvents() {
	for {
		select {
		case deadPeer := <-gdi.adapter.PresumedDead():
			if gdi.isAlive(deadPeer) {
				gdi.expireDeadMembers([]utils.PKIidType{deadPeer})
			}
		case changedID := <-gdi.adapter.IdentitySwitch():
			gdi.logger.Infof("Peer's PKI-ID is changed, so, remove %s from membership.", changedID.String())
			gdi.remove(changedID)
		case <-gdi.stopChan:
			return
		}
	}
}

func (gdi *gossipDiscoveryImpl) handleMessages() {
	for {
		select {
		case m := <-gdi.adapter.Accept():
			gdi.handleMsgFromComm(m)
		case <-gdi.stopChan:
			return
		}
	}
}

func (gdi *gossipDiscoveryImpl) handleMsgFromComm(msg utils.ReceivedMessage) {
	if msg == nil {
		return
	}

	sgm := msg.GetSignedGossipMessage()
	if sgm.GetAliveMsg() == nil && sgm.GetMemReq() == nil && sgm.GetMemRes() == nil {
		gdi.logger.Warnf("Discovery service only accepts AliveMessage or MembershipRequest or MembershipResponse message, but got: %s.", sgm.String())
		return
	}

	if req := sgm.GetMemReq(); req != nil {
		selfInfo, err := utils.EnvelopeToSignedGossipMessage(req.SelfInformation)
		if err != nil {
			gdi.logger.Errorf("Failed deserializing GossipMessage from Envelope, error: %s.", err.Error())
			return
		}

		if !gdi.crypt.ValidateAliveMsg(selfInfo) {
			return
		}

		if gdi.msgStore.CheckValid(selfInfo) {
			gdi.handleAliveMsg(selfInfo)
		}

		var internalEndpoint string
		if req.SelfInformation.SecretEnvelope != nil {
			internalEndpoint = utils.InternalEndpoint(req.SelfInformation.SecretEnvelope)
		}

		go gdi.sendMembershipResponse(selfInfo.GetAliveMsg().Membership, internalEndpoint, sgm.Nonce)
	}

	if resp := sgm.GetMemRes(); resp != nil {
		gdi.pubsub.Publish(fmt.Sprintf("%d", sgm.Nonce), sgm.Nonce)
		for _, envelope := range resp.Alive {
			alive, err := utils.EnvelopeToSignedGossipMessage(envelope)
			if err != nil {
				gdi.logger.Errorf("Membership response contains an invalid message from an online peer, error: %s.", err.Error())
				continue
			}
			if alive.GetAliveMsg() != nil {
				if gdi.msgStore.CheckValid(alive) && gdi.crypt.ValidateAliveMsg(alive) {
					gdi.handleAliveMsg(alive)
				}
			} else {
				gdi.logger.Warnf("Expected alive message, but got %s.", alive.String())
				continue
			}
		}
		for _, envelope := range resp.Dead {
			dead, err := utils.EnvelopeToSignedGossipMessage(envelope)
			if err != nil {
				gdi.logger.Errorf("Membership response contains an invalid message from an online peer, error: %s.", err.Error())
				continue
			}

			if !gdi.msgStore.CheckValid(dead) || gdi.crypt.ValidateAliveMsg(dead) {
				continue
			}

			var unknownDeadMember []*utils.SignedGossipMessage
			gdi.mutex.RLock()
			if _, known := gdi.id2Member[utils.PKIidType(dead.GetAliveMsg().Membership.PkiId).String()]; !known {
				unknownDeadMember = append(unknownDeadMember, dead)
			}
			gdi.mutex.RUnlock()
			gdi.learnNewMembers(nil, unknownDeadMember)
		}
	}

	if sgm.GetAliveMsg() != nil {
		if !gdi.msgStore.CheckValid(sgm) || !gdi.crypt.ValidateAliveMsg(sgm) {
			return
		}
		if gdi.isSentByMe(sgm) {
			return
		}

		gdi.msgStore.Add(sgm)
		gdi.handleAliveMsg(sgm)
		gdi.adapter.Forward(msg)
	}
}

func (gdi *gossipDiscoveryImpl) handleAliveMsg(m *utils.SignedGossipMessage) {
	if gdi.isSentByMe(m) {
		return
	}

	pkiID := utils.PKIidType(m.GetAliveMsg().Membership.PkiId)
	ts := m.GetAliveMsg().Timestamp

	gdi.mutex.RLock()
	_, known := gdi.id2Member[pkiID.String()]
	gdi.mutex.RUnlock()

	if !known {
		gdi.learnNewMembers([]*utils.SignedGossipMessage{m}, []*utils.SignedGossipMessage{})
		return
	}

	gdi.mutex.RLock()
	lastAliveTS, isAlive := gdi.aliveLastTS[pkiID.String()]
	lastDeadTS, isDead := gdi.deadLastTS[pkiID.String()]
	gdi.mutex.RUnlock()

	if !isAlive && !isDead {
		gdi.logger.Panicf("Member %s is known but not found neither in alive nor in dead lastTS maps.", utils.MemberToString(m.GetAliveMsg().Membership))
		return
	}

	if isAlive && isDead {
		gdi.logger.Panicf("Member %s is known but found in alive and dead lastTS maps at the same time.", utils.MemberToString(m.GetAliveMsg().Membership))
		return
	}

	if isDead {
		if before(lastDeadTS, ts) {
			gdi.resurrectMember(m, ts)
		} else if !same(lastDeadTS, ts) {
			gdi.logger.Debugf("Got old alive message about dead peer, last dead time: %s, but the timestamp of alive message is %s.", lastDeadTS.String(), utils.PeerTimeToString(ts))
		}
	}

	if isAlive {
		if before(lastAliveTS, ts) {
			gdi.learnExistingMembers([]*utils.SignedGossipMessage{m})
		} else if !same(lastAliveTS, ts) {
			gdi.logger.Debugf("Got old alive message about alive peer, last alive time: %s, but the timestamp of alive message is %s.", lastAliveTS.String(), utils.PeerTimeToString(ts))
		}
	}
}

func (gdi *gossipDiscoveryImpl) sendMembershipResponse(targetMember *pgossip.Member, internalEndpoint string, nonce uint64) {
	targetPeer := &utils.NetworkMember{
		Endpoint:         targetMember.Endpoint,
		InternalEndpoint: internalEndpoint,
		Metadata:         targetMember.Metadata,
		PKIid:            targetMember.PkiId,
	}

	var aliveMsg *utils.SignedGossipMessage
	var err error
	gdi.mutex.RLock()
	aliveMsg = gdi.selfAliveMsg
	gdi.mutex.RUnlock()

	if aliveMsg == nil {
		aliveMsg, err = gdi.createSignedAliveMessage(true)
		if err != nil {
			gdi.logger.Errorf("Failed creating alive message, error: %s.", err.Error())
			return
		}
	}
	memResp := gdi.createMembershipResponse(aliveMsg, targetPeer)
	if memResp == nil {
		gdi.adapter.CloseConn(targetPeer)
		return
	}

	msg, err := utils.NoopSign(&pgossip.GossipMessage{
		Tag:   pgossip.GossipMessage_EMPTY,
		Nonce: nonce,
		Content: &pgossip.GossipMessage_MemRes{
			MemRes: memResp,
		},
	})
	if err != nil {
		gdi.logger.Errorf("Failed creating SignedGossipMessage, error: %s.", err.Error())
		return
	}

	gdi.adapter.SendToPeer(targetPeer, msg)
}

func (gdi *gossipDiscoveryImpl) sendMembershipRequestWithoutAck(member *utils.NetworkMember, includeInternalEndpoint bool) {
	req, err := gdi.createMembershipRequest(includeInternalEndpoint)
	if err != nil {
		gdi.logger.Errorf("Failed creating membership request, error: %s.", err.Error())
		return
	}
	signedReq, err := utils.NoopSign(req)
	if err != nil {
		gdi.logger.Errorf("Failed creating SignedGossipMessage, error: %s.", err.Error())
		return
	}
	gdi.adapter.SendToPeer(member, signedReq)
}

func (gdi *gossipDiscoveryImpl) sendUntilAcked(peer *utils.NetworkMember, msg *utils.SignedGossipMessage) {
	nonce := msg.Nonce
	for i := 0; i < gdi.maxConnectAttempts && !gdi.closed(); i++ {
		subscription := gdi.pubsub.Subscribe(fmt.Sprintf("%d", nonce), time.Second*5)
		gdi.adapter.SendToPeer(peer, msg)
		if _, timeoutErr := subscription.Listen(); timeoutErr == nil {
			return
		} else {
			gdi.logger.Errorf("Timeout expired, couldn't receive acknowledgement from %s.", peer.PKIid.String())
		}
		time.Sleep(gdi.reconnectInterval)
	}
}

func (gdi *gossipDiscoveryImpl) learnNewMembers(aliveMembers []*utils.SignedGossipMessage, deadMembers []*utils.SignedGossipMessage) {
	gdi.mutex.Lock()
	defer gdi.mutex.Unlock()

	for _, am := range aliveMembers {
		pkiID := utils.PKIidType(am.GetAliveMsg().Membership.PkiId)
		if bytes.Equal(gdi.self.PKIid, pkiID) {
			continue
		}
		gdi.aliveLastTS[pkiID.String()] = &timestamp{
			incTime:  tsToTime(am.GetAliveMsg().Timestamp.IncNum),
			lastSeen: time.Now(),
			seqNum:   am.GetAliveMsg().Timestamp.SeqNum,
		}
		gdi.aliveMembership.Put(pkiID, &utils.SignedGossipMessage{GossipMessage: am.GossipMessage, Envelope: am.Envelope})
		gdi.logger.Debugf("Learned about a new alive member: %s.", utils.AliveMessageToString(am.GetAliveMsg()))
	}

	for _, dm := range deadMembers {
		pkiID := utils.PKIidType(dm.GetAliveMsg().Membership.PkiId)
		if bytes.Equal(pkiID, gdi.self.PKIid) {
			gdi.logger.Warn("I am alive, but someone thinks i'm dead.")
			continue
		}
		gdi.deadLastTS[pkiID.String()] = &timestamp{
			incTime:  tsToTime(dm.GetAliveMsg().Timestamp.IncNum),
			seqNum:   dm.GetAliveMsg().Timestamp.SeqNum,
			lastSeen: time.Now(),
		}
		gdi.deadMembership.Put(pkiID, &utils.SignedGossipMessage{GossipMessage: dm.GossipMessage, Envelope: dm.Envelope})
		gdi.logger.Debugf("Learned about a new dead member: %s.", utils.AliveMessageToString(dm.GetAliveMsg()))
	}

	// 更新所有新成员信息，无论是活的还是死的。
	for _, members := range [][]*utils.SignedGossipMessage{aliveMembers, deadMembers} {
		for _, m := range members {
			aMsg := m.GetAliveMsg()
			pkiID := utils.PKIidType(aMsg.Membership.PkiId)

			var internalEndpoint string
			if m.Envelope.SecretEnvelope != nil {
				internalEndpoint = utils.InternalEndpoint(m.SecretEnvelope)
			}
			if prevNetMem := gdi.id2Member[pkiID.String()]; prevNetMem != nil {
				internalEndpoint = prevNetMem.InternalEndpoint
			}

			gdi.id2Member[pkiID.String()] = &utils.NetworkMember{
				Endpoint:         aMsg.Membership.Endpoint,
				InternalEndpoint: internalEndpoint,
				Metadata:         aMsg.Membership.Metadata,
				PKIid:            pkiID,
			}
		}
	}
}

func (gdi *gossipDiscoveryImpl) learnExistingMembers(aliveArr []*utils.SignedGossipMessage) {
	gdi.mutex.Lock()
	defer gdi.mutex.Unlock()

	for _, m := range aliveArr {
		am := m.GetAliveMsg()
		if am == nil {
			continue
		}

		pkiID := utils.PKIidType(am.Membership.PkiId)

		var internalEndpoint string
		if prevNetMem := gdi.id2Member[pkiID.String()]; prevNetMem != nil {
			internalEndpoint = prevNetMem.InternalEndpoint
		}
		if m.Envelope.SecretEnvelope != nil {
			internalEndpoint = utils.InternalEndpoint(m.SecretEnvelope)
		}

		gdi.id2Member[pkiID.String()] = &utils.NetworkMember{
			Endpoint:         am.Membership.Endpoint,
			InternalEndpoint: internalEndpoint,
			Metadata:         am.Membership.Metadata,
			PKIid:            pkiID,
		}

		if _, isKnownAsDead := gdi.deadLastTS[pkiID.String()]; isKnownAsDead {
			gdi.logger.Warnf("The member %s has been dead.", utils.MemberToString(am.Membership))
			continue
		}

		if oldTS, isKnownAsAlive := gdi.aliveLastTS[pkiID.String()]; !isKnownAsAlive {
			gdi.logger.Warnf("The member %s is not alive.", utils.MemberToString(am.Membership))
			continue
		} else {
			var changed bool = false
			newIncTime := tsToTime(am.Timestamp.IncNum)
			if !oldTS.incTime.Equal(newIncTime) {
				changed = true
				oldTS.incTime = newIncTime
			}
			if oldTS.seqNum != am.Timestamp.SeqNum {
				changed = true
				oldTS.seqNum = am.Timestamp.SeqNum
			}
			if changed {
				gdi.logger.Debugf("Update alive member: %s.", utils.AliveMessageToString(am))
			}
			gdi.aliveLastTS[pkiID.String()].lastSeen = time.Now()

			if old := gdi.aliveMembership.MsgByID(pkiID); old != nil {
				gdi.logger.Debugf("Replace old alive membership %s by new alive membership %s.", utils.AliveMessageToString(old.GetAliveMsg()), utils.AliveMessageToString(am))
				gdi.aliveMembership.Remove(pkiID)
				gdi.aliveMembership.Put(pkiID, &utils.SignedGossipMessage{GossipMessage: m.GossipMessage, Envelope: m.Envelope})
			}
		}
	}
}

func (gdi *gossipDiscoveryImpl) resurrectMember(sgm *utils.SignedGossipMessage, pt *pgossip.PeerTime) {
	gdi.mutex.Lock()
	defer gdi.mutex.Unlock()

	membership := sgm.GetAliveMsg().Membership
	pkiID := utils.PKIidType(membership.PkiId)
	gdi.aliveLastTS[pkiID.String()] = &timestamp{
		lastSeen: time.Now(),
		seqNum:   pt.SeqNum,
		incTime:  tsToTime(pt.IncNum),
	}

	var internalEndpoint string
	if prevNetMem := gdi.id2Member[pkiID.String()]; prevNetMem != nil {
		internalEndpoint = prevNetMem.InternalEndpoint
	}
	if sgm.SecretEnvelope != nil {
		internalEndpoint = utils.InternalEndpoint(sgm.SecretEnvelope)
	}

	gdi.id2Member[pkiID.String()] = &utils.NetworkMember{
		Endpoint:         membership.Endpoint,
		InternalEndpoint: internalEndpoint,
		Metadata:         membership.Metadata,
		PKIid:            pkiID,
	}

	delete(gdi.deadLastTS, pkiID.String())
	gdi.deadMembership.Remove(pkiID)
	gdi.aliveMembership.Put(pkiID, &utils.SignedGossipMessage{GossipMessage: sgm.GossipMessage, Envelope: sgm.Envelope})
}

func (gdi *gossipDiscoveryImpl) getDeadMembers() []utils.PKIidType {
	gdi.mutex.RLock()
	defer gdi.mutex.RUnlock()

	dead := []utils.PKIidType{}
	for id, last := range gdi.aliveLastTS {
		elapsedNonAliveTime := time.Since(last.lastSeen)
		if elapsedNonAliveTime > gdi.aliveExpirationTimeout {
			gdi.logger.Warnf("Haven't heard from %s for %.2f seconds.", id, elapsedNonAliveTime.Seconds())
			pkiID := utils.StringToPKIidType(id)
			dead = append(dead, pkiID)
		}
	}
	return dead
}

func (gdi *gossipDiscoveryImpl) isSentByMe(m *utils.SignedGossipMessage) bool {
	pkiID := m.GetAliveMsg().Membership.PkiId
	if !bytes.Equal(gdi.self.PKIid, pkiID) {
		return false
	}
	diffExternalEndpoint := gdi.self.Endpoint != m.GetAliveMsg().Membership.Endpoint
	var diffInternalEndpoint bool
	if m.GetSecretEnvelope() != nil {
		internalEndpoint := utils.InternalEndpoint(m.GetSecretEnvelope())
		if internalEndpoint != "" {
			diffInternalEndpoint = gdi.self.InternalEndpoint != internalEndpoint
		}
	}

	if diffExternalEndpoint || diffInternalEndpoint {
		gdi.logger.Errorf("Bad configuration detected, received AliveMessage from a peer with the same PKI-ID as myself: %s.", utils.AliveMessageToString(m.GetAliveMsg()))
	}
	return true
}

func (gdi *gossipDiscoveryImpl) createSignedAliveMessage(includeInternalEndpoint bool) (*utils.SignedGossipMessage, error) {
	msg, internalEndpoint := gdi.aliveMsgAndInternalEndpoint()
	envelope := gdi.crypt.SignMessage(msg, internalEndpoint)
	if envelope == nil {
		return nil, errors.NewError("failed signing message")
	}
	sgm := &utils.SignedGossipMessage{
		GossipMessage: msg,
		Envelope:      envelope,
	}
	if !includeInternalEndpoint {
		sgm.SecretEnvelope = nil
	}

	return sgm, nil
}

func (gdi *gossipDiscoveryImpl) createMembershipResponse(aliveMsg *utils.SignedGossipMessage, targetMember *utils.NetworkMember) *pgossip.MembershipResponse {
	shouldSend, omitConcealedFields := gdi.disclosurePolicy(targetMember)

	if !shouldSend(aliveMsg) {
		return nil
	}

	gdi.mutex.RLock()
	defer gdi.mutex.RUnlock()

	var deadPeers []*pgossip.Envelope
	for _, dm := range gdi.deadMembership.ToSlice() {
		if !shouldSend(dm) {
			continue
		}
		deadPeers = append(deadPeers, omitConcealedFields(dm))
	}

	var alivePeers = []*pgossip.Envelope{omitConcealedFields(aliveMsg)}
	for _, am := range gdi.aliveMembership.ToSlice() {
		if !shouldSend(am) {
			continue
		}
		alivePeers = append(alivePeers, omitConcealedFields(am))
	}

	return &pgossip.MembershipResponse{
		Alive: alivePeers,
		Dead:  deadPeers,
	}
}

func (gdi *gossipDiscoveryImpl) createMembershipRequest(includeInternalEndpoint bool) (*pgossip.GossipMessage, error) {
	aliveMsg, err := gdi.createSignedAliveMessage(includeInternalEndpoint)
	if err != nil {
		return nil, errors.NewError(err.Error())
	}
	req := &pgossip.MembershipRequest{
		SelfInformation: aliveMsg.Envelope,
	}
	return &pgossip.GossipMessage{
		Tag:   pgossip.GossipMessage_EMPTY,
		Nonce: uint64(0),
		Content: &pgossip.GossipMessage_MemReq{
			MemReq: req,
		},
	}, nil
}

func (gdi *gossipDiscoveryImpl) aliveMsgAndInternalEndpoint() (*pgossip.GossipMessage, string) {
	gdi.mutex.Lock()
	defer gdi.mutex.Unlock()

	gdi.seqNum++
	msg := &pgossip.GossipMessage{
		Tag: pgossip.GossipMessage_EMPTY,
		Content: &pgossip.GossipMessage_AliveMsg{
			AliveMsg: &pgossip.AliveMessage{
				Membership: &pgossip.Member{
					Endpoint: gdi.self.Endpoint,
					Metadata: gdi.self.Metadata,
					PkiId:    gdi.self.PKIid,
				},
				Timestamp: &pgossip.PeerTime{
					IncNum: gdi.incTime,
					SeqNum: gdi.seqNum,
				},
			},
		},
	}
	return msg, gdi.self.InternalEndpoint
}

func (gdi *gossipDiscoveryImpl) expireDeadMembers(dead []utils.PKIidType) {
	var deadMembersToExpire []utils.NetworkMember
	gdi.mutex.Lock()
	for _, pkiID := range dead {
		lastTS, isAlive := gdi.aliveLastTS[pkiID.String()]
		if isAlive {
			deadMembersToExpire = append(deadMembersToExpire, gdi.id2Member[pkiID.String()].Clone())
			gdi.deadLastTS[pkiID.String()] = lastTS
			delete(gdi.aliveLastTS, pkiID.String())

			if am := gdi.aliveMembership.MsgByID(pkiID); am != nil {
				gdi.deadMembership.Put(pkiID, am)
				gdi.aliveMembership.Remove(pkiID)
			}
		}
	}
	gdi.mutex.Unlock()

	for i := range deadMembersToExpire {
		gdi.logger.Infof("Because %s is dead, disconnect from it.", deadMembersToExpire[i])
		gdi.adapter.CloseConn(&deadMembersToExpire[i])
	}
}

func (gdi *gossipDiscoveryImpl) copyLastSeen(lastSeenMap map[string]*timestamp) []utils.NetworkMember {
	gdi.mutex.RLock()
	defer gdi.mutex.RUnlock()

	res := []utils.NetworkMember{}
	for pkiID := range lastSeenMap {
		res = append(res, *gdi.id2Member[pkiID])
	}
	return res
}

func (gdi *gossipDiscoveryImpl) isAlive(pkiID utils.PKIidType) bool {
	gdi.mutex.RLock()
	defer gdi.mutex.RUnlock()
	_, isAlive := gdi.aliveLastTS[pkiID.String()]
	return isAlive
}

func (gdi *gossipDiscoveryImpl) isMyOwnEndpoint(endpoint string) bool {
	return endpoint == fmt.Sprintf("127.0.0.1:%d", gdi.port) || endpoint == fmt.Sprintf("localhost:%d", gdi.port) || endpoint == gdi.self.Endpoint || endpoint == gdi.self.InternalEndpoint
}

func (gdi *gossipDiscoveryImpl) remove(pkiID utils.PKIidType) {
	gdi.mutex.Lock()
	defer gdi.mutex.Unlock()
	gdi.aliveMembership.Remove(pkiID)
	gdi.deadMembership.Remove(pkiID)
	delete(gdi.deadLastTS, pkiID.String())
	delete(gdi.aliveLastTS, pkiID.String())
	delete(gdi.id2Member, pkiID.String())
}

func (gdi *gossipDiscoveryImpl) closed() bool {
	select {
	case <-gdi.stopChan:
		return true
	default:
		return false
	}
}

func tsToTime(ts uint64) time.Time {
	return time.Unix(0, int64(ts))
}

func same(a *timestamp, b *pgossip.PeerTime) bool {
	return uint64(a.incTime.UnixNano()) == b.IncNum && a.seqNum == b.SeqNum
}

// before 判断时间戳 a 是否在时间戳 b 之前。
func before(a *timestamp, b *pgossip.PeerTime) bool {
	return (uint64(a.incTime.UnixNano()) == b.IncNum && a.seqNum < b.SeqNum) || (uint64(a.incTime.UnixNano()) < b.IncNum)
}
