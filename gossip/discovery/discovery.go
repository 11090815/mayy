package discovery

import (
	"bytes"
	"encoding/hex"
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
	"github.com/11090815/mayy/gossip/protoext"
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
type EnvelopeFilter func(message *protoext.SignedGossipMessage) *pgossip.Envelope

// Sieve 决定了是否能将 SignedGossipMessage 发送给远程节点。
type Sieve func(message *protoext.SignedGossipMessage) bool

// DisclosurePolicy 定义了给定的远程对等体是否有资格了解消息，以及从给定的 SignedGossipMessage 中有资格了解哪些消息。
type DisclosurePolicy func(remotePeer *NetworkMember) (Sieve, EnvelopeFilter)

type identifier func() (*PeerIdentification, error)

/* ------------------------------------------------------------------------------------------ */

type NetworkMember struct {
	Endpoint         string
	InternalEndpoint string
	Metadata         []byte
	PKIid            utils.PKIidType
	Properties       *pgossip.Properties
	*pgossip.Envelope
}

func (nm NetworkMember) Clone() NetworkMember {
	pkiIDClone := make([]byte, len(nm.PKIid))
	copy(pkiIDClone, nm.PKIid)
	metadataClone := make([]byte, len(nm.Metadata))
	copy(metadataClone, nm.Metadata)
	clone := NetworkMember{
		Endpoint:         nm.Endpoint,
		InternalEndpoint: nm.InternalEndpoint,
		Metadata:         metadataClone,
		PKIid:            pkiIDClone,
		Properties:       proto.Clone(nm.Properties).(*pgossip.Properties),
		Envelope:         proto.Clone(nm.Envelope).(*pgossip.Envelope),
	}

	return clone
}

func (nm NetworkMember) PreferredEndpoint() string {
	if nm.InternalEndpoint != "" {
		return nm.InternalEndpoint
	}
	return nm.Endpoint
}

func (nm NetworkMember) HasExternalEndpoint() bool {
	return nm.Endpoint != ""
}

func (nm NetworkMember) String() string {
	return fmt.Sprintf("{NetworkMember | Endpoint: %s; InternalEndpoint: %s; Metadata: %dbytes; PKI-ID: %s; Properties: %s; Envelope: %s}",
		nm.Endpoint, nm.InternalEndpoint, len(nm.Metadata), nm.PKIid.String(), protoext.PropertiesToString(nm.Properties), protoext.EnvelopeToString(nm.Envelope))
}

/* ------------------------------------------------------------------------------------------ */

type Members []NetworkMember

// ByID 将 Members ([]NetworkMember) 转化成 mapper: PKI-ID => NetworkMember。
func (members Members) ByID() map[string]NetworkMember {
	mapper := make(map[string]NetworkMember)
	for _, peer := range members {
		mapper[peer.PKIid.String()] = peer
	}
	return mapper
}

// Intersect 获得两个 Members 的交集。
func (members Members) Intersect(otherMembers Members) Members {
	var intersect Members
	otherMap := otherMembers.ByID()
	for _, peer := range members {
		if _, exists := otherMap[peer.PKIid.String()]; exists {
			intersect = append(intersect, peer)
		}
	}
	return intersect
}

func (members Members) Filter(filter func(peer NetworkMember) bool) Members {
	var res Members
	for _, peer := range members {
		if filter(peer) {
			res = append(res, peer)
		}
	}
	return res
}

// Map 对 Members 里的每个 NetworkMember 调用一次给定的函数。
func (members Members) Map(f func(NetworkMember) NetworkMember) Members {
	var res Members
	for _, peer := range members {
		res = append(res, f(peer))
	}
	return res
}

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
	Gossip(msg *protoext.SignedGossipMessage)

	// SendToPeer 单播。
	SendToPeer(peer *NetworkMember, msg *protoext.SignedGossipMessage)

	Ping(peer *NetworkMember) bool

	Accept() <-chan protoext.ReceivedMessage

	// ReceiveDiscoveryMessage 接收与 discovery 相关的消息。
	ReceiveDiscoveryMessage(msg protoext.ReceivedMessage)

	PresumedDead() <-chan utils.PKIidType

	CloseConn(peer *NetworkMember)

	// Forward 将消息转发给下一跳。
	Forward(msg protoext.ReceivedMessage)

	// IdentitySwitch 返回一个通道，此通道内存放证书发生变化的节点的 ID。
	IdentitySwitch() <-chan utils.PKIidType

	Stop()
}

// batchingEmitter 用于 gossip 推送/转发 阶段。消息被添加到 batchingEmitter 中，它们被周期性地分批转发 T 次，
// 然后被丢弃。如果 batchingEmitter 存储的消息计数达到一定容量，也会触发消息分派。
type batchingEmitter interface {
	Add(any)
	Size() int
	Stop()
}

// emittedGossipMessage 封装了签名的 gossip 消息，并在消息转发时使用路由过滤器
type emittedGossipMessage struct {
	*protoext.SignedGossipMessage
	filter func(id utils.PKIidType) bool
}

type discoveryAdapter struct {
	c                comm.Comm
	presumedDead     chan utils.PKIidType
	incChan          chan protoext.ReceivedMessage
	gossipFunc       func(msg *protoext.SignedGossipMessage)
	forwardFunc      func(msg protoext.ReceivedMessage)
	disclosurePolicy DisclosurePolicy
	stopping         int32
	stopOnce         sync.Once
}

func NewDiscoveryAdapter(c comm.Comm, propagateTimes int, emitter batchingEmitter, presumedDead chan utils.PKIidType, disclosurePolicy DisclosurePolicy) DiscoveryAdapter {
	adapter := &discoveryAdapter{
		c:            c,
		presumedDead: presumedDead,
		incChan:      make(chan protoext.ReceivedMessage),
		gossipFunc: func(msg *protoext.SignedGossipMessage) {
			if propagateTimes == 0 {
				return
			}
			emitter.Add(&emittedGossipMessage{
				SignedGossipMessage: msg,
				filter: func(id utils.PKIidType) bool {
					return true
				},
			})
		},
		forwardFunc: func(msg protoext.ReceivedMessage) {
			if propagateTimes == 0 {
				return
			}
			emitter.Add(&emittedGossipMessage{
				SignedGossipMessage: msg.GetSignedGossipMessage(),
				filter:              msg.GetConnectionInfo().ID.IsNotSameFilter,
			})
		},
		disclosurePolicy: disclosurePolicy,
		stopping:         int32(0),
	}

	return adapter
}

func (da *discoveryAdapter) Gossip(msg *protoext.SignedGossipMessage) {
	if da.closed() {
		return
	}
	da.gossipFunc(msg)
}

func (da *discoveryAdapter) SendToPeer(peer *NetworkMember, msg *protoext.SignedGossipMessage) {
	if da.closed() {
		return
	}

	if memReq := msg.GetMemReq(); memReq != nil && len(peer.PKIid) != 0 {
		selfMsg, err := protoext.EnvelopeToSignedGossipMessage(memReq.SelfInformation)
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
		if msg, err = protoext.NoopSign(msgClone); err != nil {
			return
		}
		da.c.Send(msg, &comm.RemotePeer{PKIID: peer.PKIid, Endpoint: peer.PreferredEndpoint()})
		return
	}
	da.c.Send(msg, &comm.RemotePeer{PKIID: peer.PKIid, Endpoint: peer.PreferredEndpoint()})
}

func (da *discoveryAdapter) Ping(peer *NetworkMember) bool {
	if da.closed() {
		return false
	}
	return da.c.Probe(&comm.RemotePeer{PKIID: peer.PKIid, Endpoint: peer.PreferredEndpoint()}) == nil
}

func (da *discoveryAdapter) Accept() <-chan protoext.ReceivedMessage {
	return da.incChan
}

func (da *discoveryAdapter) ReceiveDiscoveryMessage(msg protoext.ReceivedMessage) {
	da.incChan <- msg
}

func (da *discoveryAdapter) PresumedDead() <-chan utils.PKIidType {
	return da.presumedDead
}

func (da *discoveryAdapter) CloseConn(peer *NetworkMember) {
	da.c.CloseConn(&comm.RemotePeer{PKIID: peer.PKIid, Endpoint: peer.PreferredEndpoint()})
}

func (da *discoveryAdapter) Forward(msg protoext.ReceivedMessage) {
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
	Lookup(pkiID utils.PKIidType) *NetworkMember

	// Self 返回此实例的信息。
	Self() NetworkMember

	// UpdateMetadata 更新此实例的元数据信息。
	UpdateMetadata([]byte)

	// UpdateEndpoint 更新此实例的 endpoint。
	UpdateEndpoint(string)

	// GetMembership 返回所有成员信息。
	GetMembership() Members

	// InitiateSync 向 peerNum 个节点询问它们所掌握的成员信息，将这些信息同步过来。
	InitiateSync(peerNum int)

	// Connect 与节点建立连接，同时确认对方与自己是否在同一组织内。
	Connect(member NetworkMember, identifier identifier)

	Stop()
}

type gossipDiscoveryImpl struct {
	self         NetworkMember
	selfAliveMsg *protoext.SignedGossipMessage
	port         int
	incTime      uint64
	seqNum       uint64

	bootstrapPeers    []string
	anchorPeerTracker AnchorPeerTracker

	crypt   CryptoService
	adapter DiscoveryAdapter
	pubsub  *utils.PubSub

	logger mlog.Logger
	mutex  *sync.RWMutex

	aliveMembership *protoext.MembershipStore
	aliveLastTS     map[string]*timestamp // PKIid => *timestamp
	deadMembership  *protoext.MembershipStore
	deadLastTS      map[string]*timestamp     // PKIid => *timestamp
	id2Member       map[string]*NetworkMember // PKIid => *NetworkMember
	msgStore        *aliveMsgStore

	aliveTimeInterval time.Duration // 每隔这段时间，广播一次自己的 alive 消息
	// aliveExpirationTimeout x aliveMsgExpirationFactor 得到 alive 消息的过期时间
	aliveExpirationTimeout       time.Duration // 超过这么长时间没有消息的话，就会断开与此节点之间建立的连接
	aliveMsgExpirationFactor     int
	aliveExpirationCheckInterval time.Duration
	reconnectInterval            time.Duration

	disclosurePolicy DisclosurePolicy

	maxConnectAttempts int

	stopChan chan struct{}
}

type aliveMsgStore struct {
	msgstore.MessageStore
}

func newAliveMsgStore(d *gossipDiscoveryImpl) *aliveMsgStore {
	policy := protoext.NewGossipMessageComparator(0)
	aliveMsgTTL := d.aliveExpirationTimeout * time.Duration(d.aliveMsgExpirationFactor)
	externalLock := func() { d.mutex.Lock() }
	externalUnlock := func() { d.mutex.Unlock() }

	callback := func(m any) {
		msg := m.(*protoext.SignedGossipMessage)
		if msg.GetAliveMsg() == nil {
			return
		}
		membership := msg.GetAliveMsg().Membership
		id := utils.PKIidType(membership.PkiId)
		endpoint := membership.Endpoint
		internalEndpoint := protoext.InternalEndpoint(msg.SecretEnvelope)
		if utils.Contains(internalEndpoint, d.bootstrapPeers) || d.anchorPeerTracker.IsAnchorPeer(internalEndpoint) ||
			utils.Contains(endpoint, d.bootstrapPeers) || d.anchorPeerTracker.IsAnchorPeer(endpoint) {
			d.logger.Warnf("Do not remove bootstrap or anchor peer endpoint %s from membership.", endpoint)
			return
		}
		d.logger.Infof("Remove member %s.", protoext.MemberToString(membership))
		d.aliveMembership.Remove(id)
		d.deadMembership.Remove(id)
		delete(d.id2Member, id.String())
		delete(d.deadLastTS, id.String())
		delete(d.aliveLastTS, id.String())
	}

	s := &aliveMsgStore{
		MessageStore: msgstore.NewMessageStoreExpirable(policy, msgstore.NoopTrigger, aliveMsgTTL, externalLock, externalUnlock, callback),
	}

	return s
}

func (ams *aliveMsgStore) Add(msg any) bool {
	m := msg.(*protoext.SignedGossipMessage)
	if m.GetAliveMsg() != nil {
		return ams.MessageStore.Add(msg)
	} else {
		panic(fmt.Sprintf("expected AliveMessage, but got %T", m.GossipMessage))
	}
}

func (ams *aliveMsgStore) CheckValid(msg any) bool {
	m := msg.(*protoext.SignedGossipMessage)
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
	return fmt.Sprintf("{timestamp | incTime: %d; seqNum: %d}", ts.incTime.UnixNano(), ts.seqNum)
}

type DiscoveryConfig struct {
	AliveTimeInterval            time.Duration
	AliveExpirationTimeout       time.Duration
	AliveExpirationCheckInterval time.Duration
	ReconnectInterval            time.Duration
	MaxConnectAttempts           int
	MsgExpirationFactor          int
	BootstrapPeers               []string
}

func NewDiscoveryService(self NetworkMember, adapter DiscoveryAdapter, crypt CryptoService, policy DisclosurePolicy,
	config DiscoveryConfig, anchorPeerTracker AnchorPeerTracker, logger mlog.Logger) Discovery {
	gdi := &gossipDiscoveryImpl{
		self:                         self,
		incTime:                      uint64(time.Now().UnixNano()),
		seqNum:                       uint64(0),
		aliveLastTS:                  make(map[string]*timestamp),
		deadLastTS:                   make(map[string]*timestamp),
		id2Member:                    make(map[string]*NetworkMember),
		aliveMembership:              protoext.NewMembershipStore(),
		deadMembership:               protoext.NewMembershipStore(),
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
		maxConnectAttempts:           config.MaxConnectAttempts,
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

func (gdi *gossipDiscoveryImpl) Lookup(pkiID utils.PKIidType) *NetworkMember {
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

func (gdi *gossipDiscoveryImpl) Self() NetworkMember {
	if gdi.closed() {
		gdi.logger.Warn("Discovery service is already closed.")
		return NetworkMember{}
	}
	gdi.mutex.RLock()
	defer gdi.mutex.RUnlock()
	aliveMsg, _ := gdi.aliveMsgAndInternalEndpoint()
	envelope, _ := protoext.NoopSign(aliveMsg)
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
	gdi.mutex.Unlock()
	gdi.self.Endpoint = endpoint
}

func (gdi *gossipDiscoveryImpl) GetMembership() Members {
	if gdi.closed() {
		gdi.logger.Warn("Discovery service is already closed.")
		return []NetworkMember{}
	}
	gdi.mutex.RLock()
	defer gdi.mutex.RUnlock()
	var aliveMembers Members
	for pkiID := range gdi.aliveLastTS {
		aliveMembers = append(aliveMembers, gdi.id2Member[pkiID].Clone())
	}
	return aliveMembers
}

func (gdi *gossipDiscoveryImpl) InitiateSync(peerNum int) {
	if gdi.closed() {
		gdi.logger.Warn("Discovery service is already closed.")
		return
	}

	var peers2Send []*NetworkMember

	gdi.mutex.RLock()
	n := gdi.aliveMembership.Size()
	t := peerNum
	if t > n {
		t = n
	}
	aliveMembersAsSlice := gdi.aliveMembership.ToSlice()
	for _, i := range utils.GetRandomIndices(t, n-1) {
		pulledPeer := aliveMembersAsSlice[i].GetAliveMsg().Membership
		var internalEndpoint string
		if aliveMembersAsSlice[i].Envelope.SecretEnvelope != nil {
			internalEndpoint = protoext.InternalEndpoint(aliveMembersAsSlice[i].SecretEnvelope)
		}
		peers2Send = append(peers2Send, &NetworkMember{
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
	signedReq, err := protoext.NoopSign(req)
	if err != nil {
		gdi.logger.Errorf("Failed creating SignedGossipMessage, error: %s.", err.Error())
		return
	}

	for _, mem := range peers2Send {
		gdi.adapter.SendToPeer(mem, signedReq)
	}
}

func (gdi *gossipDiscoveryImpl) Connect(member NetworkMember, identifier identifier) {
	for _, endpoint := range []string{member.Endpoint, member.InternalEndpoint} {
		if gdi.isMyOwnEndpoint(endpoint) {
			return
		}
	}
	go func() {
		for i := 0; i < gdi.maxConnectAttempts && !gdi.closed(); i++ {
			id, err := identifier()
			if err != nil {
				if gdi.closed() {
					return
				}
				gdi.logger.Errorf("Couldn't fetch identity information for member %s, error: %s.", member.String(), err.Error())
				time.Sleep(gdi.reconnectInterval)
				continue
			}
			peer := &NetworkMember{
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
			signedReq, err := protoext.NoopSign(req)
			if err != nil {
				gdi.logger.Errorf("Failed creating SignedGossipMessage, error: %s.", err.Error())
				continue
			}
			gdi.sendUntilAcked(peer, signedReq)
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
			go func(nm NetworkMember) {
				defer wg.Done()
				if gdi.adapter.Ping(&nm) {
					gdi.logger.Debugf("Member %s is responding, we can send membership request to it.", nm.String())
					gdi.sendMembershipRequestWithoutAck(&member, true)
				} else {
					gdi.logger.Debugf("Member %s is still dead.", nm.String())
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
		if len(dead) > 1 {
			gdi.logger.Debugf("There are %d dead members in this view.", len(dead))
			gdi.expireDeadMembers(dead)
		} else if len(dead) > 0 {
			gdi.logger.Debug("There is one dead member in this view.")
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
			gdi.purge(changedID)
		case <-gdi.stopChan:
			return
		}
	}
}

func (gdi *gossipDiscoveryImpl) handleMessages() {
	inCh := gdi.adapter.Accept()
	for {
		select {
		case m := <-inCh:
			gdi.handleMsgFromComm(m)
		case <-gdi.stopChan:
			return
		}
	}
}

func (gdi *gossipDiscoveryImpl) handleMsgFromComm(msg protoext.ReceivedMessage) {
	if msg == nil {
		return
	}

	sgm := msg.GetSignedGossipMessage()
	if sgm.GetAliveMsg() == nil || sgm.GetMemReq() == nil || sgm.GetMemRes() == nil {
		gdi.logger.Warnf("Discovery service only accepts AliveMessage or MembershipRequest or MembershipResponse message, but got: %s.", sgm.String())
		return
	}

	if req := sgm.GetMemReq(); req != nil {
		selfInfo, err := protoext.EnvelopeToSignedGossipMessage(req.SelfInformation)
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
			internalEndpoint = protoext.InternalEndpoint(req.SelfInformation.SecretEnvelope)
		}

		go gdi.sendMembershipResponse(selfInfo.GetAliveMsg().Membership, internalEndpoint, sgm.Nonce)
	}

	if resp := sgm.GetMemRes(); resp != nil {
		gdi.pubsub.Publish(fmt.Sprintf("%d", sgm.Nonce), sgm.Nonce)
		for _, envelope := range resp.Alive {
			alive, err := protoext.EnvelopeToSignedGossipMessage(envelope)
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
			dead, err := protoext.EnvelopeToSignedGossipMessage(envelope)
			if err != nil {
				gdi.logger.Errorf("Membership response contains an invalid message from an online peer, error: %s.", err.Error())
				continue
			}

			if !gdi.msgStore.CheckValid(dead) || gdi.crypt.ValidateAliveMsg(dead) {
				continue
			}

			var unknownDeadMember []*protoext.SignedGossipMessage
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

func (gdi *gossipDiscoveryImpl) handleAliveMsg(m *protoext.SignedGossipMessage) {
	if gdi.isSentByMe(m) {
		return
	}

	pkiID := utils.PKIidType(m.GetAliveMsg().Membership.PkiId)
	ts := m.GetAliveMsg().Timestamp

	gdi.mutex.RLock()
	_, known := gdi.id2Member[pkiID.String()]
	gdi.mutex.RUnlock()

	if !known {
		gdi.learnNewMembers([]*protoext.SignedGossipMessage{m}, []*protoext.SignedGossipMessage{})
		return
	}

	gdi.mutex.RLock()
	lastAliveTS, isAlive := gdi.aliveLastTS[pkiID.String()]
	lastDeadTS, isDead := gdi.deadLastTS[pkiID.String()]
	gdi.mutex.RUnlock()

	if !isAlive && !isDead {
		gdi.logger.Panicf("Member %s is known but not found neither in alive nor in dead lastTS maps.", protoext.MemberToString(m.GetAliveMsg().Membership))
		return
	}

	if isAlive && isDead {
		gdi.logger.Panicf("Member %s is known but found in alive and dead lastTS maps at the same time.", protoext.MemberToString(m.GetAliveMsg().Membership))
		return
	}

	if isDead {
		if before(lastDeadTS, ts) {
			gdi.resurrectMember(m, ts)
		} else if !same(lastDeadTS, ts) {
			gdi.logger.Debugf("Got old alive message about dead peer, last dead time: %s, but the timestamp of alive message is %s.", lastDeadTS.String(), protoext.PeerTimeToString(ts))
		}
	}

	if isAlive {
		if before(lastAliveTS, ts) {
			gdi.learnExistingMembers([]*protoext.SignedGossipMessage{m})
		} else if !same(lastAliveTS, ts) {
			gdi.logger.Debugf("Got old alive message about alive peer, last alive time: %s, but the timestamp of alive message is %s.", lastDeadTS.String(), protoext.PeerTimeToString(ts))
		}
	}
}

func (gdi *gossipDiscoveryImpl) sendMembershipResponse(targetMember *pgossip.Member, internalEndpoint string, nonce uint64) {
	targetPeer := &NetworkMember{
		Endpoint:         targetMember.Endpoint,
		InternalEndpoint: internalEndpoint,
		Metadata:         targetMember.Metadata,
		PKIid:            targetMember.PkiId,
	}

	var aliveMsg *protoext.SignedGossipMessage
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
		return
	}

	msg, err := protoext.NoopSign(&pgossip.GossipMessage{
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

func (gdi *gossipDiscoveryImpl) sendMembershipRequestWithoutAck(member *NetworkMember, includeInternalEndpoint bool) {
	req, err := gdi.createMembershipRequest(includeInternalEndpoint)
	if err != nil {
		gdi.logger.Errorf("Failed creating membership request, error: %s.", err.Error())
		return
	}
	signedReq, err := protoext.NoopSign(req)
	if err != nil {
		gdi.logger.Errorf("Failed creating SignedGossipMessage, error: %s.", err.Error())
		return
	}
	gdi.adapter.SendToPeer(member, signedReq)
}

func (gdi *gossipDiscoveryImpl) sendUntilAcked(peer *NetworkMember, msg *protoext.SignedGossipMessage) {
	nonce := msg.Nonce
	for i := 0; i < gdi.maxConnectAttempts && !gdi.closed(); i++ {
		subscription := gdi.pubsub.Subscribe(fmt.Sprintf("%d", nonce), time.Second*5)
		gdi.adapter.SendToPeer(peer, msg)
		if _, timeoutErr := subscription.Listen(); timeoutErr == nil {
			return
		}
		time.Sleep(gdi.reconnectInterval)
	}
}

func (gdi *gossipDiscoveryImpl) learnNewMembers(aliveMembers []*protoext.SignedGossipMessage, deadMembers []*protoext.SignedGossipMessage) {
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
		gdi.aliveMembership.Put(pkiID, &protoext.SignedGossipMessage{GossipMessage: am.GossipMessage, Envelope: am.Envelope})
		gdi.logger.Debugf("Learned about a new alive member: %s.", protoext.AliveMessageToString(am.GetAliveMsg()))
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
		gdi.deadMembership.Put(pkiID, &protoext.SignedGossipMessage{GossipMessage: dm.GossipMessage, Envelope: dm.Envelope})
		gdi.logger.Debugf("Learned about a new dead member: %s.", protoext.AliveMessageToString(dm.GetAliveMsg()))
	}

	// 更新所有新成员信息，无论是活的还是死的。
	for _, members := range [][]*protoext.SignedGossipMessage{aliveMembers, deadMembers} {
		for _, m := range members {
			aMsg := m.GetAliveMsg()
			pkiID := utils.PKIidType(aMsg.Membership.PkiId)

			var internalEndpoint string
			if m.Envelope.SecretEnvelope != nil {
				internalEndpoint = protoext.InternalEndpoint(m.SecretEnvelope)
			}
			if prevNetMem := gdi.id2Member[pkiID.String()]; prevNetMem != nil {
				internalEndpoint = prevNetMem.InternalEndpoint
			}

			gdi.id2Member[pkiID.String()] = &NetworkMember{
				Endpoint:         aMsg.Membership.Endpoint,
				InternalEndpoint: internalEndpoint,
				Metadata:         aMsg.Membership.Metadata,
				PKIid:            pkiID,
			}
		}
	}
}

func (gdi *gossipDiscoveryImpl) learnExistingMembers(aliveArr []*protoext.SignedGossipMessage) {
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
			internalEndpoint = protoext.InternalEndpoint(m.SecretEnvelope)
		}

		gdi.id2Member[pkiID.String()] = &NetworkMember{
			Endpoint:         am.Membership.Endpoint,
			InternalEndpoint: internalEndpoint,
			Metadata:         am.Membership.Metadata,
			PKIid:            pkiID,
		}

		if _, isKnownAsDead := gdi.deadLastTS[pkiID.String()]; isKnownAsDead {
			gdi.logger.Warnf("The member %s has been dead.", protoext.MemberToString(am.Membership))
			continue
		}

		if _, isKnownAsAlive := gdi.aliveLastTS[pkiID.String()]; !isKnownAsAlive {
			gdi.logger.Warnf("The member %s is not alive.", protoext.MemberToString(am.Membership))
			continue
		} else {
			gdi.logger.Debugf("Update alive member: %s.", protoext.AliveMessageToString(am))
			gdi.aliveLastTS[pkiID.String()].incTime = tsToTime(am.Timestamp.IncNum)
			gdi.aliveLastTS[pkiID.String()].seqNum = am.Timestamp.SeqNum
			gdi.aliveLastTS[pkiID.String()].lastSeen = time.Now()

			if old := gdi.aliveMembership.MsgByID(pkiID); old != nil {
				gdi.logger.Debugf("Replace old alive membership %s by new alive membership %s.", protoext.AliveMessageToString(old.GetAliveMsg()), protoext.AliveMessageToString(am))
				gdi.aliveMembership.Remove(pkiID)
				gdi.aliveMembership.Put(pkiID, &protoext.SignedGossipMessage{GossipMessage: m.GossipMessage, Envelope: m.Envelope})
			}
		}
	}
}

func (gdi *gossipDiscoveryImpl) resurrectMember(sgm *protoext.SignedGossipMessage, pt *pgossip.PeerTime) {
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
		internalEndpoint = protoext.InternalEndpoint(sgm.SecretEnvelope)
	}

	gdi.id2Member[pkiID.String()] = &NetworkMember{
		Endpoint:         membership.Endpoint,
		InternalEndpoint: internalEndpoint,
		Metadata:         membership.Metadata,
		PKIid:            pkiID,
	}

	delete(gdi.deadLastTS, pkiID.String())
	gdi.deadMembership.Remove(pkiID)
	gdi.aliveMembership.Put(pkiID, &protoext.SignedGossipMessage{GossipMessage: sgm.GossipMessage, Envelope: sgm.Envelope})
}

func (gdi *gossipDiscoveryImpl) getDeadMembers() []utils.PKIidType {
	gdi.mutex.RLock()
	defer gdi.mutex.RUnlock()

	dead := []utils.PKIidType{}
	for id, last := range gdi.aliveLastTS {
		elapsedNonAliveTime := time.Since(last.lastSeen)
		if elapsedNonAliveTime > gdi.aliveExpirationTimeout {
			gdi.logger.Warnf("Haven't heard from %s for %.2f minutes.", id, elapsedNonAliveTime.Minutes())
			pkiID, _ := hex.DecodeString(id)
			dead = append(dead, utils.PKIidType(pkiID))
		}
	}
	return dead
}

func (gdi *gossipDiscoveryImpl) isSentByMe(m *protoext.SignedGossipMessage) bool {
	pkiID := m.GetAliveMsg().Membership.PkiId
	if !bytes.Equal(gdi.self.PKIid, pkiID) {
		return false
	}
	diffExternalEndpoint := gdi.self.Endpoint != m.GetAliveMsg().Membership.Endpoint
	var diffInternalEndpoint bool
	if m.GetSecretEnvelope() != nil {
		internalEndpoint := protoext.InternalEndpoint(m.GetSecretEnvelope())
		if internalEndpoint != "" {
			diffInternalEndpoint = gdi.self.InternalEndpoint != internalEndpoint
		}
	}

	if diffExternalEndpoint || diffInternalEndpoint {
		gdi.logger.Errorf("Bad configuration detected, received AliveMessage from a peer with the same PKI-ID as myself: %s.", protoext.AliveMessageToString(m.GetAliveMsg()))
	}
	return true
}

func (gdi *gossipDiscoveryImpl) createSignedAliveMessage(includeInternalEndpoint bool) (*protoext.SignedGossipMessage, error) {
	msg, internalEndpoint := gdi.aliveMsgAndInternalEndpoint()
	envelope := gdi.crypt.SignMessage(msg, internalEndpoint)
	if envelope == nil {
		return nil, errors.NewError("failed signing message")
	}
	sgm := &protoext.SignedGossipMessage{
		GossipMessage: msg,
		Envelope:      envelope,
	}
	if !includeInternalEndpoint {
		sgm.SecretEnvelope = nil
	}

	return sgm, nil
}

func (gdi *gossipDiscoveryImpl) createMembershipResponse(aliveMsg *protoext.SignedGossipMessage, targetMember *NetworkMember) *pgossip.MembershipResponse {
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
	var deadMembersToExpire []NetworkMember

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

func (gdi *gossipDiscoveryImpl) copyLastSeen(lastSeenMap map[string]*timestamp) []NetworkMember {
	gdi.mutex.RLock()
	defer gdi.mutex.RUnlock()

	res := []NetworkMember{}
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

func (gdi *gossipDiscoveryImpl) purge(pkiID utils.PKIidType) {
	gdi.logger.Infof("Purging %s from membership.", pkiID.String())
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

func before(a *timestamp, b *pgossip.PeerTime) bool {
	return (uint64(a.incTime.UnixNano()) == b.IncNum && a.seqNum < b.SeqNum) || (uint64(a.incTime.UnixNano()) < b.IncNum)
}
