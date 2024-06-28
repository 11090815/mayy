package discovery

import (
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

// EnvelopeFilter 会过滤掉 SignedGossipMessage 中的部分信息得到一个 Envelope。
type EnvelopeFilter func(message *protoext.SignedGossipMessage) *pgossip.Envelope

// Sieve 决定了是否能将 SignedGossipMessage 发送给远程节点。
type Sieve func(message *protoext.SignedGossipMessage) bool

// DisclosurePolicy 定义了给定的远程对等体有资格了解哪些消息，以及从给定的 SignedGossipMessage 中有资格了解哪些消息。
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
		oldKnown := memReq.Known
		memReq = &pgossip.MembershipRequest{
			SelfInformation: selfMsg.Envelope,
			Known:           oldKnown,
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
	self            NetworkMember
	selfAliveMsg    *protoext.SignedGossipMessage
	port            int
	incTime         uint64
	seqNum          uint64
	deadLastTS      map[string]*timestamp
	crypt           CryptoService
	adapter         DiscoveryAdapter
	logger          mlog.Logger
	mutex           *sync.RWMutex
	aliveMembership *protoext.MembershipStore

	aliveTimeInterval time.Duration // 每隔这段时间

	stopChan chan struct{}
}

type aliveMsgStore struct {
	msgstore.MessageStore
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
	BotstrapPeers                []string
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

func (gdi *gossipDiscoveryImpl) closed() bool {
	select {
	case <-gdi.stopChan:
		return true
	default:
		return false
	}
}
