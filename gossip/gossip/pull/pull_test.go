package pull

import (
	"bytes"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/gossip/algo"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
	"github.com/stretchr/testify/require"
)

var (
	pullInterval    = 500 * time.Millisecond
	timeoutInterval = 20 * time.Second
)

type pullMsg struct {
	respondChan chan *pullMsg
	msg         *utils.SignedGossipMessage
	pkiID       utils.PKIidType
	endpoint    string
}

func (msg *pullMsg) GetSourceEnvelope() *pgossip.Envelope {
	return msg.msg.Envelope
}

func (msg *pullMsg) Respond(m *pgossip.GossipMessage) {
	sgm, _ := utils.NoopSign(m)
	msg.respondChan <- &pullMsg{
		msg:         sgm,
		respondChan: msg.respondChan,
	}
}

func (msg *pullMsg) GetSignedGossipMessage() *utils.SignedGossipMessage {
	return msg.msg
}

func (msg *pullMsg) GetConnectionInfo() *utils.ConnectionInfo {
	return &utils.ConnectionInfo{
		PkiID:    msg.pkiID,
		Endpoint: msg.endpoint,
	}
}

func (msg *pullMsg) Ack(error) {}

type pullInstance struct {
	self          utils.NetworkMember
	mediator      PullMediator
	items         *utils.Set
	msgChan       chan *pullMsg
	peer2PullInst map[string]*pullInstance // endpoint => *pullInstance
	stopChan      chan struct{}
	pullAdapter   *PullAdapter
	config        PullConfig
}

func (p *pullInstance) Send(msg *utils.SignedGossipMessage, peers ...*utils.RemotePeer) {
	for _, peer := range peers {
		m := &pullMsg{
			msg:         msg,
			respondChan: p.msgChan,
			pkiID:       p.self.PKIid,
			endpoint:    p.self.Endpoint,
		}
		p.peer2PullInst[peer.Endpoint].msgChan <- m
	}
}

func (p *pullInstance) GetMembership() utils.Members {
	members := []utils.NetworkMember{}
	for _, peer := range p.peer2PullInst {
		if bytes.Equal(peer.self.PKIid, p.self.PKIid) {
			continue
		}
		members = append(members, peer.self)
	}
	return members
}

func (p *pullInstance) start() {
	p.mediator = NewPullMediator(p.config, p.pullAdapter, utils.GetLogger(utils.PullLogger, p.self.Endpoint, mlog.DebugLevel, true, true))
	go func() {
		for {
			select {
			case <-p.stopChan:
				return
			case msg := <-p.msgChan:
				p.mediator.HandleMessage(msg)
			}
		}
	}()
}

func (p *pullInstance) stop() {
	p.mediator.Stop()
	p.stopChan <- struct{}{}
}

func (p *pullInstance) wrapPullMsg(msg *utils.SignedGossipMessage) utils.ReceivedMessage {
	return &pullMsg{
		msg:         msg,
		respondChan: p.msgChan,
		endpoint:    p.self.Endpoint,
		pkiID:       p.self.PKIid,
	}
}

func createPullInstanceWithFilters(endpoint string, peer2PullInst map[string]*pullInstance, edf EgressDigestFilter, idf IngressDigestFilter) *pullInstance {
	inst := &pullInstance{
		items:         utils.NewSet(),
		stopChan:      make(chan struct{}),
		peer2PullInst: peer2PullInst,
		self:          utils.NetworkMember{Endpoint: endpoint, PKIid: utils.PKIidType(endpoint)},
		msgChan:       make(chan *pullMsg, 10),
	}
	peer2PullInst[endpoint] = inst

	config := PullConfig{
		MsgType: pgossip.PullMsgType_BLOCK_MSG,
		Channel: []byte(""),
		// ID:                endpoint,
		PeerCountToSelect: 3,
		PullInterval:      pullInterval,
		Tag:               pgossip.GossipMessage_EMPTY,
		PullEngineConfig: algo.Config{
			DigestWaitTime:   100 * time.Millisecond,
			RequestWaitTime:  200 * time.Millisecond,
			ResponseWaitTime: 300 * time.Millisecond,
		},
	}
	seqNumFromMsg := func(msg *utils.SignedGossipMessage) string {
		dataMsg := msg.GetDataMsg()
		if dataMsg == nil {
			return ""
		}
		if dataMsg.Payload == nil {
			return ""
		}
		return fmt.Sprintf("%d", dataMsg.Payload.SeqNum)
	}
	blockConsumer := func(msg *utils.SignedGossipMessage) {
		inst.items.Add(msg.GetDataMsg().Payload.SeqNum)
	}
	inst.pullAdapter = &PullAdapter{
		Sender:               inst,
		MembershipService:    inst,
		IdentitfierExtractor: seqNumFromMsg,
		MsgConsumer:          blockConsumer,
		EgressDigestFilter:   edf,
		IngressDigestFilter:  idf,
	}
	inst.config = config

	return inst
}

func createPullInstance(endpoint string, peer2PullInst map[string]*pullInstance) *pullInstance {
	return createPullInstanceWithFilters(endpoint, peer2PullInst, nil, nil)
}

func TestCreateAndStop(t *testing.T) {
	inst := createPullInstance("localhost:2000", make(map[string]*pullInstance))
	inst.start()
	inst.stop()
}

func TestRegisterMsgHook(t *testing.T) {
	peer2pullInst := make(map[string]*pullInstance)
	inst1 := createPullInstance("localhost:2001", peer2pullInst)
	inst2 := createPullInstance("localhost:2002", peer2pullInst)
	inst1.start()
	inst2.start()
	defer inst1.stop()
	defer inst2.stop()

	receivedMsgType := utils.NewSet()

	for _, msgType := range []MsgType{HelloMsgType, RequestMsgType, ResponseMsgType, DigestMsgType} {
		mType := msgType
		inst1.mediator.RegisterMsgHook(mType, func(itemIDs []string, items []*utils.SignedGossipMessage, msg utils.ReceivedMessage) {
			receivedMsgType.Add(mType)
		})
	}

	inst1.mediator.Add(dataMsg(1))
	inst2.mediator.Add(dataMsg(2))

	waitUntilOrFail(t, func() bool { return len(receivedMsgType.ToArray()) == 4 })
}

func TestFilter(t *testing.T) {
	peer2pullInst := make(map[string]*pullInstance)
	eq := func(a, b any) bool {
		return a == b
	}
	df := func(msg utils.ReceivedMessage) func(string) bool {
		if msg.GetSignedGossipMessage().GetDataReq() != nil {
			req := msg.GetSignedGossipMessage().GetDataReq()
			return func(s string) bool {
				return utils.IndexInSlice(utils.BytesToStrings(req.Digests), s, eq) != -1
			}
		}
		return func(s string) bool {
			n, _ := strconv.ParseInt(s, 10, 64)
			return n%2 == 0
		}
	}
	inst1 := createPullInstanceWithFilters("localhost:2001", peer2pullInst, df, nil)
	inst2 := createPullInstance("localhost:2002", peer2pullInst)
	inst1.start()
	inst2.start()
	defer inst1.stop()
	defer inst2.stop()

	inst1.mediator.Add(dataMsg(1))
	inst1.mediator.Add(dataMsg(2))
	inst1.mediator.Add(dataMsg(3))
	inst1.mediator.Add(dataMsg(4))

	waitUntilOrFail(t, func() bool { return inst2.items.Exists(uint64(2)) })
	waitUntilOrFail(t, func() bool { return inst2.items.Exists(uint64(4)) })
	require.False(t, inst2.items.Exists(1))
	require.False(t, inst2.items.Exists(3))
}

func TestAddAndRemove(t *testing.T) {
	peer2pullInst := make(map[string]*pullInstance)
	inst1 := createPullInstance("localhost:2001", peer2pullInst)
	inst2 := createPullInstance("localhost:2002", peer2pullInst)
	inst1.start()
	inst2.start()
	defer inst1.stop()
	defer inst2.stop()

	msgCount := 3

	go func() {
		for i := 0; i < msgCount; i++ {
			time.Sleep(pullInterval)
			inst1.mediator.Add(dataMsg(i))
		}
	}()

	waitUntilOrFail(t, func() bool { return len(inst2.items.ToArray()) == msgCount })

	inst2.mediator.Remove("0")
	inst1.mediator.Remove("0")
	inst2.items.Remove(uint64(0))
	inst1.mediator.Add(dataMsg(10))

	wg := sync.WaitGroup{}
	wg.Add(4)

	inst1.mediator.RegisterMsgHook(HelloMsgType, func(itemIDs []string, items []*utils.SignedGossipMessage, msg utils.ReceivedMessage) {
		wg.Done()
	})

	inst2.mediator.RegisterMsgHook(DigestMsgType, func(itemIDs []string, items []*utils.SignedGossipMessage, msg utils.ReceivedMessage) {
		wg.Done()
	})

	inst1.mediator.RegisterMsgHook(RequestMsgType, func(itemIDs []string, items []*utils.SignedGossipMessage, msg utils.ReceivedMessage) {
		wg.Done()
	})

	inst2.mediator.RegisterMsgHook(ResponseMsgType, func(itemIDs []string, items []*utils.SignedGossipMessage, msg utils.ReceivedMessage) {
		wg.Done()
	})

	wg.Wait()

	require.True(t, inst2.items.Exists(uint64(10)))
	require.False(t, inst2.items.Exists(uint64(0)))
}

func TestDigestsFilter(t *testing.T) {
	idf := createDigestsFilter(2)
	inst1 := createPullInstanceWithFilters("localhost:2001", make(map[string]*pullInstance), nil, idf)
	inst2 := createPullInstance("localhost:2002", make(map[string]*pullInstance))
	inst1ReceivedDigest := int32(0)
	inst1.start()
	inst2.start()
	defer inst1.stop()
	defer inst2.stop()

	inst1.mediator.RegisterMsgHook(DigestMsgType, func(itemIDs []string, items []*utils.SignedGossipMessage, msg utils.ReceivedMessage) {
		if atomic.LoadInt32(&inst1ReceivedDigest) == 1 {
			return
		}
		for i := range itemIDs {
			seqNum, err := strconv.ParseUint(itemIDs[i], 10, 64)
			require.NoError(t, err)
			require.True(t, seqNum >= 2, fmt.Sprintf("%d should be larger than 2", seqNum))
		}
		require.Len(t, itemIDs, 3)
		atomic.StoreInt32(&inst1ReceivedDigest, 1)
	})

	inst2.mediator.Add(dataMsg(1))
	inst2.mediator.Add(dataMsg(2))
	inst2.mediator.Add(dataMsg(3))
	inst2.mediator.Add(dataMsg(4))

	sgm, _ := utils.NoopSign(helloMsg())
	inst2.mediator.HandleMessage(inst1.wrapPullMsg(sgm))
	waitUntilOrFail(t, func() bool { return atomic.LoadInt32(&inst1ReceivedDigest) == 1 })
}

func TestHandleMessage(t *testing.T) {
	inst1 := createPullInstance("localhost:2001", make(map[string]*pullInstance))
	inst2 := createPullInstance("localhost:2002", make(map[string]*pullInstance))
	inst1.start()
	inst2.start()
	defer inst1.stop()
	defer inst2.stop()

	inst2.mediator.Add(dataMsg(1))
	inst2.mediator.Add(dataMsg(2))
	inst2.mediator.Add(dataMsg(3))

	inst1ReceivedDigest := int32(0)
	inst1ReceivedResponse := int32(0)

	inst1.mediator.RegisterMsgHook(DigestMsgType, func(itemIDs []string, items []*utils.SignedGossipMessage, msg utils.ReceivedMessage) {
		if atomic.LoadInt32(&inst1ReceivedDigest) == 1 {
			return
		}
		atomic.AddInt32(&inst1ReceivedDigest, 1)
		require.Len(t, itemIDs, 3)
	})
	inst1.mediator.RegisterMsgHook(ResponseMsgType, func(itemIDs []string, items []*utils.SignedGossipMessage, msg utils.ReceivedMessage) {
		if atomic.LoadInt32(&inst1ReceivedResponse) == 1 {
			return
		}
		atomic.AddInt32(&inst1ReceivedResponse, 1)
		require.Len(t, itemIDs, 3)
	})

	sgm, _ := utils.NoopSign(helloMsg())
	inst2.mediator.HandleMessage(inst1.wrapPullMsg(sgm))

	waitUntilOrFail(t, func() bool { return atomic.LoadInt32(&inst1ReceivedDigest) == 1 })

	sgm, _ = utils.NoopSign(reqMsg("1", "2", "3"))
	inst2.mediator.HandleMessage(inst1.wrapPullMsg(sgm))
	waitUntilOrFail(t, func() bool { return atomic.LoadInt32(&inst1ReceivedResponse) == 1 })

	require.True(t, inst1.items.Exists(uint64(1)))
	require.True(t, inst1.items.Exists(uint64(2)))
	require.True(t, inst1.items.Exists(uint64(3)))
}

func dataMsg(seqNum int) *utils.SignedGossipMessage {
	sgm, _ := utils.NoopSign(&pgossip.GossipMessage{
		Tag: pgossip.GossipMessage_EMPTY,
		Content: &pgossip.GossipMessage_DataMsg{
			DataMsg: &pgossip.DataMessage{
				Payload: &pgossip.Payload{
					Data:   []byte{},
					SeqNum: uint64(seqNum),
				},
			},
		},
	})
	return sgm
}

func waitUntilOrFail(t *testing.T, pred func() bool) {
	start := time.Now()
	limit := start.UnixNano() + timeoutInterval.Nanoseconds()
	for time.Now().UnixNano() < limit {
		if pred() {
			return
		}
		time.Sleep(timeoutInterval / 1000)
	}
	require.Fail(t, "timeout expired")
}

// 过滤掉 seq num 小于 level 的 digest。
func createDigestsFilter(level uint64) IngressDigestFilter {
	return func(digestMsg *pgossip.DataDigest) *pgossip.DataDigest {
		dataDigest := &pgossip.DataDigest{
			MsgType: digestMsg.MsgType,
			Nonce:   digestMsg.Nonce,
		}
		for i := range digestMsg.Digests {
			seqNum, err := strconv.ParseUint(string(digestMsg.Digests[i]), 10, 64)
			if err != nil || seqNum < level {
				continue
			}
			dataDigest.Digests = append(dataDigest.Digests, digestMsg.Digests[i])
		}
		return dataDigest
	}
}

func helloMsg() *pgossip.GossipMessage {
	return &pgossip.GossipMessage{
		Tag: pgossip.GossipMessage_EMPTY,
		Content: &pgossip.GossipMessage_Hello{
			Hello: &pgossip.GossipHello{
				MsgType: pgossip.PullMsgType_BLOCK_MSG,
			},
		},
	}
}

func reqMsg(digest ...string) *pgossip.GossipMessage {
	return &pgossip.GossipMessage{
		Tag: pgossip.GossipMessage_EMPTY,
		Content: &pgossip.GossipMessage_DataReq{
			DataReq: &pgossip.DataRequest{
				MsgType: pgossip.PullMsgType_BLOCK_MSG,
				Digests: utils.StringsToBytes(digest),
			},
		},
	}
}
