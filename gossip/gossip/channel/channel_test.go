package channel

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/metrics/disabled"
	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/gossip/algo"
	"github.com/11090815/mayy/gossip/metrics"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pcommon"
	"github.com/11090815/mayy/protobuf/pgossip"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var (
	shortenedWaitTime = time.Millisecond * 300
	conf              = Config{
		MaxBlockCountToStore:           100,
		PullPeerNum:                    3,
		PullInterval:                   time.Second,
		RequestStateInfoInterval:       time.Millisecond * 100,
		PublishStateInfoInterval:       time.Millisecond * 100,
		BlockExpirationTimeout:         time.Second * 6,
		StateInfoCacheSweepInterval:    time.Second,
		TimeForMembershipTracker:       time.Second * 5,
		LeadershipMsgExpirationTimeout: DefaultLeadershipMsgExpirationTimeout,
		PullEngineConfig: algo.Config{
			DigestWaitTime:   shortenedWaitTime / 2,
			RequestWaitTime:  shortenedWaitTime,
			ResponseWaitTime: shortenedWaitTime,
		},
	}
)

var (
	disabledMetrics = metrics.NewGossipMetrics(&disabled.Provider{}).MembershipMetrics
	logger          = mlog.GetTestLogger("gossip.channel", mlog.DebugLevel, true)
)

var (
	// "Channel-A"
	channelA = utils.ChannelID("Channel-A")
	// "ORG1"
	orgInChannelA = utils.OrgIdentityType("ORG1")
	// "ORG2"
	orgNotInChannelA = utils.OrgIdentityType("ORG2")
	// "pkiIDInOrg1"
	pkiIDInOrg1 = utils.PKIidType("pkiIDInOrg1")
	// "pkiIDnilOrg"
	pkiIDnilOrg = utils.PKIidType("pkiIDnilOrg")
	// "pkiIDInOrg1ButNotEligible"
	pkiIDInOrg1ButNotEligible = utils.PKIidType("pkiIDInOrg1ButNotEligible")
	// "pkiIDInOrg2"
	pkiIDInOrg2 = utils.PKIidType("pkiIDInOrg2")
)

/* ------------------------------------------------------------------------------------------ */

type msgMutator func(message *pgossip.Envelope)

/* ------------------------------------------------------------------------------------------ */

type joinChanMsg struct {
	getTS            func() time.Time
	orgs2AnchorPeers map[string][]utils.AnchorPeer
}

func (jcm *joinChanMsg) SequenceNumber() uint64 {
	if jcm.getTS != nil {
		return uint64(jcm.getTS().UnixNano())
	}
	return uint64(time.Now().UnixNano())
}

func (jcm *joinChanMsg) Orgs() []utils.OrgIdentityType {
	if jcm.orgs2AnchorPeers == nil {
		return []utils.OrgIdentityType{orgInChannelA}
	}
	orgs := make([]utils.OrgIdentityType, len(jcm.orgs2AnchorPeers))
	i := 0
	for org := range jcm.orgs2AnchorPeers {
		orgs[i] = utils.StringToOrgIdentityType(org)
		i++
	}
	return orgs
}

func (jcm *joinChanMsg) AnchorPeersOf(org utils.OrgIdentityType) []utils.AnchorPeer {
	if jcm.orgs2AnchorPeers == nil {
		return []utils.AnchorPeer{}
	}
	return jcm.orgs2AnchorPeers[org.String()]
}

type cryptoService struct {
	mocked bool
	mock.Mock
}

func (cs *cryptoService) Expiration(peerIdentity utils.PeerIdentityType) (time.Time, error) {
	return time.Now().Add(time.Hour), nil
}

func (cs *cryptoService) GetPKIidOfCert(identity utils.PeerIdentityType) utils.PKIidType {
	return utils.PKIidType(identity)
}

func (cs *cryptoService) VerifyByChannel(channel utils.ChannelID, identity utils.PeerIdentityType, _, _ []byte) error {
	if !cs.mocked {
		return nil
	}
	args := cs.Called(identity)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(error)
}

func (cs *cryptoService) VerifyBlock(channelID utils.ChannelID, seqNum uint64, block *pcommon.Block) error {
	args := cs.Called(block)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(error)
}

func (cs *cryptoService) VerifyBlockAttestation(channelID utils.ChannelID, block *pcommon.Block) error {
	panic("not implemented")
}

func (cs *cryptoService) Sign(msg []byte) ([]byte, error) {
	panic("not implemented")
}

func (cs *cryptoService) Verify(identity utils.PeerIdentityType, signature, message []byte) error {
	panic("not implemented")
}

func (cs *cryptoService) ValidateIdentity(identity utils.PeerIdentityType) error {
	panic("not implemented")
}

/* ------------------------------------------------------------------------------------------ */

type receivedMsg struct {
	pkiID utils.PKIidType
	msg   *utils.SignedGossipMessage
	mock.Mock
}

func (rm *receivedMsg) GetSourceEnvelope() *pgossip.Envelope {
	return rm.msg.Envelope
}

func (rm *receivedMsg) GetSignedGossipMessage() *utils.SignedGossipMessage {
	return rm.msg
}

func (rm *receivedMsg) Respond(msg *pgossip.GossipMessage) {
	rm.Called(msg)
}

func (rm *receivedMsg) Ack(err error) {

}

func (rm *receivedMsg) GetConnectionInfo() *utils.ConnectionInfo {
	return &utils.ConnectionInfo{
		PkiID: rm.pkiID,
	}
}

/* ------------------------------------------------------------------------------------------ */

type gossipAdapterMock struct {
	signCallCount uint32
	mock.Mock
	sync.RWMutex
}

func (gam *gossipAdapterMock) On(method string, args ...any) *mock.Call {
	gam.Lock()
	defer gam.Unlock()
	return gam.Mock.On(method, args...)
}

func (gam *gossipAdapterMock) Sign(msg *pgossip.GossipMessage) (*utils.SignedGossipMessage, error) {
	atomic.AddUint32(&gam.signCallCount, 1)
	return utils.NoopSign(msg)
}

func (gam *gossipAdapterMock) GetConf() Config {
	args := gam.Called()
	return args.Get(0).(Config)
}

func (gam *gossipAdapterMock) Gossip(msg *utils.SignedGossipMessage) {
	gam.Called(msg)
}

func (gam *gossipAdapterMock) Forward(msg utils.ReceivedMessage) {
	gam.Called(msg)
}

func (gam *gossipAdapterMock) DeMultiplex(msg any) {
	gam.Called(msg)
}

func (gam *gossipAdapterMock) GetMembership() utils.Members {
	args := gam.Called()
	val := args.Get(0)
	if fn, isFunc := val.(func() utils.Members); isFunc {
		return fn()
	}
	members := val.(utils.Members)
	return members
}

func (gam *gossipAdapterMock) Lookup(pkiID utils.PKIidType) *utils.NetworkMember {
	if !gam.wasMocked("Lookup") {
		return &utils.NetworkMember{}
	}
	args := gam.Called(pkiID)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*utils.NetworkMember)
}

func (gam *gossipAdapterMock) Send(msg *utils.SignedGossipMessage, peers ...*utils.RemotePeer) {
	if !gam.wasMocked("Send") {
		return
	}
	gam.Called(msg, peers)
}

func (gam *gossipAdapterMock) ValidateStateInfoMessage(msg *utils.SignedGossipMessage) error {
	args := gam.Called(msg)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(error)
}

func (gam *gossipAdapterMock) GetOrgOfPeer(pkiID utils.PKIidType) utils.OrgIdentityType {
	args := gam.Called(pkiID)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(utils.OrgIdentityType)
}

func (gam *gossipAdapterMock) GetIdentityByPKIID(pkiID utils.PKIidType) utils.PeerIdentityType {
	if gam.wasMocked("GetIdentityByPKIID") {
		return gam.Called(pkiID).Get(0).(utils.PeerIdentityType)
	}
	return utils.PeerIdentityType(pkiID)
}

func (gam *gossipAdapterMock) wasMocked(method string) bool {
	gam.RLock()
	defer gam.RUnlock()
	for _, ec := range gam.ExpectedCalls {
		if ec.Method == method {
			return true
		}
	}
	return false
}

/* ------------------------------------------------------------------------------------------ */

func sequence(start uint64, end uint64) []uint64 {
	seqs := make([]uint64, end-start+1)
	i := 0
	for n := start; n <= end; n++ {
		seqs[i] = n
		i++
	}
	return seqs
}

func configureAdapter(adapter *gossipAdapterMock, members utils.Members) {
	adapter.On("GetConf").Return(conf)
	adapter.On("GetMembership").Return(members)
	adapter.On("GetOrgOfPeer", pkiIDInOrg1).Return(orgInChannelA)
	adapter.On("GetOrgOfPeer", pkiIDInOrg1ButNotEligible).Return(orgInChannelA)
	adapter.On("GetOrgOfPeer", pkiIDInOrg2).Return(orgNotInChannelA)
	adapter.On("GetOrgOfPeer", pkiIDnilOrg).Return(nil)
	adapter.On("GetOrgOfPeer", mock.Anything).Return(utils.OrgIdentityType(nil))
}

func createStateInfoMsg(ledgerHeight uint64, pkiID utils.PKIidType, channel utils.ChannelID) *utils.SignedGossipMessage {
	sgm, _ := utils.NoopSign(&pgossip.GossipMessage{
		Tag:     pgossip.GossipMessage_CHAN_OR_ORG,
		Channel: channel,
		Content: &pgossip.GossipMessage_StateInfo{
			StateInfo: &pgossip.StateInfo{
				Channel_MAC: utils.GenerateMAC(pkiID, channel),
				Timestamp:   &pgossip.PeerTime{IncNum: uint64(time.Now().UnixNano()), SeqNum: 1},
				PkiId:       pkiID,
				Properties: &pgossip.Properties{
					LedgerHeight: ledgerHeight,
				},
			},
		},
	})
	return sgm
}

func stateInfoSnapshotForChannel(channel utils.ChannelID, stateInfoMsgs ...*utils.SignedGossipMessage) *utils.SignedGossipMessage {
	envelopes := make([]*pgossip.Envelope, len(stateInfoMsgs))
	for i, info := range stateInfoMsgs {
		envelopes[i] = info.Envelope
	}
	sgm, _ := utils.NoopSign(&pgossip.GossipMessage{
		Channel: channel,
		Tag:     pgossip.GossipMessage_CHAN_OR_ORG,
		Nonce:   0,
		Content: &pgossip.GossipMessage_StateInfoSnapshot{
			StateInfoSnapshot: &pgossip.StateInfoSnapshot{
				Elements: envelopes,
			},
		},
	})
	return sgm
}

func createDataMsg(seqnum uint64, channels ...utils.ChannelID) *utils.SignedGossipMessage {
	var channel utils.ChannelID
	if len(channels) == 1 {
		channel = channels[0]
	}
	sgm, _ := utils.NoopSign(&pgossip.GossipMessage{
		Tag:     pgossip.GossipMessage_CHAN_AND_ORG,
		Channel: channel,
		Content: &pgossip.GossipMessage_DataMsg{
			DataMsg: &pgossip.DataMessage{
				Payload: &pgossip.Payload{
					SeqNum: seqnum,
					Data:   []byte{},
				},
			},
		},
	})
	return sgm
}

func createHelloMsg(pkiID utils.PKIidType) *receivedMsg {
	sgm, _ := utils.NoopSign(&pgossip.GossipMessage{
		Channel: channelA,
		Tag:     pgossip.GossipMessage_CHAN_AND_ORG,
		Content: &pgossip.GossipMessage_Hello{
			Hello: &pgossip.GossipHello{
				Nonce:    500,
				Metadata: nil,
				MsgType:  pgossip.PullMsgType_BLOCK_MSG,
			},
		},
	})
	return &receivedMsg{msg: sgm, pkiID: pkiID}
}

func createDataUpdateMsg(nonce uint64, seqs ...uint64) *utils.SignedGossipMessage {
	msg := &pgossip.GossipMessage{
		Nonce:   0,
		Channel: channelA,
		Tag:     pgossip.GossipMessage_CHAN_AND_ORG,
		Content: &pgossip.GossipMessage_DataUpdate{
			DataUpdate: &pgossip.DataUpdate{
				MsgType: pgossip.PullMsgType_BLOCK_MSG,
				Nonce:   nonce,
				Data:    []*pgossip.Envelope{},
			},
		},
	}
	for _, seq := range seqs {
		msg.GetDataUpdate().Data = append(msg.GetDataUpdate().Data, createDataMsg(seq, channelA).Envelope)
	}
	sgm, _ := utils.NoopSign(msg)
	return sgm
}

func simulatePullPhaseWithVariableDigest(gc GossipChannel, t *testing.T, wg *sync.WaitGroup, mutator msgMutator, proposedDigestSeqs [][]byte, resultDigestSeqs []string, seqs ...uint64) func(args mock.Arguments) {
	var mutex sync.Mutex
	var sentHello bool
	var sentReq bool

	return func(args mock.Arguments) {
		msg := args.Get(0).(*utils.SignedGossipMessage)
		mutex.Lock()
		defer mutex.Unlock()
		if msg.GetHello() != nil && !sentHello {
			sentHello = true
			sgm, _ := utils.NoopSign(&pgossip.GossipMessage{
				Tag:     pgossip.GossipMessage_CHAN_AND_ORG,
				Channel: channelA,
				Content: &pgossip.GossipMessage_DataDig{
					DataDig: &pgossip.DataDigest{
						MsgType: pgossip.PullMsgType_BLOCK_MSG,
						Digests: proposedDigestSeqs,
						Nonce:   msg.GetHello().Nonce,
					},
				},
			})
			digestMsg := &receivedMsg{
				pkiID: pkiIDInOrg1,
				msg:   sgm,
			}
			go gc.HandleMessage(digestMsg)
		}
		if msg.GetDataReq() != nil && !sentReq {
			sentReq = true
			dataReq := msg.GetDataReq()
			for _, expectedDigest := range utils.StringsToBytes(resultDigestSeqs) {
				require.Contains(t, dataReq.Digests, expectedDigest)
			}
			require.Equal(t, len(resultDigestSeqs), len(dataReq.Digests))

			dataUpdateMsg := new(receivedMsg)
			dataUpdateMsg.pkiID = pkiIDInOrg1
			dataUpdateMsg.msg = createDataUpdateMsg(dataReq.Nonce, seqs...)
			mutator(dataUpdateMsg.msg.GetDataUpdate().Data[0])
			gc.HandleMessage(dataUpdateMsg)
			wg.Done()
		}
	}
}

func simulatePullPhase(gc GossipChannel, t *testing.T, wg *sync.WaitGroup, mutator msgMutator, seqs ...uint64) func(args mock.Arguments) {
	return simulatePullPhaseWithVariableDigest(gc, t, wg, mutator, [][]byte{[]byte("10"), []byte("11")}, []string{"10", "11"}, seqs...)
}

/* ------------------------------------------------------------------------------------------ */

func TestBadInput(t *testing.T) {
	cs := &cryptoService{}
	adapter := new(gossipAdapterMock)
	configureAdapter(adapter, nil)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Send", mock.Anything, mock.Anything)
	adapter.On("DeMultiplex", mock.Anything)
	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger).(*gossipChannel)
	require.False(t, gc.verifyMsg(nil))
	require.False(t, gc.verifyMsg(&receivedMsg{msg: nil, pkiID: nil}))
	time.Sleep(time.Millisecond)
}

func TestSelf(t *testing.T) {
	cs := &cryptoService{}
	pkiID1 := utils.PKIidType("1")
	jcm := &joinChanMsg{
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			orgInChannelA.String(): {},
		},
	}
	adapter := new(gossipAdapterMock)
	configureAdapter(adapter, nil)
	adapter.On("Gossip", mock.Anything)
	gc := NewGossipChannel(pkiID1, orgInChannelA, cs, channelA, adapter, jcm, disabledMetrics, logger)
	gc.UpdateLedgerHeight(1)
	msg := gc.Self().GossipMessage
	envelope := gc.Self().Envelope
	sgm, _ := utils.EnvelopeToSignedGossipMessage(envelope)
	require.True(t, proto.Equal(msg, sgm.GossipMessage))
	require.Equal(t, msg.GetStateInfo().Properties.LedgerHeight, uint64(1))
	require.Equal(t, msg.GetStateInfo().PkiId, []byte("1"))
}

func TestMsgStoreNotExpire(t *testing.T) {
	cs := &cryptoService{}

	pkiID1 := utils.PKIidType("1")
	pkiID2 := utils.PKIidType("2")
	pkiID3 := utils.PKIidType("3")

	peer1 := utils.NetworkMember{PKIid: pkiID1, InternalEndpoint: "1", Endpoint: "1"}
	peer2 := utils.NetworkMember{PKIid: pkiID2, InternalEndpoint: "2", Endpoint: "2"}
	peer3 := utils.NetworkMember{PKIid: pkiID3, InternalEndpoint: "3", Endpoint: "3"}

	jcm := &joinChanMsg{
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			orgInChannelA.String(): {},
		},
	}

	adapter := new(gossipAdapterMock)
	adapter.On("GetOrgOfPeer", pkiID1).Return(orgInChannelA)
	adapter.On("GetOrgOfPeer", pkiID2).Return(orgInChannelA)
	adapter.On("GetOrgOfPeer", pkiID3).Return(orgInChannelA)
	adapter.On("ValidateStateInfoMessage", mock.Anything).Return(nil)
	adapter.On("GetMembership").Return((utils.Members([]utils.NetworkMember{peer2, peer3})))
	adapter.On("DeMultiplex", mock.Anything)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("GetConf").Return(conf)

	gc := NewGossipChannel(pkiID1, orgInChannelA, cs, channelA, adapter, jcm, disabledMetrics, logger)
	gc.UpdateLedgerHeight(1)
	gc.HandleMessage(&receivedMsg{pkiID: pkiID2, msg: createStateInfoMsg(1, pkiID2, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiID3, msg: createStateInfoMsg(1, pkiID3, channelA)})
	time.Sleep(adapter.GetConf().PublishStateInfoInterval * 2)

	simulateStateInfoRequest := func(pkiID []byte, outChan chan *utils.SignedGossipMessage) {
		sentMessages := make(chan *pgossip.GossipMessage, 1)
		sgm, _ := utils.NoopSign(&pgossip.GossipMessage{
			Tag:     pgossip.GossipMessage_CHAN_OR_ORG,
			Channel: channelA,
			Content: &pgossip.GossipMessage_StateInfoPullReq{
				StateInfoPullReq: &pgossip.StateInfoPullRequest{
					Channel_MAC: utils.GenerateMAC(pkiID, channelA),
				},
			},
		})
		snapshotReq := &receivedMsg{
			pkiID: pkiID,
			msg:   sgm,
		}
		snapshotReq.On("Respond", mock.Anything).Run(func(args mock.Arguments) {
			sentMessages <- args.Get(0).(*pgossip.GossipMessage)
		})

		go gc.HandleMessage(snapshotReq)
		select {
		case <-time.After(time.Second):
			t.Fatal("Haven't received a state info snapshot on time")
		case msg := <-sentMessages:
			for _, envelope := range msg.GetStateInfoSnapshot().Elements {
				sgm, err := utils.EnvelopeToSignedGossipMessage(envelope)
				require.NoError(t, err)
				outChan <- sgm
			}
		}
	}
	c := make(chan *utils.SignedGossipMessage, 3)
	simulateStateInfoRequest(pkiID2, c)
	require.Len(t, c, 3)

	c = make(chan *utils.SignedGossipMessage, 3)
	simulateStateInfoRequest(pkiID3, c)
	require.Len(t, c, 3)

	adapter.On("Lookup", pkiID1).Return(&peer1)
	adapter.On("Lookup", pkiID2).Return(&peer2)
	adapter.On("Lookup", pkiID3).Return(nil)

	time.Sleep(conf.StateInfoCacheSweepInterval * 2)

	c = make(chan *utils.SignedGossipMessage, 3)
	simulateStateInfoRequest(pkiID2, c)
	require.Len(t, c, 2)

	c = make(chan *utils.SignedGossipMessage, 3)
	simulateStateInfoRequest(pkiID3, c)
	require.Len(t, c, 2)
}

func TestLeaveChannel(t *testing.T) {
	jcm := &joinChanMsg{
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			"ORG1": {},
			"ORG2": {},
		},
	}

	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)
	adapter := new(gossipAdapterMock)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("DeMultiplex", mock.Anything)
	members := make(utils.Members, 2)
	members[0] = utils.NetworkMember{PKIid: pkiIDInOrg1}
	members[1] = utils.NetworkMember{PKIid: pkiIDInOrg2}

	var helloPullWG sync.WaitGroup
	helloPullWG.Add(1)

	configureAdapter(adapter, members)
	gc := NewGossipChannel(utils.PKIidType("p0"), orgInChannelA, cs, channelA, adapter, jcm, disabledMetrics, logger)
	adapter.On("Send", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		msg := args.Get(0).(*utils.SignedGossipMessage)
		if utils.IsPullMsg(msg.GossipMessage) {
			helloPullWG.Done()
			require.False(t, gc.(*gossipChannel).hasLeftChannel())
		}
	})

	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(1, pkiIDInOrg1, channelA)})
	time.Sleep(time.Millisecond * 10)
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg2, msg: createStateInfoMsg(1, pkiIDInOrg2, channelA)})
	time.Sleep(time.Millisecond * 10)
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createDataMsg(2, channelA)})
	time.Sleep(time.Millisecond * 10)
	require.Len(t, gc.GetPeers(), 1)

	require.Equal(t, pkiIDInOrg1, gc.GetPeers()[0].PKIid)
	var digestSendTime int32
	var DigestSentWG sync.WaitGroup
	DigestSentWG.Add(1)
	hello := createHelloMsg(pkiIDInOrg1)
	hello.On("Respond", mock.Anything).Run(func(args mock.Arguments) {
		atomic.AddInt32(&digestSendTime, 1)
		require.Equal(t, int32(1), atomic.LoadInt32(&digestSendTime))
		DigestSentWG.Done()
	})
	helloPullWG.Wait()
	go gc.HandleMessage(hello)
	DigestSentWG.Wait()
	gc.LeaveChannel()
	go gc.HandleMessage(hello)
	require.Len(t, gc.GetPeers(), 0)
	time.Sleep(conf.PullInterval * 3)
}

func TestChannelPeriodicalPublishStateInfo(t *testing.T) {
	ledgerHeight := 5
	receivedMsgCount := int32(0)
	stateInfoReceptionChan := make(chan *utils.SignedGossipMessage, 1)

	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)

	peerA := utils.NetworkMember{
		PKIid:            pkiIDInOrg1,
		Endpoint:         "127.0.0.1",
		InternalEndpoint: "localhost",
	}
	members := utils.Members{}
	members = append(members, peerA)

	adapter := new(gossipAdapterMock)
	configureAdapter(adapter, members)
	adapter.On("Send", mock.Anything, mock.Anything)
	adapter.On("Gossip", mock.Anything).Run(func(args mock.Arguments) {
		if atomic.LoadInt32(&receivedMsgCount) == int32(1) {
			return
		}
		atomic.StoreInt32(&receivedMsgCount, 1)
		msg := args.Get(0).(*utils.SignedGossipMessage)
		stateInfoReceptionChan <- msg
	})

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	gc.UpdateLedgerHeight(uint64(ledgerHeight))
	defer gc.Stop()

	var msg *utils.SignedGossipMessage
	select {
	case <-time.After(time.Second * 5):
		t.Fatal("Haven't sent state info on time")
	case m := <-stateInfoReceptionChan:
		msg = m
	}
	require.Equal(t, ledgerHeight, int(msg.GetStateInfo().Properties.LedgerHeight))
}

func TestChannelMsgStoreEviction(t *testing.T) {
	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)

	adapter := new(gossipAdapterMock)
	peerA := utils.NetworkMember{
		PKIid:            pkiIDInOrg1,
		Endpoint:         "127.0.0.1",
		InternalEndpoint: "localhost",
	}
	members := utils.Members{}
	members = append(members, peerA)
	configureAdapter(adapter, members)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("DeMultiplex", mock.Anything).Run(func(args mock.Arguments) {})

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	defer gc.Stop()
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(100, pkiIDInOrg1, channelA)})

	var wg sync.WaitGroup

	msgsPerPhase := uint64(50)
	lastPullPhase := make(chan uint64, msgsPerPhase)
	totalPhases := uint64(4)
	phaseNum := uint64(0)
	wg.Add(int(totalPhases))

	adapter.On("Send", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		msg := args.Get(0).(*utils.SignedGossipMessage)
		if !utils.IsPullMsg(msg.GossipMessage) {
			return
		}

		if atomic.LoadUint64(&phaseNum) == totalPhases && msg.GetHello() != nil {
			return
		}

		start := atomic.LoadUint64(&phaseNum) * msgsPerPhase
		end := start + msgsPerPhase

		if msg.GetHello() != nil {
			atomic.AddUint64(&phaseNum, 1)
		}

		currSeq := sequence(start, end)
		pullPhase := simulatePullPhase(gc, t, &wg, func(message *pgossip.Envelope) {}, currSeq...)
		pullPhase(args)

		if msg.GetDataReq() != nil && atomic.LoadUint64(&phaseNum) == totalPhases {
			for _, seq := range currSeq {
				lastPullPhase <- seq
			}
			close(lastPullPhase)
		}
	})
	wg.Wait()

	msgSentFromPullMediator := make(chan *pgossip.GossipMessage, 1)
	helloMsg := createHelloMsg(pkiIDInOrg1)
	helloMsg.On("Respond", mock.Anything).Run(func(args mock.Arguments) {
		msg := args.Get(0).(*pgossip.GossipMessage)
		if msg.GetDataDig() == nil {
			return
		}
		msgSentFromPullMediator <- msg
	})
	gc.HandleMessage(helloMsg)
	select {
	case msg := <-msgSentFromPullMediator:
		msgSentFromPullMediator <- msg
	case <-time.After(time.Second * 5):
		t.Fatal("Didn't reply with a digest on time")
	}

	require.Len(t, msgSentFromPullMediator, 1)
	msg := <-msgSentFromPullMediator
	require.True(t, msg.GetDataDig() != nil)
	require.Len(t, msg.GetDataDig().Digests, adapter.GetConf().MaxBlockCountToStore+1)
	for seq := range lastPullPhase {
		require.Contains(t, msg.GetDataDig().Digests, []byte(fmt.Sprintf("%d", seq)))
	}
}

func TestChannelPull(t *testing.T) {
	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)

	receivedBlockChan := make(chan *utils.SignedGossipMessage, 2)

	members := new(utils.Members)
	*members = append(*members, utils.NetworkMember{PKIid: pkiIDInOrg1})
	adapter := new(gossipAdapterMock)
	configureAdapter(adapter, *members)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("DeMultiplex", mock.Anything).Run(func(args mock.Arguments) {
		sgm := args.Get(0).(*utils.SignedGossipMessage)
		if sgm.GetDataMsg() != nil {
			receivedBlockChan <- sgm
		}
	})
	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	go gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(100, pkiIDInOrg1, channelA)})

	var wg sync.WaitGroup
	wg.Add(1)
	pullPhase := simulatePullPhase(gc, t, &wg, func(message *pgossip.Envelope) {}, 10, 11)
	adapter.On("Send", mock.Anything, mock.Anything).Run(pullPhase)
	wg.Wait()
	for expectedSeq := 10; expectedSeq <= 11; expectedSeq++ {
		select {
		case <-time.After(time.Second * 5):
			t.Fatal("Haven't received blocks on time")
		case msg := <-receivedBlockChan:
			require.Equal(t, uint64(expectedSeq), msg.GetDataMsg().Payload.SeqNum)
		}
	}
}

func TestChannelPullAccessControl(t *testing.T) {
	cs := &cryptoService{}
	adapter := new(gossipAdapterMock)
	cs.On("VerifyBlock", mock.Anything).Return(nil)
	pkiID1 := utils.PKIidType("1")
	pkiID2 := utils.PKIidType("2")
	pkiID3 := utils.PKIidType("3")
	peer1 := utils.NetworkMember{PKIid: pkiID1, InternalEndpoint: "1"}
	peer2 := utils.NetworkMember{PKIid: pkiID2, InternalEndpoint: "2"}
	peer3 := utils.NetworkMember{PKIid: pkiID3, InternalEndpoint: "3"}
	members := utils.Members{}
	members = append(members, []utils.NetworkMember{peer1, peer2, peer3}...)

	adapter.On("GetOrgOfPeer", pkiID1).Return(orgInChannelA)
	adapter.On("GetOrgOfPeer", pkiID2).Return(orgNotInChannelA)
	adapter.On("GetOrgOfPeer", pkiID3).Return(orgNotInChannelA)
	configureAdapter(adapter, members)
	adapter.On("DeMultiplex", mock.Anything)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)

	sentHello := int32(0)
	adapter.On("Send", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		msg := args.Get(0).(*utils.SignedGossipMessage)
		if msg.GetHello() != nil {
			atomic.StoreInt32(&sentHello, 1)
			peerID := string(args.Get(1).([]*utils.RemotePeer)[0].PKIID)
			require.Equal(t, "1", peerID)
			require.NotEqual(t, "2", peerID)
			require.NotEqual(t, "3", peerID)
		}
	})

	joinMsg := &joinChanMsg{
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			"ORG1": {},
			"ORG2": {},
		},
	}

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, joinMsg, disabledMetrics, logger)
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(100, pkiIDInOrg1, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiID1, msg: createStateInfoMsg(100, pkiID1, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiID2, msg: createStateInfoMsg(100, pkiID2, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiID3, msg: createStateInfoMsg(100, pkiID3, channelA)})

	responsedChan := make(chan *pgossip.GossipMessage, 1)
	messageRelayer := func(args mock.Arguments) {
		msg := args.Get(0).(*pgossip.GossipMessage)
		responsedChan <- msg
	}

	gc.HandleMessage(&receivedMsg{msg: createDataMsg(5, channelA), pkiID: pkiIDInOrg1})

	helloMsg := createHelloMsg(pkiID1)
	helloMsg.On("Respond", mock.Anything).Run(messageRelayer)
	go gc.HandleMessage(helloMsg)
	select {
	case <-responsedChan:
	case <-time.After(time.Second):
		require.Fail(t, "Didn't reply to a hello within a timely manner")
	}

	helloMsg = createHelloMsg(pkiID2)
	helloMsg.On("Respond", mock.Anything).Run(messageRelayer)
	go gc.HandleMessage(helloMsg)
	select {
	case <-responsedChan:
		require.Fail(t, "Should not reply to a hello message, because the hello message from a peer who is from a foreign org")
	case <-time.After(time.Second):
	}

	helloMsg = createHelloMsg(pkiID3)
	helloMsg.On("Respond", mock.Anything).Run(messageRelayer)
	go gc.HandleMessage(helloMsg)
	select {
	case <-responsedChan:
		require.Fail(t, "Should not reply to a hello message, because the hello message from a peer who is from a foreign org")
	case <-time.After(time.Second):
	}

	time.Sleep(time.Second * 3)
	require.Equal(t, sentHello, int32(1))
}

func TestChannelPeerNotInChannel(t *testing.T) {
	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)

	gossipMessagesSentFromChannel := make(chan *pgossip.GossipMessage, 1)

	adapter := new(gossipAdapterMock)
	configureAdapter(adapter, nil)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("Send", mock.Anything, mock.Anything)
	adapter.On("DeMultiplex", mock.Anything)

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)

	gc.HandleMessage(&receivedMsg{msg: createDataMsg(5, channelA)})
	require.Equal(t, 0, gc.(*gossipChannel).blockMsgStore.Size())

	gc.HandleMessage(&receivedMsg{msg: createDataMsg(5, channelA), pkiID: pkiIDInOrg2})
	require.Equal(t, 0, gc.(*gossipChannel).blockMsgStore.Size())

	gc.HandleMessage(&receivedMsg{msg: createDataMsg(5, channelA), pkiID: pkiIDInOrg1})
	require.Equal(t, 1, gc.(*gossipChannel).blockMsgStore.Size())

	messageRelayer := func(args mock.Arguments) {
		msg := args.Get(0).(*pgossip.GossipMessage)
		gossipMessagesSentFromChannel <- msg
	}

	gc.HandleMessage(&receivedMsg{msg: createStateInfoMsg(10, pkiIDInOrg1, channelA), pkiID: pkiIDInOrg1})
	helloMsg := createHelloMsg(pkiIDInOrg1)
	helloMsg.On("Respond", mock.Anything).Run(messageRelayer)
	gc.HandleMessage(helloMsg)
	select {
	case <-gossipMessagesSentFromChannel:
	case <-time.After(time.Second):
		require.Fail(t, "Didn't reply to a hello within a timely manner")
	}

	helloMsg = createHelloMsg(pkiIDInOrg2)
	helloMsg.On("Respond", mock.Anything).Run(messageRelayer)
	gc.HandleMessage(helloMsg)
	select {
	case <-gossipMessagesSentFromChannel:
		require.Fail(t, "Should not reply to a hello message, because the hello message from a peer who is from a foreign channel")
	case <-time.After(time.Second):
	}

	gc.HandleMessage(&receivedMsg{msg: createStateInfoMsg(10, pkiIDInOrg1ButNotEligible, channelA), pkiID: pkiIDInOrg1ButNotEligible})
	cs.On("VerifyByChannel", mock.Anything).Return(errors.NewError("not eligible"))
	cs.mocked = true
	gc.ConfigureChannel(&joinChanMsg{})
	helloMsg = createHelloMsg(pkiIDInOrg1ButNotEligible)
	helloMsg.On("Respond", mock.Anything).Run(messageRelayer)
	gc.HandleMessage(helloMsg)
	select {
	case <-gossipMessagesSentFromChannel:
		require.Fail(t, "Should not reply to a hello message, because the hello message from a peer who is not eligible for the channel")
	case <-time.After(time.Second):
	}

	cs.Mock = mock.Mock{}

	req, _ := gc.(*gossipChannel).createStateInfoRequest()
	validReceivedMsg := &receivedMsg{
		msg:   req,
		pkiID: pkiIDInOrg1,
	}
	validReceivedMsg.On("Respond", mock.Anything).Run(messageRelayer)
	gc.HandleMessage(validReceivedMsg)
	select {
	case <-gossipMessagesSentFromChannel:
	case <-time.After(time.Second):
		require.Fail(t, "Didn't reply to a hello within a timely manner")
	}

	invalidReceivedMsg := &receivedMsg{
		msg:   req,
		pkiID: pkiIDInOrg2,
	}
	invalidReceivedMsg.On("Respond", mock.Anything).Run(messageRelayer)
	gc.HandleMessage(invalidReceivedMsg)
	select {
	case <-gossipMessagesSentFromChannel:
		require.Fail(t, "Should not reply to a request message, because the request message from a peer who is from a foreign org")
	case <-time.After(time.Second):
	}

	req2, _ := gc.(*gossipChannel).createStateInfoRequest()
	req2.GetStateInfoPullReq().Channel_MAC = utils.GenerateMAC(pkiIDInOrg1, utils.ChannelID{'a'})
	invalidReceivedMsg2 := &receivedMsg{
		msg:   req2,
		pkiID: pkiIDInOrg1,
	}
	invalidReceivedMsg2.On("Respond", mock.Anything).Run(messageRelayer)
	gc.HandleMessage(invalidReceivedMsg2)
	select {
	case <-gossipMessagesSentFromChannel:
		require.Fail(t, "Should not reply to a request message, because the request message from a peer who is from a foreign org")
	case <-time.After(time.Second):
	}
}

func TestChannelIsInChannel(t *testing.T) {
	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)
	adapter := new(gossipAdapterMock)
	configureAdapter(adapter, nil)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Send", mock.Anything, mock.Anything)
	adapter.On("DeMultiplex", mock.Anything)

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	require.False(t, gc.IsOrgInChannel(nil))
	require.False(t, gc.IsOrgInChannel(orgNotInChannelA))
	require.True(t, gc.IsOrgInChannel(orgInChannelA))
	require.False(t, gc.IsMemberInChannel(utils.NetworkMember{PKIid: pkiIDInOrg2}))
	require.True(t, gc.IsMemberInChannel(utils.NetworkMember{PKIid: pkiIDInOrg1}))
}

func TestChannelIsSubscribed(t *testing.T) {
	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)
	adapter := new(gossipAdapterMock)
	configureAdapter(adapter, nil)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Send", mock.Anything, mock.Anything)
	adapter.On("DeMultiplex", mock.Anything)
	adapter.On("Forward", mock.Anything)

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	gc.HandleMessage(&receivedMsg{msg: createStateInfoMsg(10, pkiIDInOrg1, channelA), pkiID: pkiIDInOrg1})
	require.True(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg1}))
}

func TestChannelAddToMessageStore(t *testing.T) {
	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)
	demuxedMsgs := make(chan *utils.SignedGossipMessage, 1)

	adapter := new(gossipAdapterMock)
	configureAdapter(adapter, nil)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Send", mock.Anything, mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("DeMultiplex", mock.Anything).Run(func(args mock.Arguments) {
		demuxedMsgs <- args.Get(0).(*utils.SignedGossipMessage)
	})

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	gc.HandleMessage(&receivedMsg{msg: createDataMsg(11, channelA), pkiID: pkiIDInOrg1})
	select {
	case <-demuxedMsgs:
	case <-time.After(time.Second):
		require.Fail(t, "Didn't demultiplex a data msg within a timely manner")
	}
	gc.AddToMsgStore(createDataMsg(12, channelA))
	gc.HandleMessage(&receivedMsg{msg: createDataMsg(12, channelA), pkiID: pkiIDInOrg1})
	select {
	case <-demuxedMsgs:
		require.Fail(t, "Should not receive old data msg")
	case <-time.After(time.Second):
	}

	gc.AddToMsgStore(createStateInfoMsg(10, pkiIDInOrg1, channelA))
	helloMsg := createHelloMsg(pkiIDInOrg1)
	responsedChan := make(chan struct{}, 1)
	helloMsg.On("Respond", mock.Anything).Run(func(args mock.Arguments) {
		responsedChan <- struct{}{}
	})
	gc.HandleMessage(helloMsg)
	select {
	case <-responsedChan:
	case <-time.After(time.Second):
		require.Fail(t, "Didn't reply to a hello within a timely manner")
	}
	gc.HandleMessage(&receivedMsg{msg: createStateInfoMsg(10, pkiIDInOrg1, channelA), pkiID: pkiIDInOrg1})
	require.True(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg1}))
}

func TestChannelBlockExpiration(t *testing.T) {
	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)

	demuxedMsgs := make(chan *utils.SignedGossipMessage, 1)

	adapter := new(gossipAdapterMock)
	configureAdapter(adapter, nil)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Send", mock.Anything, mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("DeMultiplex", mock.Anything).Run(func(args mock.Arguments) {
		demuxedMsgs <- args.Get(0).(*utils.SignedGossipMessage)
	})

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)

	respondChan := make(chan *pgossip.GossipMessage, 1)
	messageRelayer := func(args mock.Arguments) {
		msg := args.Get(0).(*pgossip.GossipMessage)
		respondChan <- msg
	}

	gc.HandleMessage(&receivedMsg{msg: createDataMsg(5, channelA), pkiID: pkiIDInOrg1})
	select {
	case <-demuxedMsgs:
	case <-time.After(time.Second):
		require.Fail(t, "Haven't detected demultiplexing message")
	}

	helloMsg := createHelloMsg(pkiIDInOrg1)
	helloMsg.On("Respond", mock.Anything).Run(messageRelayer)
	gc.HandleMessage(helloMsg)
	select {
	case <-time.After(time.Second):
	case <-respondChan:
		require.Fail(t, "Shouldn't replied to hello message")
	}

	stateInfoMsg := createStateInfoMsg(10, pkiIDInOrg1, channelA)
	gc.AddToMsgStore(stateInfoMsg)
	helloMsg = createHelloMsg(pkiIDInOrg1)
	helloMsg.On("Respond", mock.Anything).Run(messageRelayer)
	gc.HandleMessage(helloMsg)
	select {
	case <-time.After(time.Second):
		require.Fail(t, "Haven't replied to hello message")
	case msg := <-respondChan:
		if msg.GetDataDig() != nil {
			require.Equal(t, "5", string(msg.GetDataDig().Digests[0]))
		} else {
			require.Fail(t, "Not correct pull msg type in response - expect digest")
		}
	}

	time.Sleep(gc.(*gossipChannel).adapter.GetConf().BlockExpirationTimeout + time.Second)

	gc.HandleMessage(&receivedMsg{msg: createDataMsg(5, channelA), pkiID: pkiIDInOrg1})
	select {
	case <-time.After(time.Second):
	case <-demuxedMsgs:
		require.Fail(t, "Shouldn't process the block")
	}

	// gc.AddToMsgStore(stateInfoMsg)
	gc.HandleMessage(helloMsg)
	select {
	case <-time.After(time.Second):
	case <-respondChan:
		require.Fail(t, "No digest should be sent")
	}

	time.Sleep(gc.(*gossipChannel).adapter.GetConf().BlockExpirationTimeout + time.Second)

	gc.HandleMessage(&receivedMsg{msg: createDataMsg(5, channelA), pkiID: pkiIDInOrg1})
	select {
	case <-demuxedMsgs:
	case <-time.After(time.Second):
		require.Fail(t, "Haven't detected demultiplexing message")
	}

	gc.HandleMessage(helloMsg)
	select {
	case <-time.After(time.Second):
		require.Fail(t, "Haven't replied to hello message")
	case msg := <-respondChan:
		if msg.GetDataDig() != nil {
			require.Equal(t, "5", string(msg.GetDataDig().Digests[0]))
		} else {
			require.Fail(t, "Not correct pull msg type in response - expect digest")
		}
	}
}

func TestChannelBadBlocks(t *testing.T) {
	receivedMessages := make(chan *utils.SignedGossipMessage, 1)
	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)

	adapter := new(gossipAdapterMock)
	members := utils.Members{}
	members = append(members, utils.NetworkMember{PKIid: pkiIDInOrg1})
	configureAdapter(adapter, members)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("DeMultiplex", mock.Anything).Run(func(args mock.Arguments) {
		receivedMessages <- args.Get(0).(*utils.SignedGossipMessage)
	})

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	gc.HandleMessage(&receivedMsg{msg: createDataMsg(1, channelA), pkiID: pkiIDInOrg1})
	require.Len(t, receivedMessages, 1)
	<-receivedMessages

	gc.HandleMessage(&receivedMsg{msg: createDataMsg(2, utils.ChannelID{'a'}), pkiID: pkiIDInOrg1})
	require.Len(t, receivedMessages, 0)

	dataMsg := createDataMsg(3, channelA)
	dataMsg.GetDataMsg().Payload = nil
	gc.HandleMessage(&receivedMsg{msg: dataMsg, pkiID: pkiIDInOrg1})
	require.Len(t, receivedMessages, 0)

	cs.Mock = mock.Mock{}
	cs.On("VerifyBlock", mock.Anything).Return(errors.NewError("bad signature"))
	gc.HandleMessage(&receivedMsg{msg: createDataMsg(4, channelA), pkiID: pkiIDInOrg1})
	require.Len(t, receivedMessages, 0)
}

func TestNoGossipOrSigningWhenEmptyMembership(t *testing.T) {
	var gossipedWG sync.WaitGroup
	gossipedWG.Add(1)

	var emptyMembership = utils.Members{}
	var nonEmptyMembership = utils.Members{}
	nonEmptyMembership = append(nonEmptyMembership, utils.NetworkMember{PKIid: pkiIDInOrg1})

	var dynamicMembership atomic.Value
	dynamicMembership.Store(nonEmptyMembership)

	cs := &cryptoService{}
	adapter := new(gossipAdapterMock)

	conf := conf
	conf.PublishStateInfoInterval = time.Second
	conf.RequestStateInfoInterval = time.Hour
	conf.TimeForMembershipTracker = time.Hour
	adapter.On("GetConf").Return(conf)
	adapter.On("GetOrgOfPeer", pkiIDInOrg1).Return(orgInChannelA)
	adapter.On("Gossip", mock.Anything).Run(func(args mock.Arguments) {
		gossipedWG.Done()
	})
	adapter.On("GetMembership").Return(func() utils.Members {
		return dynamicMembership.Load().(utils.Members)
	})

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	require.Equal(t, uint32(1), atomic.LoadUint32(&adapter.signCallCount))
	defer gc.Stop()
	gc.UpdateLedgerHeight(1)
	gossipedWG.Wait()
	require.Equal(t, uint32(2), atomic.LoadUint32(&adapter.signCallCount))

	dynamicMembership.Store(emptyMembership)
	gc.UpdateLedgerHeight(2)
	time.Sleep(conf.PublishStateInfoInterval * 3)
	require.Equal(t, uint32(2), atomic.LoadUint32(&adapter.signCallCount))

	require.Empty(t, gc.Self().GetStateInfo().Properties.Chaincodes)
	gossipedWG.Add(1)
	gc.UpdateChaincodes([]*pgossip.Chaincode{{Name: "mycc"}})
	require.Equal(t, uint32(3), atomic.LoadUint32(&adapter.signCallCount))
	require.Equal(t, "mycc", gc.Self().GetStateInfo().Properties.Chaincodes[0].Name)
}

func TestChannelPulledBadBlocks(t *testing.T) {
	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)

	adapter := new(gossipAdapterMock)
	members := utils.Members{}
	members = append(members, utils.NetworkMember{PKIid: pkiIDInOrg1})
	configureAdapter(adapter, members)
	adapter.On("DeMultiplex", mock.Anything)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(1, pkiIDInOrg1, channelA)})

	var wg sync.WaitGroup
	wg.Add(1)

	changeChan := func(envelope *pgossip.Envelope) {
		sgm, _ := utils.EnvelopeToSignedGossipMessage(envelope)
		sgm.Channel = utils.ChannelID("a")
		sgm, _ = utils.NoopSign(sgm.GossipMessage)
		envelope.Payload = sgm.Payload
	}

	pullPhase1 := simulatePullPhase(gc, t, &wg, changeChan, 10, 11)
	adapter.On("Send", mock.Anything, mock.Anything).Run(pullPhase1)
	wg.Wait()
	gc.Stop()
	require.Equal(t, 0, gc.(*gossipChannel).blockMsgStore.Size())

	cs = &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(errors.NewError("bad block"))
	adapter = new(gossipAdapterMock)
	configureAdapter(adapter, members)
	adapter.On("DeMultiplex", mock.Anything)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	gc = NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(1, pkiIDInOrg1, channelA)})
	wg.Add(1)
	noop := func(*pgossip.Envelope) {}
	pullPhase2 := simulatePullPhase(gc, t, &wg, noop, 10, 11)
	adapter.On("Send", mock.Anything, mock.Anything).Run(pullPhase2)
	wg.Wait()
	gc.Stop()
	require.Equal(t, 0, gc.(*gossipChannel).blockMsgStore.Size())

	cs = &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(errors.NewError("bad block"))
	adapter = new(gossipAdapterMock)
	configureAdapter(adapter, members)
	adapter.On("DeMultiplex", mock.Anything)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	gc = NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(1, pkiIDInOrg1, channelA)})
	wg.Add(1)
	emptyBlock := func(envelope *pgossip.Envelope) {
		sgm, _ := utils.EnvelopeToSignedGossipMessage(envelope)
		sgm.GetDataMsg().Payload = nil
		sgm, _ = utils.NoopSign(sgm.GossipMessage)
		envelope.Payload = sgm.Envelope.Payload
	}
	pullPhase3 := simulatePullPhase(gc, t, &wg, emptyBlock, 10, 11)
	adapter.On("Send", mock.Anything, mock.Anything).Run(pullPhase3)
	wg.Wait()
	gc.Stop()
	require.Equal(t, 0, gc.(*gossipChannel).blockMsgStore.Size())

	cs = &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(errors.NewError("bad block"))
	adapter = new(gossipAdapterMock)
	configureAdapter(adapter, members)
	adapter.On("DeMultiplex", mock.Anything)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	gc = NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(1, pkiIDInOrg1, channelA)})
	wg.Add(1)
	nonBlockMsg := func(envelope *pgossip.Envelope) {
		sgm, _ := utils.EnvelopeToSignedGossipMessage(envelope)
		sgm.Content = createHelloMsg(pkiIDInOrg1).GetSignedGossipMessage().Content
		sgm, _ = utils.NoopSign(sgm.GossipMessage)
		envelope.Payload = sgm.Payload
	}
	pullPhase4 := simulatePullPhase(gc, t, &wg, nonBlockMsg, 10, 11)
	adapter.On("Send", mock.Anything, mock.Anything).Run(pullPhase4)
	wg.Wait()
	gc.Stop()
	require.Equal(t, 0, gc.(*gossipChannel).blockMsgStore.Size())
}

func TestChannelStateInfoSnapshot(t *testing.T) {
	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)

	adapter := new(gossipAdapterMock)
	adapter.On("Lookup", mock.Anything).Return(&utils.NetworkMember{Endpoint: "localhost:5000"})
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("ValidateStateInfoMessage", mock.Anything).Return(nil)
	adapter.On("Send", mock.Anything, mock.Anything)
	members := utils.Members{}
	members = append(members, utils.NetworkMember{PKIid: pkiIDInOrg1})
	configureAdapter(adapter, members)

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)

	sentMessages := make(chan *pgossip.GossipMessage, 10)

	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: stateInfoSnapshotForChannel(utils.ChannelID("a"), createStateInfoMsg(4, pkiIDInOrg1, channelA))})
	require.Empty(t, gc.GetPeers())

	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: stateInfoSnapshotForChannel(channelA, createStateInfoMsg(4, pkiIDInOrg1, utils.ChannelID("a")))})
	require.Empty(t, gc.GetPeers())

	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: stateInfoSnapshotForChannel(channelA, createStateInfoMsg(4, pkiIDInOrg2, channelA))})
	require.Empty(t, gc.GetPeers())

	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg2, msg: stateInfoSnapshotForChannel(channelA, createStateInfoMsg(4, pkiIDInOrg1, channelA))})
	require.Empty(t, gc.GetPeers())

	stateInfoMsg := createStateInfoMsg(4, pkiIDInOrg1, channelA)
	stateInfoMsg.GetStateInfo().Channel_MAC = append(stateInfoMsg.GetStateInfo().Channel_MAC, 1)
	stateInfoMsg, _ = utils.NoopSign(stateInfoMsg.GossipMessage)
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: stateInfoSnapshotForChannel(channelA, stateInfoMsg)})
	require.Empty(t, gc.GetPeers())

	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: stateInfoSnapshotForChannel(channelA, createStateInfoMsg(4, pkiIDInOrg1, channelA))})
	require.NotEmpty(t, gc.GetPeers())
	require.Equal(t, 4, int(gc.GetPeers()[0].Properties.LedgerHeight))

	sgm, _ := utils.NoopSign(&pgossip.GossipMessage{
		Tag:     pgossip.GossipMessage_CHAN_OR_ORG,
		Channel: channelA,
		Content: &pgossip.GossipMessage_StateInfoPullReq{
			StateInfoPullReq: &pgossip.StateInfoPullRequest{
				Channel_MAC: append(utils.GenerateMAC(pkiIDInOrg1, channelA), 1),
			},
		},
	})
	snapshotReq := &receivedMsg{
		pkiID: pkiIDInOrg1,
		msg:   sgm,
	}
	snapshotReq.On("Respond", mock.Anything).Run(func(args mock.Arguments) {
		sentMessages <- args.Get(0).(*pgossip.GossipMessage)
	})

	go gc.HandleMessage(snapshotReq)
	select {
	case <-sentMessages:
		require.Fail(t, "Shouldn't reply to an uncorrect request with invalid channel_mac")
	case <-time.After(time.Second):
	}

	sgm, _ = utils.NoopSign(&pgossip.GossipMessage{
		Tag:     pgossip.GossipMessage_CHAN_OR_ORG,
		Channel: channelA,
		Content: &pgossip.GossipMessage_StateInfoPullReq{
			StateInfoPullReq: &pgossip.StateInfoPullRequest{
				Channel_MAC: utils.GenerateMAC(pkiIDInOrg1, channelA),
			},
		},
	})
	snapshotReq = &receivedMsg{
		pkiID: pkiIDInOrg1,
		msg:   sgm,
	}
	snapshotReq.On("Respond", mock.Anything).Run(func(args mock.Arguments) {
		sentMessages <- args.Get(0).(*pgossip.GossipMessage)
	})

	go gc.HandleMessage(snapshotReq)
	select {
	case msg := <-sentMessages:
		elements := msg.GetStateInfoSnapshot().Elements
		require.Len(t, elements, 1)
		signedMsg, err := utils.EnvelopeToSignedGossipMessage(elements[0])
		require.NoError(t, err)
		require.Equal(t, 4, int(signedMsg.GetStateInfo().Properties.LedgerHeight))
	case <-time.After(time.Second):
		require.Fail(t, "Didn't reply to a request within a timely manner")
	}

	invalidStateInfoSnapshot := stateInfoSnapshotForChannel(channelA, createStateInfoMsg(4, pkiIDInOrg1, channelA))
	invalidStateInfoSnapshot.GetStateInfoSnapshot().Elements = []*pgossip.Envelope{createHelloMsg(pkiIDInOrg1).GetSourceEnvelope()}
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: invalidStateInfoSnapshot})

	invalidStateInfoSnapshot = stateInfoSnapshotForChannel(channelA, createStateInfoMsg(4, utils.PKIidType("unknown"), channelA))
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: invalidStateInfoSnapshot})
}

func TestInterOrgExternalEndpointDisclosure(t *testing.T) {
	cs := &cryptoService{}
	adapter := new(gossipAdapterMock)
	pkiID1 := utils.PKIidType("withExternalEndpoint")
	pkiID2 := utils.PKIidType("noExternalEndpoint")
	pkiID3 := utils.PKIidType("pkiIDInOrg2")
	adapter.On("Lookup", pkiID1).Return(&utils.NetworkMember{Endpoint: "localhost:5000"})
	adapter.On("Lookup", pkiID2).Return(&utils.NetworkMember{})
	adapter.On("Lookup", pkiID3).Return(&utils.NetworkMember{})
	adapter.On("GetOrgOfPeer", pkiID1).Return(orgInChannelA)
	adapter.On("GetOrgOfPeer", pkiID2).Return(orgInChannelA)
	adapter.On("GetOrgOfPeer", pkiID3).Return(utils.OrgIdentityType("ORG2"))
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("DeMultiplex", mock.Anything)
	configureAdapter(adapter, nil)
	joinMsg := &joinChanMsg{
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			orgInChannelA.String(): {},
			"ORG2":                 {},
		},
	}
	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, joinMsg, disabledMetrics, logger)
	gc.HandleMessage(&receivedMsg{pkiID: pkiID1, msg: createStateInfoMsg(0, pkiID1, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiID2, msg: createStateInfoMsg(0, pkiID2, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiID3, msg: createStateInfoMsg(0, pkiID3, channelA)})

	sentMessages := make(chan *pgossip.GossipMessage, 10)
	sgm, _ := utils.NoopSign(&pgossip.GossipMessage{
		Tag:     pgossip.GossipMessage_CHAN_OR_ORG,
		Channel: channelA,
		Content: &pgossip.GossipMessage_StateInfoPullReq{
			StateInfoPullReq: &pgossip.StateInfoPullRequest{
				Channel_MAC: utils.GenerateMAC(pkiID3, channelA),
			},
		},
	})
	req := &receivedMsg{
		pkiID: pkiID3,
		msg:   sgm,
	}
	req.On("Respond", mock.Anything).Run(func(args mock.Arguments) {
		sentMessages <- args.Get(0).(*pgossip.GossipMessage)
	})

	go gc.HandleMessage(req)
	select {
	case <-time.After(time.Second):
		require.Fail(t, "Should respond to req msg in time")
	case msg := <-sentMessages:
		elements := msg.GetStateInfoSnapshot().Elements
		require.Len(t, elements, 2)
		m1, _ := utils.EnvelopeToSignedGossipMessage(elements[0])
		m2, _ := utils.EnvelopeToSignedGossipMessage(elements[1])
		pkiIDs := [][]byte{pkiID1, pkiID3}
		require.Contains(t, pkiIDs, m1.GetStateInfo().PkiId)
		require.Contains(t, pkiIDs, m2.GetStateInfo().PkiId)
	}

	sgm, _ = utils.NoopSign(&pgossip.GossipMessage{
		Tag:     pgossip.GossipMessage_CHAN_OR_ORG,
		Channel: channelA,
		Content: &pgossip.GossipMessage_StateInfoPullReq{
			StateInfoPullReq: &pgossip.StateInfoPullRequest{
				Channel_MAC: utils.GenerateMAC(pkiID2, channelA),
			},
		},
	})
	req = &receivedMsg{
		pkiID: pkiID2,
		msg:   sgm,
	}
	req.On("Respond", mock.Anything).Run(func(args mock.Arguments) {
		sentMessages <- args.Get(0).(*pgossip.GossipMessage)
	})
	go gc.HandleMessage(req)
	select {
	case <-time.After(time.Second):
		require.Fail(t, "Should respond to req msg in time")
	case msg := <-sentMessages:
		elements := msg.GetStateInfoSnapshot().Elements
		require.Len(t, elements, 3)
		m1, _ := utils.EnvelopeToSignedGossipMessage(elements[0])
		m2, _ := utils.EnvelopeToSignedGossipMessage(elements[1])
		m3, _ := utils.EnvelopeToSignedGossipMessage(elements[2])
		pkiIDs := [][]byte{pkiID1, pkiID2, pkiID3}
		require.Contains(t, pkiIDs, m1.GetStateInfo().PkiId)
		require.Contains(t, pkiIDs, m2.GetStateInfo().PkiId)
		require.Contains(t, pkiIDs, m3.GetStateInfo().PkiId)
	}
}

func TestChannelStop(t *testing.T) {
	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)
	adapter := new(gossipAdapterMock)
	var sentCount int32
	members := utils.Members{}
	members = append(members, utils.NetworkMember{PKIid: pkiIDInOrg1})
	configureAdapter(adapter, members)
	adapter.On("Send", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		atomic.AddInt32(&sentCount, 1)
	})
	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	time.Sleep(time.Second)
	gc.Stop()
	oldCount := atomic.LoadInt32(&sentCount)
	t1 := time.Now()
	for {
		if time.Since(t1).Nanoseconds() > (time.Second * 15).Nanoseconds() {
			require.Fail(t, "Channel stop failed")
		}
		time.Sleep(time.Second)
		newCount := atomic.LoadInt32(&sentCount)
		if newCount == oldCount {
			break
		}
		oldCount = newCount
	}
}

func TestChannelReconfigureChannel(t *testing.T) {
	cs := &cryptoService{}
	adapter := new(gossipAdapterMock)
	members := utils.Members{}
	members = append(members, utils.NetworkMember{PKIid: pkiIDInOrg1})
	configureAdapter(adapter, members)
	adapter.On("GetConf").Return(conf)
	adapter.On("GetMembership").Return([]utils.NetworkMember{})
	adapter.On("OrgByPeerIdentity", utils.PeerIdentityType(orgInChannelA)).Return(orgInChannelA)
	adapter.On("OrgByPeerIdentity", utils.PeerIdentityType(orgNotInChannelA)).Return(orgNotInChannelA)
	adapter.On("GetOrgOfPeer", pkiIDInOrg1).Return(orgInChannelA)
	adapter.On("GetOrgOfPeer", pkiIDInOrg2).Return(orgNotInChannelA)

	outdatedJoinChanMsg := &joinChanMsg{
		getTS: func() time.Time {
			return time.Now()
		},
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			string(orgNotInChannelA): {},
		},
	}

	newJoinChanMsg := &joinChanMsg{
		getTS: func() time.Time {
			return time.Now().Add(time.Millisecond * 100)
		},
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			string(orgInChannelA): {},
		},
	}

	updatedJoinChanMsg := &joinChanMsg{
		getTS: func() time.Time {
			return time.Now().Add(time.Millisecond * 200)
		},
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			string(orgNotInChannelA): {},
		},
	}

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, newJoinChanMsg, disabledMetrics, logger)

	gc.ConfigureChannel(newJoinChanMsg)

	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("Send", mock.Anything, mock.Anything)
	adapter.On("DeMultiplex", mock.Anything)

	require.True(t, gc.IsOrgInChannel(orgInChannelA))
	require.False(t, gc.IsOrgInChannel(orgNotInChannelA))
	require.True(t, gc.IsMemberInChannel(utils.NetworkMember{PKIid: pkiIDInOrg1}))
	require.False(t, gc.IsMemberInChannel(utils.NetworkMember{PKIid: pkiIDInOrg2}))

	gc.ConfigureChannel(outdatedJoinChanMsg)
	require.True(t, gc.IsOrgInChannel(orgInChannelA))
	require.False(t, gc.IsOrgInChannel(orgNotInChannelA))
	require.True(t, gc.IsMemberInChannel(utils.NetworkMember{PKIid: pkiIDInOrg1}))
	require.False(t, gc.IsMemberInChannel(utils.NetworkMember{PKIid: pkiIDInOrg2}))

	gc.ConfigureChannel(updatedJoinChanMsg)
	gc.ConfigureChannel(updatedJoinChanMsg)
	require.False(t, gc.IsOrgInChannel(orgInChannelA))
	require.True(t, gc.IsOrgInChannel(orgNotInChannelA))
	require.False(t, gc.IsMemberInChannel(utils.NetworkMember{PKIid: pkiIDInOrg1}))
	require.True(t, gc.IsMemberInChannel(utils.NetworkMember{PKIid: pkiIDInOrg2}))

	sgm, _ := gc.(*gossipChannel).createStateInfoRequest()
	invalidReceivedMsg := &receivedMsg{
		msg:   sgm,
		pkiID: pkiIDInOrg1,
	}
	gossipMessagesSentFromChannel := make(chan *pgossip.GossipMessage, 1)
	messageRelayer := func(arg mock.Arguments) {
		msg := arg.Get(0).(*pgossip.GossipMessage)
		gossipMessagesSentFromChannel <- msg
	}
	invalidReceivedMsg.On("Respond", mock.Anything).Run(messageRelayer)
	gc.HandleMessage(invalidReceivedMsg)
	select {
	case <-gossipMessagesSentFromChannel:
		t.Fatal("Responded with digest, but shouldn't have since peer is in ORG2 and its not in the channel")
	case <-time.After(time.Second * 1):
	}
}

func TestChannelNoAnchorPeers(t *testing.T) {
	// Scenario: We got a join channel message with no anchor peers
	// In this case, we should be in the channel

	cs := &cryptoService{}
	adapter := new(gossipAdapterMock)
	members := utils.Members{}
	members = append(members, utils.NetworkMember{PKIid: pkiIDInOrg1})
	configureAdapter(adapter, members)

	adapter.On("GetConf").Return(conf)
	adapter.On("GetMembership").Return([]utils.NetworkMember{})
	adapter.On("OrgByPeerIdentity", utils.PeerIdentityType(orgInChannelA)).Return(orgInChannelA)
	adapter.On("GetOrgOfPeer", pkiIDInOrg1).Return(orgInChannelA)
	adapter.On("GetOrgOfPeer", pkiIDInOrg2).Return(orgNotInChannelA)

	jcm := &joinChanMsg{
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			string(orgInChannelA): {},
		},
	}

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, utils.JoinChannelMessage(jcm), disabledMetrics, logger)
	require.True(t, gc.IsOrgInChannel(orgInChannelA))
}

func TestGossipChannelEligibility(t *testing.T) {
	// Scenario: We have a peer in an org that joins a channel with org1 and org2.
	// and it receives StateInfo messages of other peers and the eligibility
	// of these peers of being in the channel is checked.
	// During the test, the channel is reconfigured, and the expiration
	// of the peer identities is simulated.

	cs := &cryptoService{}
	selfPKIID := utils.PKIidType("p")
	adapter := new(gossipAdapterMock)
	pkiIDinOrg3 := utils.PKIidType("pkiIDinOrg3")
	members := utils.Members{}
	members = append(members, []utils.NetworkMember{
		{PKIid: pkiIDInOrg1},
		{PKIid: pkiIDInOrg1ButNotEligible},
		{PKIid: pkiIDInOrg2},
		{PKIid: pkiIDinOrg3},
	}...)
	adapter.On("GetMembership").Return(members)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("Send", mock.Anything, mock.Anything)
	adapter.On("DeMultiplex", mock.Anything)
	adapter.On("GetConf").Return(conf)

	// At first, all peers are in the channel except pkiIDinOrg3
	org1 := utils.OrgIdentityType("ORG1")
	org2 := utils.OrgIdentityType("ORG2")
	org3 := utils.OrgIdentityType("ORG3")

	adapter.On("GetOrgOfPeer", selfPKIID).Return(org1)
	adapter.On("GetOrgOfPeer", pkiIDInOrg1).Return(org1)
	adapter.On("GetOrgOfPeer", pkiIDInOrg2).Return(org2)
	adapter.On("GetOrgOfPeer", pkiIDInOrg1ButNotEligible).Return(org1)
	adapter.On("GetOrgOfPeer", pkiIDinOrg3).Return(org3)

	gc := NewGossipChannel(selfPKIID, orgInChannelA, cs, channelA, adapter, &joinChanMsg{
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			string(org1): {},
			string(org2): {},
		},
	}, disabledMetrics, logger)
	// Every peer sends a StateInfo message
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(1, pkiIDInOrg1, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg2, msg: createStateInfoMsg(1, pkiIDInOrg2, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1ButNotEligible, msg: createStateInfoMsg(1, pkiIDInOrg1ButNotEligible, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDinOrg3, msg: createStateInfoMsg(1, pkiIDinOrg3, channelA)})

	require.True(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg1}))
	require.True(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg2}))
	require.True(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg1ButNotEligible}))
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDinOrg3}))

	// Ensure peers from the channel are returned
	require.True(t, gc.PeerFilter(func(signature utils.PeerSignature) bool {
		return true
	})(utils.NetworkMember{PKIid: pkiIDInOrg1}))
	require.True(t, gc.PeerFilter(func(signature utils.PeerSignature) bool {
		return true
	})(utils.NetworkMember{PKIid: pkiIDInOrg2}))
	// But not peers which aren't in the channel
	require.False(t, gc.PeerFilter(func(signature utils.PeerSignature) bool {
		return true
	})(utils.NetworkMember{PKIid: pkiIDinOrg3}))

	// Ensure the given predicate is considered
	require.True(t, gc.PeerFilter(func(signature utils.PeerSignature) bool {
		return bytes.Equal(signature.PeerIdentity, []byte("pkiIDInOrg2"))
	})(utils.NetworkMember{PKIid: pkiIDInOrg2}))

	require.False(t, gc.PeerFilter(func(signature utils.PeerSignature) bool {
		return bytes.Equal(signature.PeerIdentity, []byte("pkiIDinOrg2"))
	})(utils.NetworkMember{PKIid: pkiIDInOrg1}))

	// Remove org2 from the channel
	gc.ConfigureChannel(&joinChanMsg{
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			string(org1): {},
		},
	})

	require.True(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg1}))
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg2}))
	require.True(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg1ButNotEligible}))
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDinOrg3}))

	// Now simulate a config update that removed pkiIDInOrg1ButNotEligible from the channel readers
	cs.mocked = true
	cs.On("VerifyByChannel", utils.PeerIdentityType(pkiIDInOrg1ButNotEligible)).Return(errors.NewError("Not a channel reader"))
	cs.On("VerifyByChannel", mock.Anything).Return(nil)
	gc.ConfigureChannel(&joinChanMsg{
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			string(org1): {},
		},
	})
	require.True(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg1}))
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg2}))
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg1ButNotEligible}))
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDinOrg3}))

	// Now Simulate a certificate expiration of pkiIDInOrg1.
	// This is done by asking the adapter to lookup the identity by PKI-ID, but if the certificate
	// is expired, the mapping is deleted and hence the lookup yields nothing.
	adapter.On("GetIdentityByPKIID", pkiIDInOrg1).Return(utils.PeerIdentityType(nil))
	adapter.On("GetIdentityByPKIID", pkiIDInOrg2).Return(utils.PeerIdentityType(pkiIDInOrg2))
	adapter.On("GetIdentityByPKIID", pkiIDInOrg1ButNotEligible).Return(utils.PeerIdentityType(pkiIDInOrg1ButNotEligible))
	adapter.On("GetIdentityByPKIID", pkiIDinOrg3).Return(utils.PeerIdentityType(pkiIDinOrg3))

	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg1}))
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg2}))
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg1ButNotEligible}))
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDinOrg3}))

	// Now make another update of StateInfo messages, this time with updated ledger height (to overwrite earlier messages)
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(2, pkiIDInOrg1, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(2, pkiIDInOrg2, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(2, pkiIDInOrg1ButNotEligible, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(2, pkiIDinOrg3, channelA)})

	// Ensure the access control resolution hasn't changed
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg1}))
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg2}))
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDInOrg1ButNotEligible}))
	require.False(t, gc.ShouldGetBlocksForThisChannel(utils.NetworkMember{PKIid: pkiIDinOrg3}))
}

func TestChannelGetPeers(t *testing.T) {
	// Scenario: We have a peer in an org, and the peer is notified that several peers
	// exist, and some of them:
	// (1) Join its channel, and are eligible for receiving blocks.
	// (2) Join its channel, but are not eligible for receiving blocks (MSP doesn't allow this).
	// (3) Say they join its channel, but are actually from an org that is not in the channel.
	// The GetPeers query should only return peers that belong to the first group.
	cs := &cryptoService{}
	adapter := new(gossipAdapterMock)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("Send", mock.Anything, mock.Anything)
	adapter.On("DeMultiplex", mock.Anything)
	members := utils.Members{}
	members = append(members, []utils.NetworkMember{
		{PKIid: pkiIDInOrg1},
		{PKIid: pkiIDInOrg1ButNotEligible},
		{PKIid: pkiIDInOrg2},
	}...)
	configureAdapter(adapter, members)
	gc := NewGossipChannel(utils.PKIidType("p0"), orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(1, pkiIDInOrg1, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(1, pkiIDInOrg2, channelA)})
	require.Len(t, gc.GetPeers(), 1)
	require.Equal(t, pkiIDInOrg1, gc.GetPeers()[0].PKIid)

	// Ensure envelope from GetPeers is valid
	gMsg, _ := utils.EnvelopeToSignedGossipMessage(gc.GetPeers()[0].Envelope)
	require.Equal(t, []byte(pkiIDInOrg1), gMsg.GetStateInfo().PkiId)

	gc.HandleMessage(&receivedMsg{msg: createStateInfoMsg(10, pkiIDInOrg1ButNotEligible, channelA), pkiID: pkiIDInOrg1ButNotEligible})
	cs.On("VerifyByChannel", mock.Anything).Return(errors.NewError("Not eligible"))
	cs.mocked = true
	// Simulate a config update
	gc.ConfigureChannel(&joinChanMsg{})
	require.Len(t, gc.GetPeers(), 0)

	// Now recreate gc and corrupt the MAC
	// and ensure that the StateInfo message doesn't count
	gc = NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	msg := &receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(1, pkiIDInOrg1, channelA)}
	msg.GetSignedGossipMessage().GetStateInfo().Channel_MAC = utils.GenerateMAC(pkiIDInOrg2, channelA)
	gc.HandleMessage(msg)
	require.Len(t, gc.GetPeers(), 0)
}

func TestOnDemandGossip(t *testing.T) {
	// Scenario: update the metadata and ensure only 1 dissemination
	// takes place when membership is not empty
	peerA := utils.NetworkMember{
		PKIid:            pkiIDInOrg1,
		Endpoint:         "a",
		InternalEndpoint: "a",
	}
	members := utils.Members{}
	members = append(members, peerA)

	cs := &cryptoService{}

	adapter := new(gossipAdapterMock)
	configureAdapter(adapter, members)

	adapter.ExpectedCalls = append(adapter.ExpectedCalls[:1], adapter.ExpectedCalls[2:]...)
	var lock sync.RWMutex
	var membershipKnown bool
	adapter.On("GetMembership").Return(func() utils.Members {
		lock.RLock()
		defer lock.RUnlock()
		if !membershipKnown {
			return []utils.NetworkMember{}
		}
		return []utils.NetworkMember{{}}
	})

	gossipedEvents := make(chan struct{})

	conf := conf
	conf.PublishStateInfoInterval = time.Millisecond * 200
	adapter.On("GetConf").Return(conf)
	adapter.On("Gossip", mock.Anything).Run(func(mock.Arguments) {
		lock.Lock()
		defer lock.Unlock()
		gossipedEvents <- struct{}{}
	})
	adapter.On("Forward", mock.Anything)

	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	defer gc.Stop()
	select {
	case <-gossipedEvents:
		require.Fail(t, "Should not have gossiped because metadata has not been updated yet")
	case <-time.After(time.Millisecond * 500):
	}

	gc.UpdateLedgerHeight(1)
	lock.Lock()
	membershipKnown = true
	lock.Unlock()

	select {
	case <-gossipedEvents:
	case <-time.After(time.Second):
		require.Fail(t, "Didn't gossip within a timely manner")
	}
	gc.UpdateLedgerHeight(2)
	adapter.On("Gossip", mock.Anything).Run(func(mock.Arguments) {
		gossipedEvents <- struct{}{}
	})
	adapter.On("Forward", mock.Anything)
	gc.(*gossipChannel).adapter = adapter
	select {
	case <-gossipedEvents:
	case <-time.After(time.Second):
		require.Fail(t, "Should have gossiped a third time")
	}
	select {
	case <-gossipedEvents:
		require.Fail(t, "Should not have gossiped a fourth time, because dirty flag should have been turned off")
	case <-time.After(time.Millisecond * 500):
	}
	gc.UpdateLedgerHeight(3)
	select {
	case <-gossipedEvents:
	case <-time.After(time.Second):
		require.Fail(t, "Should have gossiped a block now, because got a new StateInfo message")
	}
}

func TestChannelPullWithDigestsFilter(t *testing.T) {
	cs := &cryptoService{}
	cs.On("VerifyBlock", mock.Anything).Return(nil)
	receivedBlocksChan := make(chan *utils.SignedGossipMessage, 2)
	adapter := new(gossipAdapterMock)
	members := utils.Members{utils.NetworkMember{PKIid: pkiIDInOrg1}}
	configureAdapter(adapter, members)
	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("DeMultiplex", mock.Anything).Run(func(arg mock.Arguments) {
		msg := arg.Get(0).(*utils.SignedGossipMessage)
		if msg.GetDataMsg() == nil {
			return
		}
		// The peer is supposed to de-multiplex 1 ledger block
		require.True(t, msg.GetDataMsg() != nil)
		receivedBlocksChan <- msg
	})
	gc := NewGossipChannel(pkiIDInOrg1, orgInChannelA, cs, channelA, adapter, &joinChanMsg{}, disabledMetrics, logger)
	go gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(100, pkiIDInOrg1, channelA)})

	gc.UpdateLedgerHeight(11)

	var wg sync.WaitGroup
	wg.Add(1)

	pullPhase := simulatePullPhaseWithVariableDigest(gc, t, &wg, func(envelope *pgossip.Envelope) {}, [][]byte{[]byte("10"), []byte("11")}, []string{"11"}, 11)
	adapter.On("Send", mock.Anything, mock.Anything).Run(pullPhase)
	wg.Wait()

	select {
	case <-time.After(time.Second * 5):
		t.Fatal("Haven't received blocks on time")
	case msg := <-receivedBlocksChan:
		require.Equal(t, uint64(11), msg.GetDataMsg().Payload.SeqNum)
	}
}

func TestFilterForeignOrgLeadershipMessages(t *testing.T) {
	org1 := utils.OrgIdentityType("org1")
	org2 := utils.OrgIdentityType("org2")

	p1 := utils.PKIidType("p1")
	p2 := utils.PKIidType("p2")

	cs := &cryptoService{}
	adapter := &gossipAdapterMock{}

	relayedLeadershipMsgs := make(chan interface{}, 2)

	adapter.On("GetOrgOfPeer", p1).Return(org1)
	adapter.On("GetOrgOfPeer", p2).Return(org2)

	adapter.On("GetMembership").Return(utils.Members{})
	adapter.On("GetConf").Return(conf)
	adapter.On("DeMultiplex", mock.Anything).Run(func(args mock.Arguments) {
		relayedLeadershipMsgs <- args.Get(0)
	})

	joinMsg := &joinChanMsg{
		orgs2AnchorPeers: map[string][]utils.AnchorPeer{
			string(org1): {},
			string(org2): {},
		},
	}

	gc := NewGossipChannel(pkiIDInOrg1, org1, cs, channelA, adapter, joinMsg, disabledMetrics, logger)

	leadershipMsg := func(sender utils.PKIidType, creator utils.PKIidType) utils.ReceivedMessage {
		return &receivedMsg{
			pkiID: sender,
			msg: &utils.SignedGossipMessage{
				GossipMessage: &pgossip.GossipMessage{
					Channel: channelA,
					Tag:     pgossip.GossipMessage_CHAN_AND_ORG,
					Content: &pgossip.GossipMessage_LeadershipMsg{
						LeadershipMsg: &pgossip.LeadershipMessage{
							PkiId: creator,
							Timestamp: &pgossip.PeerTime{
								SeqNum: 1,
								IncNum: 1,
							},
						},
					},
				},
			},
		}
	}

	gc.HandleMessage(leadershipMsg(p1, p1))
	require.Len(t, relayedLeadershipMsgs, 1, "should have relayed a message from p1 (same org)")

	gc.HandleMessage(leadershipMsg(p2, p1))
	require.Len(t, relayedLeadershipMsgs, 1, "should not have relayed a message from p2 (foreign org)")

	gc.HandleMessage(leadershipMsg(p1, p2))
	require.Len(t, relayedLeadershipMsgs, 1, "should not have relayed a message from p2 (foreign org)")
}

func TestChangesInPeers(t *testing.T) {
	// TestChangesInPeers tracks after offline and online peers in channel
	// Scenario1: no new peers - list of peers stays with no change
	// Scenario2: new peer was added - old peers stay with no change
	// Scenario3: new peer was added - one old peer was deleted
	// Scenario4: new peer was added - one old peer hasn't been changed
	// Scenario5: new peer was added and there were no other peers before
	// Scenario6: a peer was deleted and no new peers were added
	// Scenario7: one peer was deleted and all other peers stayed with no change
	type testCase struct {
		name           string
		oldMembers     map[string]struct{}
		newMembers     map[string]struct{}
		expected       []string
		entryInChannel func(chan string)
		expectedTotal  float64
	}
	cases := []testCase{
		{
			name:       "noChanges",
			oldMembers: map[string]struct{}{"pkiID11": {}, "pkiID22": {}, "pkiID33": {}},
			newMembers: map[string]struct{}{"pkiID11": {}, "pkiID22": {}, "pkiID33": {}},
			expected:   []string{""},
			entryInChannel: func(chStr chan string) {
				chStr <- ""
			},
			expectedTotal: 3,
		},
		{
			name:       "newPeerWasAdded",
			oldMembers: map[string]struct{}{"pkiID1": {}},
			newMembers: map[string]struct{}{"pkiID1": {}, "pkiID3": {}},
			expected: []string{
				"Membership view has changed. peers went online: [[pkiID3]], current view: [[pkiID1] [pkiID3]]",
				"Membership view has changed. peers went online: [[pkiID3]], current view: [[pkiID3] [pkiID1]]",
			},
			entryInChannel: func(chStr chan string) {},
			expectedTotal:  2,
		},
		{
			name:       "newPeerAddedOldPeerDeleted",
			oldMembers: map[string]struct{}{"pkiID1": {}, "pkiID2": {}},
			newMembers: map[string]struct{}{"pkiID1": {}, "pkiID3": {}},
			expected: []string{
				"Membership view has changed. peers went offline: [[pkiID2]], peers went online: [[pkiID3]], current view: [[pkiID1] [pkiID3]]",
				"Membership view has changed. peers went offline: [[pkiID2]], peers went online: [[pkiID3]], current view: [[pkiID3] [pkiID1]]",
			},
			entryInChannel: func(chStr chan string) {},
			expectedTotal:  2,
		},
		{
			name:       "newPeersAddedOldPeerStayed",
			oldMembers: map[string]struct{}{"pkiID1": {}},
			newMembers: map[string]struct{}{"pkiID2": {}},
			expected: []string{
				"Membership view has changed. peers went offline: [[pkiID1]], peers went online: [[pkiID2]], current view: [[pkiID2]]",
				"Membership view has changed. peers went offline: [[pkiID1]], peers went online: [[pkiID2]], current view: [[pkiID2]]",
			},
			entryInChannel: func(chStr chan string) {},
			expectedTotal:  1,
		},
		{
			name:           "newPeersAddedNoOldPeers",
			oldMembers:     map[string]struct{}{},
			newMembers:     map[string]struct{}{"pkiID1": {}},
			expected:       []string{"Membership view has changed. peers went online: [[pkiID1]], current view: [[pkiID1]]"},
			entryInChannel: func(chStr chan string) {},
			expectedTotal:  1,
		},
		{
			name:           "PeerWasDeletedNoNewPeers",
			oldMembers:     map[string]struct{}{"pkiID1": {}},
			newMembers:     map[string]struct{}{},
			expected:       []string{"Membership view has changed. peers went offline: [[pkiID1]], current view: []"},
			entryInChannel: func(chStr chan string) {},
			expectedTotal:  0,
		},
		{
			name:       "onePeerWasDeletedRestStayed",
			oldMembers: map[string]struct{}{"pkiID01": {}, "pkiID02": {}, "pkiID03": {}},
			newMembers: map[string]struct{}{"pkiID01": {}, "pkiID02": {}},
			expected: []string{
				"Membership view has changed. peers went offline: [[pkiID03]], current view: [[pkiID01] [pkiID02]]",
				"Membership view has changed. peers went offline: [[pkiID03]], current view: [[pkiID02] [pkiID01]]",
			},
			entryInChannel: func(chStr chan string) {},
			expectedTotal:  2,
		},
	}

	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			tickChan := make(chan time.Time)

			buildMembers := func(rangeMembers map[string]struct{}) []utils.NetworkMember {
				var members []utils.NetworkMember
				for peerID := range rangeMembers {
					peer := utils.NetworkMember{
						Endpoint:         peerID,
						InternalEndpoint: peerID,
					}
					peer.PKIid = utils.PKIidType(peerID)
					members = append(members, peer)
				}
				return members
			}

			stopChan := make(chan struct{})

			getPeersToTrackCallCount := 0
			getListOfPeers := func() utils.Members {
				var members []utils.NetworkMember
				if getPeersToTrackCallCount == 0 {
					members = buildMembers(test.oldMembers)
					getPeersToTrackCallCount++
				} else if getPeersToTrackCallCount == 1 {
					members = buildMembers(test.newMembers)
					getPeersToTrackCallCount++
					close(stopChan) // no more ticks, stop tracking changes
				} else {
					t.Fatal("getPeersToTrack called too many times")
				}
				return members
			}

			mt := &membershipTracker{
				getPeersToTrack: getListOfPeers,
				report:          logger.Infof,
				stopChan:        stopChan,
				tickerC:         tickChan,
				metrics:         disabledMetrics,
				channelID:       utils.ChannelID("test"),
			}

			wgMT := sync.WaitGroup{}
			wgMT.Add(1)
			go func() {
				mt.trackMembershipChanges()
				wgMT.Done()
			}()

			tickChan <- time.Time{}

			// mt needs to have received a tick before it was closed
			wgMT.Wait()
		})
	}
}

func TestMembershiptrackerStopWhenGCStops(t *testing.T) {
	// membershipTracker is invoked when gossip channel starts
	// membershipTracker, as long as gossip channel was not stopped, has printed the right thing
	// membershipTracker does not print after gossip channel was stopped
	// membershipTracker stops running after gossip channel was stopped
	cs := &cryptoService{}
	pkiID1 := utils.PKIidType("1")
	adapter := new(gossipAdapterMock)

	jcm := &joinChanMsg{}

	peerA := utils.NetworkMember{
		PKIid:            pkiIDInOrg1,
		Endpoint:         "a",
		InternalEndpoint: "a",
	}
	peerB := utils.NetworkMember{
		PKIid:            pkiIDInOrg2,
		Endpoint:         "b",
		InternalEndpoint: "b",
	}

	conf := conf
	conf.RequestStateInfoInterval = time.Hour
	conf.PullInterval = time.Hour
	conf.TimeForMembershipTracker = time.Millisecond * 10

	adapter.On("Gossip", mock.Anything)
	adapter.On("Forward", mock.Anything)
	adapter.On("Send", mock.Anything, mock.Anything)
	adapter.On("DeMultiplex", mock.Anything)
	adapter.On("GetConf").Return(conf)
	adapter.On("GetOrgOfPeer", pkiIDInOrg1).Return(orgInChannelA)
	adapter.On("GetOrgOfPeer", pkiIDInOrg2).Return(orgInChannelA)
	adapter.On("GetOrgOfPeer", mock.Anything).Return(utils.OrgIdentityType(nil))

	waitForHandleMsgChan := make(chan struct{})

	adapter.On("GetMembership").Return(utils.Members{peerA}).Run(func(args mock.Arguments) {
		waitForHandleMsgChan <- struct{}{}
	}).Once()

	var check uint32
	atomic.StoreUint32(&check, 0)

	gc := NewGossipChannel(pkiID1, orgInChannelA, cs, channelA, adapter, jcm, disabledMetrics, logger)

	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg1, msg: createStateInfoMsg(1, pkiIDInOrg1, channelA)})
	gc.HandleMessage(&receivedMsg{pkiID: pkiIDInOrg2, msg: createStateInfoMsg(1, pkiIDInOrg2, channelA)})
	<-waitForHandleMsgChan

	wg := sync.WaitGroup{}
	wg.Add(1)
	adapter.On("GetMembership").Return(utils.Members{peerB}).Run(func(args mock.Arguments) {
		defer wg.Done()
		gc.(*gossipChannel).Stop()
	}).Once()

	atomic.StoreUint32(&check, 1)

	wg.Wait()
	adapter.On("GetMembership").Return(utils.Members{peerB}).Run(func(args mock.Arguments) {
		t.Fatalf("Membership tracker should have been stopped already.")
	})

	time.Sleep(conf.TimeForMembershipTracker * 2)
}
