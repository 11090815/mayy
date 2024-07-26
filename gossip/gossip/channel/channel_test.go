package channel

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/metrics/disabled"
	"github.com/11090815/mayy/common/mlog"
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
		BlockExpirationInterval:        time.Second * 6,
		StateInfoCacheSweepInterval:    time.Second,
		TimeForMembershipTracker:       time.Second * 5,
		DigestWaitTime:                 shortenedWaitTime / 2,
		RequestWaitTime:                shortenedWaitTime,
		ResponseWaitTime:               shortenedWaitTime,
		LeadershipMsgExpirationTimeout: DefaultLeadershipMsgExpirationTimeout,
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

	time.Sleep(gc.(*gossipChannel).adapter.GetConf().BlockExpirationInterval + time.Second)

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

	time.Sleep(gc.(*gossipChannel).adapter.GetConf().BlockExpirationInterval + time.Second)

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
		Tag: pgossip.GossipMessage_CHAN_OR_ORG,
		Channel: channelA,
		Content: &pgossip.GossipMessage_StateInfoPullReq{
			StateInfoPullReq: &pgossip.StateInfoPullRequest{
				Channel_MAC: utils.GenerateMAC(pkiID3, channelA),
			},
		},
	})
	req := &receivedMsg{
		pkiID: pkiID3,
		msg: sgm,
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
		Tag: pgossip.GossipMessage_CHAN_OR_ORG,
		Channel: channelA,
		Content: &pgossip.GossipMessage_StateInfoPullReq{
			StateInfoPullReq: &pgossip.StateInfoPullRequest{
				Channel_MAC: utils.GenerateMAC(pkiID2, channelA),
			},
		},
	})
	req = &receivedMsg{
		pkiID: pkiID2,
		msg: sgm,
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
