package gossip

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/gossip/algo"
	"github.com/11090815/mayy/gossip/gossip/pull"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pcommon"
	"github.com/11090815/mayy/protobuf/pgossip"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var logger = utils.GetLogger("certstore", "test", mlog.DebugLevel, true, true)

/* ------------------------------------------------------------------------------------------ */

type naiveCryptoService struct {
	sync.RWMutex
	allowedPkiIDS       map[string]struct{}
	revokedPkiIDS       map[string]struct{}
	expirationTimesLock *sync.RWMutex
	expirationTimes     map[string]time.Time
}

func (ncs *naiveCryptoService) OrgByPeerIdentity(utils.PeerIdentityType) utils.OrgIdentityType {
	return nil
}

func (ncs *naiveCryptoService) Expiration(peerIdentity utils.PeerIdentityType) (time.Time, error) {
	if ncs.expirationTimesLock != nil {
		ncs.expirationTimesLock.RLock()
		defer ncs.expirationTimesLock.RUnlock()
	}
	if exp, exists := ncs.expirationTimes[peerIdentity.String()]; exists {
		return exp, nil
	}
	return time.Now().Add(time.Hour), nil
}

func (ncs *naiveCryptoService) VerifyByChannel(_ utils.ChannelID, peerIdentity utils.PeerIdentityType, _, _ []byte) error {
	if ncs.allowedPkiIDS == nil {
		return nil
	}
	if _, allowed := ncs.allowedPkiIDS[peerIdentity.String()]; allowed {
		return nil
	}
	return errors.NewError("invalid")
}

func (ncs *naiveCryptoService) ValidateIdentity(peerIdentity utils.PeerIdentityType) error {
	ncs.RLock()
	defer ncs.RUnlock()
	if ncs.revokedPkiIDS == nil {
		return nil
	}
	if _, revoked := ncs.revokedPkiIDS[ncs.GetPKIidOfCert(peerIdentity).String()]; revoked {
		return errors.NewError("revoked")
	}
	return nil
}

func (ncs *naiveCryptoService) GetPKIidOfCert(peerIdentity utils.PeerIdentityType) utils.PKIidType {
	return utils.PKIidType(peerIdentity)
}

func (ncs *naiveCryptoService) VerifyBlock(channelID utils.ChannelID, seqNum uint64, block *pcommon.Block) error {
	return nil
}

func (ncs *naiveCryptoService) VerifyBlockAttestation(channelID utils.ChannelID, block *pcommon.Block) error {
	return nil
}

func (ncs *naiveCryptoService) Sign(msg []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte("123456"))
	mac.Write(msg)
	return mac.Sum(nil), nil
}

func (ncs *naiveCryptoService) Verify(peerIdentity utils.PeerIdentityType, signature, message []byte) error {
	mac := hmac.New(sha256.New, []byte("123456"))
	mac.Write(message)
	expected := mac.Sum(nil)
	if !bytes.Equal(signature, expected) {
		return errors.NewError("invalid signature")
	}
	return nil
}

func (ncs *naiveCryptoService) revoke(pkiID utils.PKIidType) {
	ncs.Lock()
	defer ncs.Unlock()
	if ncs.revokedPkiIDS == nil {
		ncs.revokedPkiIDS = make(map[string]struct{})
	}
	ncs.revokedPkiIDS[pkiID.String()] = struct{}{}
}

/* ------------------------------------------------------------------------------------------ */

var ncs = &naiveCryptoService{revokedPkiIDS: make(map[string]struct{})}

/* ------------------------------------------------------------------------------------------ */

type pullerMock struct {
	mock.Mock
	pull.PullMediator
}

/* ------------------------------------------------------------------------------------------ */

type sentMsg struct {
	msg *utils.SignedGossipMessage
	mock.Mock
	connInfo *utils.ConnectionInfo
}

func (sm *sentMsg) Ack(error) {}

func (rm *sentMsg) Respond(msg *pgossip.GossipMessage) {
	rm.Called(msg)
}

func (rm *sentMsg) GetSignedGossipMessage() *utils.SignedGossipMessage {
	return rm.msg
}

func (rm *sentMsg) GetConnectionInfo() *utils.ConnectionInfo {
	return rm.connInfo
}

func (rm *sentMsg) GetSourceEnvelope() *pgossip.Envelope {
	return rm.msg.Envelope
}

/* ------------------------------------------------------------------------------------------ */

type senderMock struct {
	mock.Mock
	sync.Mutex
}

func (s *senderMock) Send(msg *utils.SignedGossipMessage, peers ...*utils.RemotePeer) {
	s.Lock()
	defer s.Unlock()
	s.Called(msg, peers)
}

/* ------------------------------------------------------------------------------------------ */

type membershipSvcMock struct {
	mock.Mock
}

func (m *membershipSvcMock) GetMembership() utils.Members {
	args := m.Called()
	return args.Get(0).(utils.Members)
}

/* ------------------------------------------------------------------------------------------ */

func createBadlySignedPeerIdentityMessage() *utils.SignedGossipMessage {
	peerIdentity := &pgossip.PeerIdentity{
		PkiId: []byte("id"),
		Cert:  []byte("id"),
	}
	signer := func(msg []byte) ([]byte, error) {
		return (&naiveCryptoService{}).Sign(msg)
	}

	m := &pgossip.GossipMessage{
		Channel: nil,
		Nonce:   0,
		Tag:     pgossip.GossipMessage_EMPTY,
		Content: &pgossip.GossipMessage_PeerIdentity{
			PeerIdentity: peerIdentity,
		},
	}
	sgm := &utils.SignedGossipMessage{
		GossipMessage: m,
	}
	sgm.Sign(signer)
	if sgm.Envelope.Signature[0] == 0 {
		sgm.Envelope.Signature[0] = 1
	} else {
		sgm.Envelope.Signature[0] = 0
	}

	return sgm
}

func createUpdateMessage(nonce uint64, sgm *utils.SignedGossipMessage) utils.ReceivedMessage {
	msg := &pgossip.GossipMessage{
		Tag: pgossip.GossipMessage_EMPTY,
		Content: &pgossip.GossipMessage_DataUpdate{
			DataUpdate: &pgossip.DataUpdate{
				MsgType: pgossip.PullMsgType_IDENTITY_MSG,
				Nonce:   nonce,
				Data:    []*pgossip.Envelope{sgm.Envelope},
			},
		},
	}
	_sgm, _ := utils.NoopSign(msg)
	return &sentMsg{msg: _sgm}
}

func createObjects(factory func(uint64) utils.ReceivedMessage, consumer pull.MsgConsumer) (pull.PullMediator, *certStore, *senderMock) {
	if consumer == nil {
		consumer = func(message *utils.SignedGossipMessage) {}
	}

	waitTime := time.Millisecond * 300
	config := pull.PullConfig{
		MsgType:           pgossip.PullMsgType_IDENTITY_MSG,
		PeerCountToSelect: 1,
		PullInterval:      time.Second,
		Tag:               pgossip.GossipMessage_EMPTY,
		Channel:           nil,
		PullEngineConfig: algo.Config{
			DigestWaitTime:   waitTime / 2,
			RequestWaitTime:  waitTime,
			ResponseWaitTime: waitTime,
		},
	}

	sender := &senderMock{}
	memberSVC := &membershipSvcMock{}
	memberSVC.On("GetMembership").Return(utils.Members{{PKIid: utils.PKIidType("aha"), Endpoint: "127.0.0.1:2048"}})

	var cs *certStore
	adapter := &pull.PullAdapter{
		Sender: sender,
		MsgConsumer: func(msg *utils.SignedGossipMessage) {
			cs.idMapper.Put(msg.GetPeerIdentity().PkiId, msg.GetPeerIdentity().Cert)
			consumer(msg)
		},
		IdentitfierExtractor: func(sgm *utils.SignedGossipMessage) string {
			return utils.PKIidType(sgm.GetPeerIdentity().PkiId).String()
		},
		MembershipService: memberSVC,
	}

	pullMediator := pull.NewPullMediator(config, adapter, logger)
	selfIdentity := utils.PeerIdentityType("test-id")
	cs = newCertStore(pullerMock{PullMediator: pullMediator}, utils.NewIdentityMapper(ncs, selfIdentity, func(pkiID utils.PKIidType, _ utils.PeerIdentityType) {
		pullMediator.Remove(pkiID.String())
	}, ncs), selfIdentity, ncs, logger)

	wg := sync.WaitGroup{}
	wg.Add(1)
	sentHello := false
	sentDataReq := false
	l := sync.Mutex{}
	sender.On("Send", mock.Anything, mock.Anything).Run(func(arg mock.Arguments) {
		msg := arg.Get(0).(*utils.SignedGossipMessage)
		l.Lock()
		defer l.Unlock()

		if hello := msg.GetHello(); hello != nil && !sentHello {
			sentHello = true
			go cs.handleMessage(createDigest(hello.Nonce))
		}

		if dataReq := msg.GetDataReq(); dataReq != nil && !sentDataReq {
			sentDataReq = true
			cs.handleMessage(factory(dataReq.Nonce))
			wg.Done()
		}
	})
	wg.Wait()
	return pullMediator, cs, sender
}

func createDigest(nonce uint64) utils.ReceivedMessage {
	digest := &pgossip.GossipMessage{
		Tag: pgossip.GossipMessage_EMPTY,
		Content: &pgossip.GossipMessage_DataDig{
			DataDig: &pgossip.DataDigest{
				Nonce:   nonce,
				MsgType: pgossip.PullMsgType_IDENTITY_MSG,
				Digests: [][]byte{[]byte("A"), []byte("C")},
			},
		},
	}
	sMsg, _ := utils.NoopSign(digest)
	return &sentMsg{msg: sMsg}
}

func createMismatchedUpdateMessage() *utils.SignedGossipMessage {
	peerIdentity := &pgossip.PeerIdentity{
		PkiId: []byte("id"),
		Cert:  []byte("identity"),
	}
	signer := func(msg []byte) ([]byte, error) {
		return (&naiveCryptoService{}).Sign(msg)
	}

	m := &pgossip.GossipMessage{
		Channel: nil,
		Nonce:   0,
		Tag:     pgossip.GossipMessage_EMPTY,
		Content: &pgossip.GossipMessage_PeerIdentity{
			PeerIdentity: peerIdentity,
		},
	}
	sgm := &utils.SignedGossipMessage{
		GossipMessage: m,
	}
	sgm.Sign(signer)

	return sgm
}

func createValidUpdateMessage() *utils.SignedGossipMessage {
	peerIdentity := &pgossip.PeerIdentity{
		PkiId: []byte("id"),
		Cert:  []byte("id"),
	}
	signer := func(msg []byte) ([]byte, error) {
		return (&naiveCryptoService{}).Sign(msg)
	}

	m := &pgossip.GossipMessage{
		Channel: nil,
		Nonce:   0,
		Tag:     pgossip.GossipMessage_EMPTY,
		Content: &pgossip.GossipMessage_PeerIdentity{
			PeerIdentity: peerIdentity,
		},
	}
	sgm := &utils.SignedGossipMessage{
		GossipMessage: m,
	}
	sgm.Sign(signer)

	return sgm
}

func testCertificateUpdate(t *testing.T, shouldSucceed bool, cs *certStore) {
	msg, _ := utils.NoopSign(&pgossip.GossipMessage{
		Channel: []byte(""),
		Tag:     pgossip.GossipMessage_EMPTY,
		Content: &pgossip.GossipMessage_Hello{
			Hello: &pgossip.GossipHello{
				Nonce:    0,
				Metadata: nil,
				MsgType:  pgossip.PullMsgType_IDENTITY_MSG,
			},
		},
	})
	hello := &sentMsg{
		msg: msg,
		connInfo: &utils.ConnectionInfo{
			PkiID:    utils.PKIidType("test"),
			Endpoint: "127.0.0.1:2049",
		},
	}
	responseChan := make(chan *pgossip.GossipMessage, 1)
	hello.On("Respond", mock.Anything).Run(func(arg mock.Arguments) {
		msg := arg.Get(0).(*pgossip.GossipMessage)
		require.NotNil(t, msg.GetDataDig())
		responseChan <- msg
	})
	cs.handleMessage(hello)
	select {
	case msg := <-responseChan:
		if shouldSucceed {
			require.Len(t, msg.GetDataDig().Digests, 2, "Valid identity hasn't entered the certStore")
		} else {
			require.Len(t, msg.GetDataDig().Digests, 1, "Mismatched identity has been injected into certStore")
		}
	case <-time.After(time.Second):
		t.Fatal("Didn't respond with a digest message in a timely manner")
	}
}

/* ------------------------------------------------------------------------------------------ */

func TestCertStoreBadSignature(t *testing.T) {
	badSignature := func(nonce uint64) utils.ReceivedMessage {
		return createUpdateMessage(nonce, createBadlySignedPeerIdentityMessage())
	}
	pm, cs, _ := createObjects(badSignature, nil)
	defer pm.Stop()
	defer cs.stop()
	testCertificateUpdate(t, false, cs)
}

func TestCertStoreMismatchedIdentity(t *testing.T) {
	mismatchedIdentity := func(nonce uint64) utils.ReceivedMessage {
		return createUpdateMessage(nonce, createMismatchedUpdateMessage())
	}
	pm, cs, _ := createObjects(mismatchedIdentity, nil)
	defer pm.Stop()
	defer cs.stop()
	testCertificateUpdate(t, false, cs)
}

func TestCertStoreShouldSucceed(t *testing.T) {
	validIdentity := func(nonce uint64) utils.ReceivedMessage {
		return createUpdateMessage(nonce, createValidUpdateMessage())
	}
	pm, cs, _ := createObjects(validIdentity, nil)
	defer pm.Stop()
	defer cs.stop()
	testCertificateUpdate(t, true, cs)
}

func TestCertRevocation(t *testing.T) {
	defer func() {
		ncs.revokedPkiIDS = map[string]struct{}{}
	}()

	totallyFineIdentity := func(nonce uint64) utils.ReceivedMessage {
		return createUpdateMessage(nonce, createValidUpdateMessage())
	}

	askedForIdentity := make(chan struct{}, 1)

	pm, cStore, sender := createObjects(totallyFineIdentity, func(message *utils.SignedGossipMessage) {
		askedForIdentity <- struct{}{}
	})
	defer cStore.stop()
	defer pm.Stop()
	testCertificateUpdate(t, true, cStore)
	// Should have asked for an identity for the first time
	require.Len(t, askedForIdentity, 1)
	// Drain channel
	<-askedForIdentity
	// Now it's 0
	require.Len(t, askedForIdentity, 0)

	sentHello := false
	l := sync.Mutex{}
	sender.Lock()
	sender.Mock = mock.Mock{}
	sender.On("Send", mock.Anything, mock.Anything).Run(func(arg mock.Arguments) {
		msg := arg.Get(0).(*utils.SignedGossipMessage)
		l.Lock()
		defer l.Unlock()

		if hello := msg.GetHello(); hello != nil && !sentHello {
			sentHello = true
			dig := &pgossip.GossipMessage{
				Tag: pgossip.GossipMessage_EMPTY,
				Content: &pgossip.GossipMessage_DataDig{
					DataDig: &pgossip.DataDigest{
						Nonce:   hello.Nonce,
						MsgType: pgossip.PullMsgType_IDENTITY_MSG,
						Digests: [][]byte{[]byte("id")},
					},
				},
			}
			sMsg, _ := utils.NoopSign(dig)
			go cStore.handleMessage(&sentMsg{msg: sMsg})
		}

		if dataReq := msg.GetDataReq(); dataReq != nil {
			askedForIdentity <- struct{}{}
		}
	})
	sender.Unlock()
	testCertificateUpdate(t, true, cStore)
	// Shouldn't have asked, because already got identity
	select {
	case <-time.After(time.Second * 5):
	case <-askedForIdentity:
		require.Fail(t, "Shouldn't have asked for an identity, because we already have it")
	}
	require.Len(t, askedForIdentity, 0)
	// Revoke the identity
	ncs.revoke(utils.PKIidType("id"))
	cStore.suspectPeers(func(id utils.PeerIdentityType) bool {
		return string(id) == "id"
	})

	l.Lock()
	sentHello = false
	l.Unlock()

	select {
	case <-time.After(time.Second * 5):
		require.Fail(t, "Didn't ask for identity, but should have. Looks like identity hasn't expired")
	case <-askedForIdentity:
	}
}
