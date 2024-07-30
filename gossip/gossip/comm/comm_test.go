package comm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/metrics/disabled"
	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/metrics"
	"github.com/11090815/mayy/gossip/mocks"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/internal/pkg/comm"
	"github.com/11090815/mayy/protobuf/pcommon"
	"github.com/11090815/mayy/protobuf/pgossip"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	hmacKey           = []byte{1, 2, 3, 4, 5, 6}
	noopPurgeIdentity = func(pkiid utils.PKIidType, identity utils.PeerIdentityType) {}
	noopMutator       = func(sgm *utils.SignedGossipMessage) *utils.SignedGossipMessage {
		return sgm
	}
	acceptAll = func(msg any) bool {
		return true
	}
	testCommConfig = Config{
		DialTimeout:  300 * time.Millisecond,
		ConnTimeout:  DefaultConnTimeout,
		RecvBuffSize: DefaultRecvBuffSize,
		SendBuffSize: DefaultSendBuffSize,
	}
	disabledMetrics = metrics.NewGossipMetrics(&disabled.Provider{}).CommMetrics
	mockSP          = &mockSecProvider{SecurityAdvisor: mocks.SecurityAdvisor{}}

	signer = func(msg []byte) ([]byte, error) {
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(msg)
		return mac.Sum(nil), nil
	}
	verifier = func(identity utils.PeerIdentityType, signature, message []byte) error {
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(message)
		expected := mac.Sum(nil)
		if !bytes.Equal(expected, signature) {
			return errors.NewErrorf("invalid signature against identity %x", identity)
		}
		return nil
	}
)

func init() {
	mockSP.SecurityAdvisor.On("OrgByPeerIdentity", mock.Anything).Return(utils.OrgIdentityType{})
}

/* ------------------------------------------------------------------------------------------ */

type tlsType int

const (
	none tlsType = iota
	oneWayTLS
	mutualTLS
)

/* ------------------------------------------------------------------------------------------ */

type msgMutator func(*utils.SignedGossipMessage) *utils.SignedGossipMessage

/* ------------------------------------------------------------------------------------------ */

type mockSecProvider struct {
	mocks.SecurityAdvisor
}

func (msp *mockSecProvider) OrgByPeerIdentity(identity utils.PeerIdentityType) utils.OrgIdentityType {
	return msp.SecurityAdvisor.OrgByPeerIdentity(identity)
}

func (msp *mockSecProvider) Expiration(utils.PeerIdentityType) (time.Time, error) {
	return time.Now().Add(time.Hour), nil
}

func (msp *mockSecProvider) ValidateIdentity(utils.PeerIdentityType) error {
	return nil
}

func (msp *mockSecProvider) GetPKIidOfCert(identity utils.PeerIdentityType) utils.PKIidType {
	return utils.PKIidType(identity)
}

func (msp *mockSecProvider) VerifyBlock(channelID utils.ChannelID, seqNum uint64, signedBlock *pcommon.Block) error {
	return nil
}

func (msp *mockSecProvider) VerifyBlockAttestation(channelID utils.ChannelID, signedBlock *pcommon.Block) error {
	return nil
}

func (msp *mockSecProvider) Sign(msg []byte) ([]byte, error) {
	return signer(msg)
}

func (msp *mockSecProvider) Verify(identity utils.PeerIdentityType, signature, message []byte) error {
	return verifier(identity, signature, message)
}

func (msp *mockSecProvider) VerifyByChannel(_ utils.ChannelID, _ utils.PeerIdentityType, _, _ []byte) error {
	return nil
}

/* ------------------------------------------------------------------------------------------ */

type commGRPC struct {
	*commImpl
	gRPCServer *comm.GRPCServer
}

func newCommInstanceOnlyWithMetrics(t *testing.T, metrics *metrics.CommMetrics, sp *mockSecProvider,
	gRPCServer *comm.GRPCServer, certs *utils.TLSCertificates, sdo utils.PeerSecureDialOpts, dialOpts ...grpc.DialOption) Comm {
	_, portStr, err := net.SplitHostPort(gRPCServer.Address())
	require.NoError(t, err)
	endpoint := fmt.Sprintf("127.0.0.1:%s", portStr)
	identity := []byte(endpoint)
	identityMapper := utils.NewIdentityMapper(sp, identity, noopPurgeIdentity, sp)
	logger := utils.GetLogger(utils.CommLogger, string(identity), mlog.DebugLevel, true, true)
	inst, err := NewCommInstance(gRPCServer.Server(), certs, identityMapper, identity, logger, sdo, sp, metrics, testCommConfig, dialOpts...)
	require.NoError(t, err)

	go func() {
		err := gRPCServer.Start()
		require.NoError(t, err)
	}()

	return &commGRPC{commImpl: inst.(*commImpl), gRPCServer: gRPCServer}
}

func newCommInstanceOnly(t *testing.T, sp *mockSecProvider, gRPCServer *comm.GRPCServer, certs *utils.TLSCertificates,
	secureDialOpts utils.PeerSecureDialOpts, dialOpts ...grpc.DialOption) Comm {
	return newCommInstanceOnlyWithMetrics(t, disabledMetrics, sp, gRPCServer, certs, secureDialOpts, dialOpts...)
}

func newCommInstance(t *testing.T, sp *mockSecProvider) (Comm, int) {
	port, gRPCServer, certs, secureDialOpts, dialOpts := utils.CreateGRPCLayer()
	inst := newCommInstanceOnly(t, sp, gRPCServer, certs, secureDialOpts, dialOpts...)
	return inst, port
}

func (cg *commGRPC) Stop() {
	cg.commImpl.Stop()
	cg.gRPCServer.Stop()
}

func handshaker(t *testing.T, port int, selfID string, comm Comm, connMutator msgMutator, connType tlsType) <-chan utils.ReceivedMessage {
	cert := generateCertificateOrPanic()
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	if connType == mutualTLS {
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	ta := credentials.NewTLS(tlsConfig)
	secureOpts := grpc.WithTransportCredentials(ta)
	if connType == none {
		secureOpts = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	acceptCh := comm.Accept(acceptAll)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	target := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := grpc.DialContext(ctx, target, secureOpts, grpc.WithBlock())
	require.NoError(t, err)
	client := pgossip.NewGossipClient(conn)
	stream, err := client.GossipStream(context.Background())
	require.NoError(t, err)

	var clientCertHash []byte // 计算自己证书的摘要值
	if len(tlsConfig.Certificates) > 0 {
		clientCertHash = certHashFromRawCert(tlsConfig.Certificates[0].Certificate[0])
	}
	pkiID := utils.PKIidType(selfID)
	msg, _ := createConnectionMsg(pkiID, clientCertHash, []byte(selfID), signer, false)
	msg = connMutator(msg)
	stream.Send(msg.Envelope)

	envelope, err := stream.Recv()
	if err != nil {
		return acceptCh
	}
	require.NoError(t, err)
	msg, err = utils.EnvelopeToSignedGossipMessage(envelope)
	require.NoError(t, err)
	require.Equal(t, []byte(target), msg.GetConnEstablish().PkiId)
	require.Equal(t, extractCertificateHashFromContext(stream.Context()), msg.GetConnEstablish().TlsCertHash)
	msg2Send := createGossipMsg()
	go stream.Send(msg2Send.Envelope)
	return acceptCh
}

// generateCertificateOrPanic 产生一个自签名的 TLS 证书。
func generateCertificateOrPanic() tls.Certificate {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		SerialNumber: sn,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotAfter:     time.Now().Add(time.Hour * 24),
	}
	rawBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	encodedCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rawBytes})
	encodedKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})
	cert, err := tls.X509KeyPair(encodedCert, encodedKey)
	if err != nil {
		panic(err)
	}
	return cert
}

func createGossipMsg() *utils.SignedGossipMessage {
	msg, _ := utils.NoopSign(&pgossip.GossipMessage{
		Tag:   pgossip.GossipMessage_EMPTY,
		Nonce: utils.RandomUint64(),
		Content: &pgossip.GossipMessage_DataMsg{
			DataMsg: &pgossip.DataMessage{},
		},
	})
	return msg
}

func remotePeer(port int) *utils.RemotePeer {
	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	return &utils.RemotePeer{Endpoint: endpoint, PKIID: utils.PKIidType(endpoint)}
}

func getAvailablePort(t *testing.T) (int, string, net.Listener) {
	ll, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	endpoint := ll.Addr().String()
	_, portStr, err := net.SplitHostPort(endpoint)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return port, endpoint, ll
}

func waitForMessages(t *testing.T, msgChan chan uint64, count int, errMsg string) {
	c := 0
	waiting := true
	timer := time.NewTimer(time.Second * 10)
	for waiting {
		select {
		case <-msgChan:
			c++
			if c == count {
				waiting = false
			}
		case <-timer.C:
			waiting = false
		}
	}
	require.Equal(t, count, c, errMsg)
}

func establishSession(t *testing.T, port int) (pgossip.Gossip_GossipStreamClient, error) {
	cert := generateCertificateOrPanic()
	secureOpts := grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
	}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := grpc.DialContext(ctx, endpoint, secureOpts, grpc.WithBlock())
	require.NoError(t, err)
	if err != nil {
		return nil, err
	}
	client := pgossip.NewGossipClient(conn)
	stream, err := client.GossipStream(context.Background())
	require.NoError(t, err)
	if err != nil {
		return nil, err
	}
	clientCertHash := certHashFromRawCert(cert.Certificate[0])
	pkiID := utils.PKIidType([]byte{1, 2, 3})
	msg, _ := createConnectionMsg(pkiID, clientCertHash, []byte{1, 2, 3}, signer, false)
	stream.Send(msg.Envelope)
	envelope, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	require.NotNil(t, envelope)
	return stream, nil
}

/* ------------------------------------------------------------------------------------------ */

func TestMutualParallelSendWithAck(t *testing.T) {
	msgNum := 10

	comm1, port1 := newCommInstance(t, mockSP)
	comm2, port2 := newCommInstance(t, mockSP)
	defer comm1.Stop()
	defer comm2.Stop()

	acceptData := func(msg any) bool {
		m := msg.(utils.ReceivedMessage).GetSignedGossipMessage()
		return m.GetDataMsg() != nil
	}

	inc1 := comm1.Accept(acceptData)
	inc2 := comm2.Accept(acceptData)

	comm1.Send(createGossipMsg(), remotePeer(port2))
	<-inc2

	for i := 0; i < msgNum; i++ {
		go comm1.SendWithAck(createGossipMsg(), time.Second*3, 1, remotePeer(port2))
	}

	for i := 0; i < msgNum; i++ {
		go comm2.SendWithAck(createGossipMsg(), time.Second*3, 1, remotePeer(port1))
	}

	go func() {
		for i := 0; i < msgNum; i++ {
			m := <-inc1
			t.Log(m)
		}
	}()

	go func() {
		for i := 0; i < msgNum; i++ {
			<-inc2
		}
	}()
}

func TestHandshake1(t *testing.T) {
	assertPositivePath := func(msg utils.ReceivedMessage, endpoint string) {
		expectedPKIID := utils.PKIidType(endpoint)
		require.Equal(t, expectedPKIID, msg.GetConnectionInfo().PkiID)
		require.Equal(t, utils.PeerIdentityType(endpoint), msg.GetConnectionInfo().Identity)
		require.NotNil(t, msg.GetConnectionInfo().AuthInfo)
		sig, _ := signer(msg.GetConnectionInfo().AuthInfo.SignedData)
		require.Equal(t, sig, msg.GetConnectionInfo().AuthInfo.Signature)
	}

	port, endpoint, listener := getAvailablePort(t)
	s := grpc.NewServer()
	identity := utils.PeerIdentityType(endpoint)
	idMapper := utils.NewIdentityMapper(mockSP, identity, noopPurgeIdentity, mockSP)
	logger := utils.GetLogger(utils.CommLogger, endpoint, mlog.DebugLevel, true, true)
	inst, err := NewCommInstance(s, nil, idMapper, identity, logger, func() []grpc.DialOption {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}, mockSP, disabledMetrics, testCommConfig)
	go s.Serve(listener)
	require.NoError(t, err)

	var msg utils.ReceivedMessage
	_, tempEndpoint, tempListener := getAvailablePort(t)
	tempListener.Close()
	acceptChan := handshaker(t, port, tempEndpoint, inst, noopMutator, none)
	select {
	case <-time.After(time.Second * 4):
		require.FailNow(t, "Didn't receive a message, seems like handshake failed")
	case msg = <-acceptChan:
	}
	assertPositivePath(msg, tempEndpoint)
	inst.Stop()
	s.Stop()
	time.Sleep(time.Second)
}

func TestHandshake2(t *testing.T) {
	assertPositivePath := func(msg utils.ReceivedMessage, endpoint string) {
		expectedPKIID := utils.PKIidType(endpoint)
		require.Equal(t, expectedPKIID, msg.GetConnectionInfo().PkiID)
		require.Equal(t, utils.PeerIdentityType(endpoint), msg.GetConnectionInfo().Identity)
		require.NotNil(t, msg.GetConnectionInfo().AuthInfo)
		sig, _ := signer(msg.GetConnectionInfo().AuthInfo.SignedData)
		require.Equal(t, sig, msg.GetConnectionInfo().AuthInfo.Signature)
	}
	comm, port := newCommInstance(t, mockSP)
	defer comm.Stop()
	var msg utils.ReceivedMessage
	_, tempEndpoint, tempListener := getAvailablePort(t)
	tempListener.Close()
	acceptChan := handshaker(t, port, tempEndpoint, comm, noopMutator, mutualTLS)
	select {
	case <-time.After(time.Second * 4):
		require.FailNow(t, "Didn't receive a message, seems like handshake failed")
	case msg = <-acceptChan:
	}
	assertPositivePath(msg, tempEndpoint)

	_, tempEndpoint, tempListener = getAvailablePort(t)
	tempListener.Close()
	acceptChan = handshaker(t, port, tempEndpoint, comm, noopMutator, oneWayTLS)
	time.Sleep(time.Second)
	require.Equal(t, 0, len(acceptChan))

	mutator := func(sgm *utils.SignedGossipMessage) *utils.SignedGossipMessage {
		sgm.GetConnEstablish().PkiId = []byte("xxxx")
		sgm.Sign(signer)
		return sgm
	}
	acceptChan = handshaker(t, port, tempEndpoint, comm, mutator, mutualTLS)
	time.Sleep(time.Second)
	require.Equal(t, 0, len(acceptChan))

	mutator = func(sgm *utils.SignedGossipMessage) *utils.SignedGossipMessage {
		sgm.GetConnEstablish().TlsCertHash = append(sgm.GetConnEstablish().TlsCertHash, 1)
		sgm.Sign(signer)
		return sgm
	}
	acceptChan = handshaker(t, port, tempEndpoint, comm, mutator, mutualTLS)
	time.Sleep(time.Second)
	require.Equal(t, 0, len(acceptChan))
}

func TestConnectUnexpectedPeer(t *testing.T) {
	identityByPort := func(port int) utils.PeerIdentityType {
		return utils.PeerIdentityType(fmt.Sprintf("127.0.0.1:%d", port))
	}

	customSP := &mockSecProvider{SecurityAdvisor: mocks.SecurityAdvisor{}}

	comm1Port, gRPCServer1, certs1, secureDialOpts1, dialOpts1 := utils.CreateGRPCLayer()
	comm2Port, gRPCServer2, certs2, secureDialOpts2, dialOpts2 := utils.CreateGRPCLayer()
	comm3Port, gRPCServer3, certs3, secureDialOpts3, dialOpts3 := utils.CreateGRPCLayer()
	comm4Port, gRPCServer4, certs4, secureDialOpts4, dialOpts4 := utils.CreateGRPCLayer()

	customSP.SecurityAdvisor.On("OrgByPeerIdentity", identityByPort(comm1Port)).Return(utils.OrgIdentityType("org1"))
	customSP.SecurityAdvisor.On("OrgByPeerIdentity", identityByPort(comm2Port)).Return(utils.OrgIdentityType("org2"))
	customSP.SecurityAdvisor.On("OrgByPeerIdentity", identityByPort(comm3Port)).Return(utils.OrgIdentityType("org3"))
	customSP.SecurityAdvisor.On("OrgByPeerIdentity", identityByPort(comm4Port)).Return(utils.OrgIdentityType("org2"))

	comm1 := newCommInstanceOnly(t, customSP, gRPCServer1, certs1, secureDialOpts1, dialOpts1...)
	comm2 := newCommInstanceOnly(t, mockSP, gRPCServer2, certs2, secureDialOpts2, dialOpts2...)
	comm3 := newCommInstanceOnly(t, mockSP, gRPCServer3, certs3, secureDialOpts3, dialOpts3...)
	comm4 := newCommInstanceOnly(t, mockSP, gRPCServer4, certs4, secureDialOpts4, dialOpts4...)

	defer comm1.Stop()
	defer comm2.Stop()
	defer comm3.Stop()
	defer comm4.Stop()

	time.Sleep(time.Second)

	messagesForComm1 := comm1.Accept(acceptAll)
	messagesForComm2 := comm2.Accept(acceptAll)
	messagesForComm3 := comm3.Accept(acceptAll)

	comm4.Send(createGossipMsg(), remotePeer(comm1Port))
	<-messagesForComm1
	comm1.CloseConn(remotePeer(comm4Port))
	time.Sleep(time.Second)

	t.Run("Same org", func(t *testing.T) {
		unexpectedRemotePeer := remotePeer(comm2Port)
		unexpectedRemotePeer.PKIID = remotePeer(comm4Port).PKIID
		comm1.Send(createGossipMsg(), unexpectedRemotePeer)
		select {
		case <-messagesForComm2:
		case <-time.After(time.Second * 5):
			require.Fail(t, "Didn't receive a message within a timely manner")
		}
	})

	t.Run("Unexpected org", func(t *testing.T) {
		unexpectedRemotePeer := remotePeer(comm3Port)
		unexpectedRemotePeer.PKIID = remotePeer(comm4Port).PKIID
		comm1.Send(createGossipMsg(), unexpectedRemotePeer)
		select {
		case <-messagesForComm3:
			require.Fail(t, "Shouldn't receive message.")
		case <-time.After(time.Second * 5):
		}
	})
}

func TestCloseConn(t *testing.T) {
	comm1, port1 := newCommInstance(t, mockSP)
	defer comm1.Stop()
	acceptChan := comm1.Accept(acceptAll)
	cert := generateCertificateOrPanic()
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
	}
	ta := credentials.NewTLS(tlsCfg)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	target := fmt.Sprintf("127.0.0.1:%d", port1)
	conn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(ta), grpc.WithBlock())
	require.NoError(t, err)
	client := pgossip.NewGossipClient(conn)
	stream, err := client.GossipStream(context.Background())
	require.NoError(t, err)

	tlsCertHash := certHashFromRawCert(tlsCfg.Certificates[0].Certificate[0])
	connMsg, err := createConnectionMsg(utils.PKIidType("id"), tlsCertHash, utils.PeerIdentityType("id"), signer, false)
	require.NoError(t, err)
	stream.Send(connMsg.Envelope)
	stream.Send(createGossipMsg().Envelope)
	select {
	case <-acceptChan:
	case <-time.After(time.Second):
		require.Fail(t, "Didn't receive a message within a timely manner")
	}
	comm1.CloseConn(&utils.RemotePeer{PKIID: utils.PKIidType("id")})
	time.Sleep(time.Second * 1)
	gotErr := false
	msg2Send := createGossipMsg()
	msg2Send.GetDataMsg().Payload = &pgossip.Payload{
		Data: make([]byte, 1024*1024),
	}
	utils.NoopSign(msg2Send.GossipMessage)
	for i := 0; i < DefaultRecvBuffSize; i++ {
		err := stream.Send(msg2Send.Envelope)
		if err != nil {
			gotErr = true
			break
		}
	}
	require.True(t, gotErr)
}

func TestCommSend(t *testing.T) {
	sendMessages := func(c Comm, peer *utils.RemotePeer, stopCh <-chan struct{}) {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			msg := createGossipMsg()
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				c.Send(msg, peer)
			}
		}
	}

	comm1, port1 := newCommInstance(t, mockSP)
	comm2, port2 := newCommInstance(t, mockSP)
	defer comm1.Stop()
	defer comm2.Stop()

	err := comm1.Probe(remotePeer(port2))
	t.Logf("err [%v]", err)

	ch1 := comm1.Accept(acceptAll)
	ch2 := comm2.Accept(acceptAll)

	stopCh1 := make(chan struct{})
	stopCh2 := make(chan struct{})

	go sendMessages(comm1, remotePeer(port2), stopCh1)
	go sendMessages(comm2, remotePeer(port1), stopCh2)

	c1received := 0
	c2received := 0

	totalMessagesReceived := (DefaultRecvBuffSize + DefaultSendBuffSize) * 2
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

RECV:
	for {
		select {
		case <-ch1:
			c1received++
			if c1received == totalMessagesReceived {
				close(stopCh2)
			}
		case <-ch2:
			c2received++
			if c2received == totalMessagesReceived {
				close(stopCh1)
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for messages to be received")
		default:
			if c1received >= totalMessagesReceived && c2received >= totalMessagesReceived {
				break RECV
			}
		}
	}

	t.Logf("c1 got %d messages, c2 got %d messages", c1received, c2received)
}

/* ------------------------------------------------------------------------------------------ */

type nonResponsivePeer struct {
	*grpc.Server
	port int
}

func newNonResponsivePeer() *nonResponsivePeer {
	port, gRPCServer, _, _, _ := utils.CreateGRPCLayer()
	nrp := &nonResponsivePeer{
		Server: gRPCServer.Server(),
		port:   port,
	}
	pgossip.RegisterGossipServer(gRPCServer.Server(), nrp)
	go gRPCServer.Start()
	return nrp
}

func (nrp *nonResponsivePeer) Ping(context.Context, *pgossip.Empty) (*pgossip.Empty, error) {
	time.Sleep(time.Second * 15) // 故意延迟，不及时响应
	return &pgossip.Empty{}, nil
}

func (nrp *nonResponsivePeer) GossipStream(stream pgossip.Gossip_GossipStreamServer) error {
	return nil
}

func (nrp *nonResponsivePeer) stop() {
	nrp.Server.Stop()
}

func TestNonResponsivePing(t *testing.T) {
	c, _ := newCommInstance(t, mockSP)
	defer c.Stop()
	nrp := newNonResponsivePeer()
	defer nrp.stop()
	s := make(chan struct{})
	go func() {
		err := c.Probe(remotePeer(nrp.port))
		t.Logf("err [%v]", err)
		s <- struct{}{}
	}()
	select {
	case <-time.After(time.Second * 10):
		require.Fail(t, "Request wasn't cancelled on time")
	case <-s:
	}
}

func TestResponses(t *testing.T) {
	comm1, port1 := newCommInstance(t, mockSP)
	comm2, _ := newCommInstance(t, mockSP)
	defer comm1.Stop()
	defer comm2.Stop()

	wg := sync.WaitGroup{}

	msg := createGossipMsg()
	wg.Add(1)
	go func() {
		ch1 := comm1.Accept(acceptAll)
		wg.Done()
		for m := range ch1 {
			reply := createGossipMsg()
			reply.Nonce = m.GetSignedGossipMessage().Nonce + 1
			m.Respond(reply.GossipMessage)
		}
	}()
	expectedNonce := msg.Nonce + 1
	ch2 := comm2.Accept(acceptAll)
	timer := time.NewTimer(10 * time.Second)
	wg.Wait()
	comm2.Send(msg, remotePeer(port1))

	select {
	case <-timer.C:
		require.Fail(t, "Haven't got response from comm1 within a timely manner")
	case resp := <-ch2:
		require.Equal(t, expectedNonce, resp.GetSignedGossipMessage().Nonce)
	}
}

func TestAccept(t *testing.T) {
	comm1, port1 := newCommInstance(t, mockSP)
	comm2, port2 := newCommInstance(t, mockSP)

	evenNONCESelector := func(m any) bool {
		return m.(utils.ReceivedMessage).GetSignedGossipMessage().Nonce%2 == 0
	}
	oddNONCESelector := func(m any) bool {
		return m.(utils.ReceivedMessage).GetSignedGossipMessage().Nonce%2 != 0
	}

	evenNONCES1 := comm1.Accept(evenNONCESelector)
	oddNONCES1 := comm1.Accept(oddNONCESelector)
	evenNONCES2 := comm2.Accept(evenNONCESelector)
	oddNONCES2 := comm2.Accept(oddNONCESelector)

	var evenResults1 []uint64
	var oddResults1 []uint64
	var evenResults2 []uint64
	var oddResults2 []uint64

	out1 := make(chan uint64)
	out2 := make(chan uint64)
	sem := make(chan struct{})

	readIntoSlice := func(a *[]uint64, out chan<- uint64, ch <-chan utils.ReceivedMessage) {
		for m := range ch {
			*a = append(*a, m.GetSignedGossipMessage().GetNonce())
			select {
			case out <- m.GetSignedGossipMessage().Nonce:
			default:
			}
		}
		sem <- struct{}{}
	}

	go readIntoSlice(&evenResults1, out1, evenNONCES1)
	go readIntoSlice(&oddResults1, out1, oddNONCES1)
	go readIntoSlice(&evenResults2, out2, evenNONCES2)
	go readIntoSlice(&oddResults2, out2, oddNONCES2)
	stopSend := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopSend:
				return
			default:
				comm1.Send(createGossipMsg(), remotePeer(port2))
				comm2.Send(createGossipMsg(), remotePeer(port1))
			}
		}
	}()

	waitForMessages(t, out1, 5, "Didn't receive all messages")
	waitForMessages(t, out2, 5, "Didn't receive all messages")
	close(stopSend)
	comm2.Stop()
	comm1.Stop()

	<-sem
	<-sem
	<-sem
	<-sem

	require.NotEmpty(t, evenResults1)
	require.NotEmpty(t, oddResults1)
	require.NotEmpty(t, evenResults2)
	require.NotEmpty(t, oddResults2)

	remainderPredicate := func(a []uint64, b uint64) {
		for _, n := range a {
			require.Equal(t, n%2, b)
		}
	}

	remainderPredicate(evenResults1, 0)
	remainderPredicate(oddResults1, 1)
	remainderPredicate(evenResults2, 0)
	remainderPredicate(oddResults2, 1)

	t.Logf("comm1 received %d even nonces", len(evenResults1))
	t.Logf("comm1 received %d odd nonces", len(oddResults1))
	t.Logf("comm2 received %d even nonces", len(evenResults2))
	t.Logf("comm2 received %d odd nonces", len(oddResults2))
}

func TestReConnections(t *testing.T) {
	comm1, port1 := newCommInstance(t, mockSP)
	comm2, port2 := newCommInstance(t, mockSP)

	reader := func(out chan uint64, in <-chan utils.ReceivedMessage) {
		for {
			msg := <-in
			if msg == nil {
				return
			}
			out <- msg.GetSignedGossipMessage().GetNonce()
		}
	}

	out1 := make(chan uint64, 10)
	out2 := make(chan uint64, 10)

	go reader(out1, comm1.Accept(acceptAll))
	go reader(out2, comm2.Accept(acceptAll))

	comm1.Send(createGossipMsg(), remotePeer(port2))
	waitForMessages(t, out2, 1, "Comm2 didn't receive a message from comm1 in a timely manner")

	comm2.Send(createGossipMsg(), remotePeer(port1))
	waitForMessages(t, out1, 1, "Comm1 didn't receive a message from comm2 in a timely manner")

	comm1.Stop()

	comm1, port1 = newCommInstance(t, mockSP)
	out1 = make(chan uint64, 1)
	go reader(out1, comm1.Accept(acceptAll))
	comm2.Send(createGossipMsg(), remotePeer(port1))
	waitForMessages(t, out1, 1, "Comm1 didn't receive a message from comm2 in a timely manner")
	comm1.Stop()
	comm2.Stop()
}

func TestProbe(t *testing.T) {
	comm1, port1 := newCommInstance(t, mockSP)
	defer comm1.Stop()
	comm2, port2 := newCommInstance(t, mockSP)

	time.Sleep(time.Second)
	require.NoError(t, comm1.Probe(remotePeer(port2)))
	_, err := comm1.Handshake(remotePeer(port2))
	require.NoError(t, err)

	tempPort, _, ll := getAvailablePort(t)
	defer ll.Close()
	err = comm1.Probe(remotePeer(tempPort))
	require.Error(t, err)
	t.Logf("err1 [%v]", err)
	_, err = comm1.Handshake(remotePeer(tempPort))
	require.Error(t, err)
	t.Logf("err2 [%v]", err)

	comm2.Stop()
	time.Sleep(time.Second)
	err = comm1.Probe(remotePeer(port2))
	require.Error(t, err)
	t.Logf("err3 [%v]", err)
	_, err = comm1.Handshake(remotePeer(port2))
	require.Error(t, err)
	t.Logf("err4 [%v]", err)

	comm2, port2 = newCommInstance(t, mockSP)
	defer comm2.Stop()
	time.Sleep(time.Second)
	err = comm2.Probe(remotePeer(port1))
	require.NoError(t, err)
	_, err = comm2.Handshake(remotePeer(port1))
	require.NoError(t, err)

	require.NoError(t, comm1.Probe(remotePeer(port2)))
	_, err = comm1.Handshake(remotePeer(port2))
	require.NoError(t, err)

	wrongRemotePeer := remotePeer(port2)
	if wrongRemotePeer.PKIID[0] == 0 {
		wrongRemotePeer.PKIID[0] = 1
	} else {
		wrongRemotePeer.PKIID[0] = 0
	}
	_, err = comm1.Handshake(wrongRemotePeer)
	require.Error(t, err)
	t.Logf("err5 [%v]", err)
}

func TestPresumedDead(t *testing.T) {
	comm1, _ := newCommInstance(t, mockSP)
	comm2, port2 := newCommInstance(t, mockSP)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		wg.Wait()
		comm1.Send(createGossipMsg(), remotePeer(port2))
	}()

	timer := time.NewTimer(time.Second * 10)
	acceptCh := comm2.Accept(acceptAll)
	wg.Done()
	select {
	case <-acceptCh:
		timer.Stop()
	case <-timer.C:
		require.Fail(t, "Didn't get first message")
	}

	comm2.Stop()
	go func() {
		for i := 0; i < 5; i++ {
			comm1.Send(createGossipMsg(), remotePeer(port2))
			time.Sleep(200 * time.Millisecond)
		}
	}()

	timer = time.NewTimer(time.Second * 3)
	select {
	case <-timer.C:
		require.Fail(t, "Didn't get a presumed dead message within a timely manner")
		break
	case <-comm1.PresumedDead():
		timer.Stop()
		break
	}
}

func TestReadFromStream(t *testing.T) {
	stream := &mocks.MockStream{}
	stream.On("CloseSend").Return(nil)
	stream.On("Recv").Return(&pgossip.Envelope{Payload: []byte{1}}, nil).Once()
	stream.On("Recv").Return(nil, errors.NewError("stream closed")).Once()

	conn := newConnection(nil, nil, stream, disabledMetrics, ConnConfig{1, 1})
	conn.logger = utils.GetLogger(utils.CommLogger, "test-stream", mlog.DebugLevel, true, true)

	errChan := make(chan error, 2)
	msgChan := make(chan *utils.SignedGossipMessage, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn.readFromStream(errChan, msgChan)
	}()

	select {
	case <-msgChan:
		require.Fail(t, "malformed message shouldn't have been received")
	case <-time.After(time.Millisecond * 100):
		require.Len(t, errChan, 1)
	}

	conn.close()
	wg.Wait()
}

func TestSendBadEnvelope(t *testing.T) {
	comm1, port1 := newCommInstance(t, mockSP)
	defer comm1.Stop()

	stream, err := establishSession(t, port1)
	require.NoError(t, err)
	require.NotNil(t, stream)

	inc := comm1.Accept(acceptAll)
	goodMsg := createGossipMsg()
	err = stream.Send(goodMsg.Envelope)
	require.NoError(t, err)

	select {
	case goodMsgReceived := <-inc:
		require.Equal(t, goodMsgReceived.GetSignedGossipMessage().Payload, goodMsg.Envelope.Payload)
	case <-time.After(time.Second * 3):
		require.Fail(t, "Didn't receive message within a timely manner")
		return
	}

	start := time.Now()
	for {
		badMsg := createGossipMsg()
		badMsg.Envelope.Payload = []byte{1}
		err = stream.Send(badMsg.Envelope)
		if err != nil {
			require.Equal(t, io.EOF, err)
			break
		}
		if time.Now().After(start.Add(time.Second * 30)) {
			require.Fail(t, "Didn't close stream within a timely manner")
			return
		}
	}
}

func TestConcurrentCloseSend(t *testing.T) {
	var stopping int32
	comm1, _ := newCommInstance(t, mockSP)
	comm2, port2 := newCommInstance(t, mockSP)
	inc := comm2.Accept(acceptAll)
	comm1.Send(createGossipMsg(), remotePeer(port2))
	<-inc
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		comm1.Send(createGossipMsg(), remotePeer(port2))
		close(ready)
		for atomic.LoadInt32(&stopping) == 0 {
			comm1.Send(createGossipMsg(), remotePeer(port2))
		}
	}()

	<-ready
	comm2.Stop()
	atomic.StoreInt32(&stopping, 1)
	<-done
}
