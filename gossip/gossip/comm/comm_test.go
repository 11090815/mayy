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
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/metrics/disabled"
	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/metrics"
	"github.com/11090815/mayy/gossip/mocks"
	"github.com/11090815/mayy/gossip/protoext"
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
	noopMutator       = func(sgm *protoext.SignedGossipMessage) *protoext.SignedGossipMessage {
		return sgm
	}
	acceptAll = func(msg any) bool {
		return true
	}
	testCommConfig = CommConfig{
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

type msgMutator func(*protoext.SignedGossipMessage) *protoext.SignedGossipMessage

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

func handshaker(t *testing.T, port int, selfID string, comm Comm, connMutator msgMutator, connType tlsType) <-chan protoext.ReceivedMessage {
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
	msg, err = protoext.EnvelopeToSignedGossipMessage(envelope)
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
		NotAfter: time.Now().Add(time.Hour * 24),
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

func createGossipMsg() *protoext.SignedGossipMessage {
	msg, _ := protoext.NoopSign(&pgossip.GossipMessage{
		Tag:   pgossip.GossipMessage_EMPTY,
		Nonce: utils.RandomUint64(),
		Content: &pgossip.GossipMessage_DataMsg{
			DataMsg: &pgossip.DataMessage{},
		},
	})
	return msg
}

func remotePeer(port int) *RemotePeer {
	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	return &RemotePeer{Endpoint: endpoint, PKIID: utils.PKIidType(endpoint)}
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

/* ------------------------------------------------------------------------------------------ */

func TestMutualParallelSendWithAck(t *testing.T) {
	msgNum := 10

	comm1, port1 := newCommInstance(t, mockSP)
	comm2, port2 := newCommInstance(t, mockSP)
	defer comm1.Stop()
	defer comm2.Stop()

	acceptData := func(msg any) bool {
		m := msg.(protoext.ReceivedMessage).GetGossipMessage()
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
	assertPositivePath := func(msg protoext.ReceivedMessage, endpoint string) {
		expectedPKIID := utils.PKIidType(endpoint)
		require.Equal(t, expectedPKIID, msg.GetConnectionInfo().ID)
		require.Equal(t, utils.PeerIdentityType(endpoint), msg.GetConnectionInfo().Identity)
		require.NotNil(t, msg.GetConnectionInfo().Auth)
		sig, _ := signer(msg.GetConnectionInfo().Auth.SignedData)
		require.Equal(t, sig, msg.GetConnectionInfo().Auth.Signature)
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

	var msg protoext.ReceivedMessage
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
	assertPositivePath := func(msg protoext.ReceivedMessage, endpoint string) {
		expectedPKIID := utils.PKIidType(endpoint)
		require.Equal(t, expectedPKIID, msg.GetConnectionInfo().ID)
		require.Equal(t, utils.PeerIdentityType(endpoint), msg.GetConnectionInfo().Identity)
		require.NotNil(t, msg.GetConnectionInfo().Auth)
		sig, _ := signer(msg.GetConnectionInfo().Auth.SignedData)
		require.Equal(t, sig, msg.GetConnectionInfo().Auth.Signature)
	}
	comm, port := newCommInstance(t, mockSP)
	defer comm.Stop()
	var msg protoext.ReceivedMessage
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

	mutator := func(sgm *protoext.SignedGossipMessage) *protoext.SignedGossipMessage {
		sgm.GetConnEstablish().PkiId = []byte("xxxx")
		sgm.Sign(signer)
		return sgm
	}
	acceptChan = handshaker(t, port, tempEndpoint, comm, mutator, mutualTLS)
	time.Sleep(time.Second)
	require.Equal(t, 0, len(acceptChan))

	mutator = func(sgm *protoext.SignedGossipMessage) *protoext.SignedGossipMessage {
		sgm.GetConnEstablish().TlsCertHash = append(sgm.GetConnEstablish().TlsCertHash, 1)
		sgm.Sign(signer)
		return sgm
	}
	acceptChan = handshaker(t, port, tempEndpoint, comm, mutator, mutualTLS)
	time.Sleep(time.Second)
	require.Equal(t, 0, len(acceptChan))
}
