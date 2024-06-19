package comm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/mlog"
	commonutils "github.com/11090815/mayy/common/utils"
	"github.com/11090815/mayy/gossip/metrics"
	"github.com/11090815/mayy/gossip/protoext"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const (
	handshakeTimeout    = time.Second * 10
	DefaultDialTimeout  = time.Second * 3
	DefaultConnTimeout  = time.Second * 2
	DefaultRecvBuffSize = 20
	DefaultSendBuffSize = 20
)

var (
	errProbe = fmt.Errorf("probe")
)

type commImpl struct {
	sa           utils.SecurityAdvisor
	tlsCerts     *utils.TLSCertificates
	pubsub       *utils.PubSub
	peerIdentity utils.PeerIdentityType
	PKIID        utils.PKIidType
	idMapper     utils.IdentityMapper
	logger       mlog.Logger

	// 主动建立 grpc 连接时所使用的参数
	dialTimeout    time.Duration // 拨号建立连接的超时时间
	opts           []grpc.DialOption
	secureDialOpts utils.PeerSecureDialOpts
	connTimeout    time.Duration // 发送消息的超时时间

	connStore       *connStore
	deadEndpoints   chan utils.PKIidType
	identityChanges chan utils.PKIidType
	msgPublisher    *ChannelDeMultiplexer
	exitCh          chan struct{}
	stopWg          sync.WaitGroup
	subscriptions   []chan protoext.ReceivedMessage
	stopping        int32
	metrics         *metrics.CommMetrics

	recvBuffSize int
	sendBuffSize int
	mutex        *sync.Mutex
}

func (c *commImpl) createConnection(endpoint string, expectedPKIID utils.PKIidType) (*connection, error) {
	var dialOpts []grpc.DialOption
	var cc *grpc.ClientConn
	var err error
	var connInfo *protoext.ConnectionInfo
	var stream pgossip.Gossip_GossipStreamClient

	c.logger.Debugf("Creating a connection to %s@%s.", expectedPKIID.String(), endpoint)
	if c.isStopping() {
		return nil, errors.NewError("stopping creating connection")
	}

	// 1. 建立连接
	dialOpts = append(dialOpts, c.secureDialOpts()...)
	dialOpts = append(dialOpts, grpc.WithBlock())
	dialOpts = append(dialOpts, c.opts...)
	ctx, cancel := context.WithTimeout(context.Background(), c.dialTimeout)
	defer cancel()
	cc, err = grpc.DialContext(ctx, endpoint, dialOpts...)
	if err != nil {
		return nil, err
	}

	// 2. 测试网络连通性
	client := pgossip.NewGossipClient(cc)
	ctx, cancel = context.WithTimeout(context.Background(), c.connTimeout)
	defer cancel()
	if _, err = client.Ping(ctx, &pgossip.Empty{}); err != nil {
		cc.Close()
		return nil, err
	}

	// 3. 身份认证
	ctx, cancel = context.WithCancel(context.Background())
	if stream, err = client.GossipStream(ctx); err == nil {
		connInfo, err = c.authenticateRemotePeer(stream, true, false)
		if err == nil {
			pkiID := connInfo.ID
			if len(expectedPKIID) != 0 && !bytes.Equal(expectedPKIID, pkiID) {
				actualOrg := c.sa.OrgByPeerIdentity(connInfo.Identity)
				expectedIdentity, _ := c.idMapper.Get(expectedPKIID)
				oldOrg := c.sa.OrgByPeerIdentity(expectedIdentity)
				if !bytes.Equal(actualOrg, oldOrg) {
					c.logger.Warnf("Remote peer claims to be a different peer, expected %s, but got %s.", expectedPKIID.String(), pkiID.String())
					cc.Close()
					cancel()
					return nil, errors.NewError("authentication failure")
				} else {
					c.logger.Infof("Peer from %s changed its PKI-ID from %s to %s.", endpoint, expectedPKIID.String(), pkiID.String())
					c.identityChanges <- expectedPKIID
				}
			}
			connConfig := ConnConfig{
				RecvBuffSize: c.recvBuffSize,
				SendBuffSize: c.sendBuffSize,
			}
			conn := newConnection(client, cc, stream, c.metrics, connConfig)
			conn.pkiID = pkiID
			conn.info = connInfo
			conn.logger = c.logger
			conn.cancel = cancel

			var h handler = func(message *protoext.SignedGossipMessage) {
				c.logger.Debugf("Got message: %s.", message.String())
				c.msgPublisher.DeMultiplex(&ReceivedMessageImpl{
					conn:                conn,
					connInfo:            connInfo,
					SignedGossipMessage: message,
				})
			}
			conn.handler = interceptAcks(h, pkiID, c.pubsub)
			return conn, nil
		}
		c.logger.Errorf("Authentication failed, error: %s.", err.Error())
	}
	cc.Close()
	cancel()
	return nil, err
}

func (c *commImpl) authenticateRemotePeer(stream stream, initiator, isProbe bool) (*protoext.ConnectionInfo, error) {
	ctx := stream.Context()
	remoteAddress := extractRemoteAddress(stream)
	remoteCertHash := extractCertificateHashFromContext(ctx) // TODO 对方的证书什么时候存起来的？
	useTLS := c.tlsCerts != nil
	var selfCertHash []byte
	c.logger.Debugf("Starting authenticating peer from %s.", remoteAddress)
	defer c.logger.Debugf("Finishing authenticating peer from %s.", remoteAddress)

	if useTLS {
		certReference := c.tlsCerts.TLSServerCert
		if initiator { // 如果是验证过程的发起者
			certReference = c.tlsCerts.TLSClientCert
		}
		selfCertHash = certHashFromRawCert(certReference.Load().(*tls.Certificate).Certificate[0])
	}

	signer := func(msg []byte) ([]byte, error) {
		return c.idMapper.Sign(msg)
	}

	if useTLS && len(remoteCertHash) == 0 {
		c.logger.Errorf("Peer %s didn't send TLS certificate.", remoteAddress)
		return nil, errors.NewError("failed authenticating TLS certificate")
	}

	connMsg, err := c.createConnectionMsg(c.PKIID, selfCertHash, c.peerIdentity, signer, isProbe)
	if err != nil {
		return nil, err
	}
	c.logger.Debugf("Sending my connection information to %s.", remoteAddress)
	stream.Send(connMsg.Envelope)
	m, err := readWithTimeout(stream, c.connTimeout, remoteAddress)
	if err != nil {
		c.logger.Errorf("Failed reading message from %s, error: %s.", remoteAddress, err.Error())
		return nil, err
	}
	receivedMsg := m.GetConnEstablish()
	if receivedMsg == nil {
		c.logger.Errorf("Expected getting ConnEstablish message, but got %T.", m.Content)
		return nil, errors.NewErrorf("expected getting ConnEstablish message, but got %T.", m.Content)
	}

	if receivedMsg.PkiId == nil {
		c.logger.Errorf("Peer from %s didn't send his pki-id.", remoteAddress)
		return nil, errors.NewError("no pki-id")
	}

	c.logger.Debugf("Received connection information from %s@%s.", hex.EncodeToString(receivedMsg.PkiId), remoteAddress)
	if err = c.idMapper.Put(receivedMsg.PkiId, receivedMsg.Identity); err != nil {
		c.logger.Errorf("Identity store rejected storing identity from %s, error: %s.", remoteAddress, err.Error())
		return nil, err
	}

	connInfo := &protoext.ConnectionInfo{
		ID:       receivedMsg.PkiId,
		Identity: receivedMsg.Identity,
		Endpoint: remoteAddress,
		Auth: &protoext.AuthInfo{
			SignedData: m.Payload,
			Signature:  m.Signature,
		},
	}

	if useTLS {
		if !bytes.Equal(remoteCertHash, receivedMsg.TlsCertHash) {
			c.logger.Errorf("Expected %s in remote hash of TLS cert, but got %s.", hex.EncodeToString(remoteCertHash), hex.EncodeToString(receivedMsg.TlsCertHash))
			return nil, errors.NewErrorf("expected %s in remote hash of TLS cert, but got %s.", hex.EncodeToString(remoteCertHash), hex.EncodeToString(receivedMsg.TlsCertHash))
		}
	}

	verifier := func(peerIdentity []byte, signature, message []byte) error {
		pkiID := c.idMapper.GetPKIidOfCert(peerIdentity)
		return c.idMapper.Verify(pkiID, signature, message)
	}
	if err = m.Verify(receivedMsg.Identity, verifier); err != nil {
		c.logger.Errorf("Failed verifying signature from %s@%s.", hex.EncodeToString(receivedMsg.PkiId), remoteAddress)
		return nil, err
	}

	if receivedMsg.Probe {
		return connInfo, errProbe
	}

	return connInfo, nil
}

func (c *commImpl) isStopping() bool {
	return atomic.LoadInt32(&c.stopping) == 1
}

// createConnectionMsg 创建连接信息。
func (c *commImpl) createConnectionMsg(pkiID utils.PKIidType, certHash []byte, cert utils.PeerIdentityType, signer protoext.SignFuncType, isProbe bool) (*protoext.SignedGossipMessage, error) {
	m := &pgossip.GossipMessage{
		Tag:   pgossip.GossipMessage_EMPTY,
		Nonce: 0,
		Content: &pgossip.GossipMessage_ConnEstablish{
			ConnEstablish: &pgossip.ConnEstablish{
				TlsCertHash: certHash,
				Identity:    cert,
				PkiId:       pkiID,
				Probe:       isProbe,
			},
		},
	}
	smg := &protoext.SignedGossipMessage{
		GossipMessage: m,
	}
	_, err := smg.Sign(signer)
	return smg, err
}

func (c *commImpl) disconnect(pkiID utils.PKIidType) {
	select {
	case c.deadEndpoints <- pkiID:
	case <-c.exitCh:
		return
	}
	c.connStore.closeConnByPKIid(pkiID)
}

/* ------------------------------------------------------------------------------------------ */

func extractRemoteAddress(stream stream) string {
	var remoteAddress string
	p, ok := peer.FromContext(stream.Context())
	if ok {
		if p.Addr != nil {
			remoteAddress = p.Addr.String()
		}
	}
	return remoteAddress
}

func certHashFromRawCert(rawCert []byte) []byte {
	if len(rawCert) == 0 {
		return nil
	}
	return commonutils.ComputeSHA256(rawCert)
}

func extractCertificateHashFromContext(ctx context.Context) []byte {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}

	if peer.AuthInfo == nil {
		return nil
	}

	tlsInfo, isTLSConn := peer.AuthInfo.(credentials.TLSInfo)
	if !isTLSConn {
		return nil
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	raw := certs[0].Raw
	return certHashFromRawCert(raw)
}

func readWithTimeout(stream stream, timeout time.Duration, address string) (*protoext.SignedGossipMessage, error) {
	inCh := make(chan *protoext.SignedGossipMessage, 1)
	errCh := make(chan error, 1)
	go func() {
		if m, err := stream.Recv(); err == nil {
			msg, err := protoext.EnvelopeToSignedGossipMessage(m)
			if err != nil {
				errCh <- err
				return
			}
			inCh <- msg
		}
	}()

	select {
	case <-time.After(timeout):
		return nil, errors.NewErrorf("timed out waiting for connection message from %s", address)
	case m := <-inCh:
		return m, nil
	case err := <-errCh:
		return nil, err
	}
}
