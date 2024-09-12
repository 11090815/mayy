package comm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/mlog"
	commonutils "github.com/11090815/mayy/common/utils"
	"github.com/11090815/mayy/gossip/metrics"
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

type Comm interface {
	// GetPKIid 返回创建此 Comm 的节点的 ID。
	GetPKIid() utils.PKIidType

	Send(msg *utils.SignedGossipMessage, peers ...*utils.RemotePeer)

	// SendWithAck 发送消息给一群 peer 节点，并等待从这些节点处收回至少 minAck 个反馈，或者直到 timeout 超时时间超时。
	SendWithAck(msg *utils.SignedGossipMessage, timeout time.Duration, minAck int, peers ...*utils.RemotePeer) AggregatedSendResult

	// Probe 给一个 peer 节点发送一条消息，如果对方回应了则返回 nil，否则返回 error。
	Probe(peer *utils.RemotePeer) error

	// Handshake 与一个 peer 节点进行握手，如果握手成功，则返回此 peer 节点的身份证书信息，否则返回 nil 和 error。
	Handshake(peer *utils.RemotePeer) (utils.PeerIdentityType, error)

	// Accept 接收 Comm 的创建者感兴趣的消息，并将这些消息放于一个 read-only 通道中，然后返回此通道。
	Accept(utils.MessageAcceptor) <-chan utils.ReceivedMessage

	// PreseumedDead 将可能已经离线的 peer 节点的 ID 放入到一个 read-only 通道里，然后返回此通道。
	PresumedDead() <-chan utils.PKIidType

	// IdentitySwitch 将身份发生改变的 peer 节点的 ID 放入到一个 read-only 通道里，然后返回此通道。
	IdentitySwitch() <-chan utils.PKIidType

	// CloseConn 关闭与某个特定 peer 节点之间的网络连接。
	CloseConn(peer *utils.RemotePeer)

	Stop()
}

type Config struct {
	DialTimeout  time.Duration // 建立拨号连接的超时时间
	ConnTimeout  time.Duration // 发送消息的超时时间
	RecvBuffSize int           // 消息接收池所能存放消息的条数
	SendBuffSize int           // 消息发送池所能发送消息的条数
}

/* ------------------------------------------------------------------------------------------ */

/* ------------------------------------------------------------------------------------------ */

type SendResult struct {
	result string
	utils.RemotePeer
}

func (sr SendResult) Error() string {
	return sr.result
}

/* ------------------------------------------------------------------------------------------ */

type AggregatedSendResult []SendResult

// AckCount 返回响应成功的消息数。
func (asr AggregatedSendResult) AckCount() int {
	count := 0
	for _, ack := range asr {
		if ack.result == "" {
			count++
		}
	}
	return count
}

// NackCount 返回响应失败的消息数。
func (asr AggregatedSendResult) NackCount() int {
	return len(asr) - asr.AckCount()
}

func (asr AggregatedSendResult) String() string {
	errMap := make(map[string]int)
	for _, ack := range asr {
		if ack.result == "" {
			continue
		}
		errMap[ack.result]++
	}

	ackCount := asr.AckCount()
	output := map[string]any{}
	if ackCount > 0 {
		output["successes"] = ackCount
	}
	if ackCount < len(asr) {
		output["failures"] = errMap
	}
	bz, _ := json.Marshal(output)
	return string(bz)
}

/* ------------------------------------------------------------------------------------------ */

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
	subscriptions   []chan utils.ReceivedMessage
	stopping        int32
	stopOnce        sync.Once
	metrics         *metrics.CommMetrics

	recvBuffSize int
	sendBuffSize int
	mutex        *sync.Mutex
}

func NewCommInstance(s *grpc.Server, certs *utils.TLSCertificates, idStore utils.IdentityMapper, identity utils.PeerIdentityType, logger mlog.Logger,
	secureDialOpts utils.PeerSecureDialOpts, sa utils.SecurityAdvisor, metrics *metrics.CommMetrics, config Config, dialOpts ...grpc.DialOption) (Comm, error) {
	inst := &commImpl{
		sa:              sa,
		tlsCerts:        certs,
		pubsub:          utils.NewPubSub(),
		peerIdentity:    identity,
		PKIID:           idStore.GetPKIidOfCert(identity),
		idMapper:        idStore,
		logger:          logger,
		dialTimeout:     config.DialTimeout,
		opts:            dialOpts,
		secureDialOpts:  secureDialOpts,
		connTimeout:     config.ConnTimeout,
		deadEndpoints:   make(chan utils.PKIidType, 100),
		identityChanges: make(chan utils.PKIidType, 10),
		msgPublisher:    NewChannelDeMultiplexer(),
		exitCh:          make(chan struct{}),
		stopWg:          sync.WaitGroup{},
		subscriptions:   make([]chan utils.ReceivedMessage, 0),
		stopping:        0,
		metrics:         metrics,
		recvBuffSize:    config.RecvBuffSize,
		sendBuffSize:    config.SendBuffSize,
		mutex:           &sync.Mutex{},
	}

	connConfig := ConnConfig{
		RecvBuffSize: config.RecvBuffSize,
		SendBuffSize: config.SendBuffSize,
	}

	inst.connStore = newConnStore(inst, logger, connConfig)

	pgossip.RegisterGossipServer(s, inst)

	return inst, nil
}

func (c *commImpl) Probe(peer *utils.RemotePeer) error {
	c.logger.Debugf("Probing peer %s@%s.", peer.PKIID.String(), peer.Endpoint)
	if c.isStopping() {
		return errors.NewError("comm instance is already closed")
	}
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, c.secureDialOpts()...)
	dialOpts = append(dialOpts, c.opts...)
	dialOpts = append(dialOpts, grpc.WithBlock())
	ctx, cancel := context.WithTimeout(context.Background(), c.dialTimeout)
	defer cancel()
	cc, err := grpc.DialContext(ctx, peer.Endpoint, dialOpts...)
	if err != nil {
		return err
	}
	defer cc.Close()
	client := pgossip.NewGossipClient(cc)
	ctx, cancel = context.WithTimeout(context.Background(), c.connTimeout)
	defer cancel()
	_, err = client.Ping(ctx, &pgossip.Empty{})
	return err
}

func (c *commImpl) Handshake(peer *utils.RemotePeer) (utils.PeerIdentityType, error) {
	c.logger.Debugf("Start shaking hands with peer %s@%s.", peer.PKIID.String(), peer.Endpoint)
	// 通过握手获取对方节点信息，这里我们主动给对方节点拨号，所以在这里，我们在拨号选项中，为了安全考虑，
	// 一般要提供我们（client端）的证书，同时还要给出 ca 的证书，用于验证对方节点（server端）的证书。
	// 所以这就要求对方（server端）在监听新的连接请求时，需要提供自己（server端）的证书。
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, c.secureDialOpts()...)
	dialOpts = append(dialOpts, c.opts...)
	dialOpts = append(dialOpts, grpc.WithBlock())

	// 通过 grpc 拨号，获得底层连接。
	ctx, cancel := context.WithTimeout(context.Background(), c.dialTimeout)
	defer cancel()
	cc, err := grpc.DialContext(ctx, peer.Endpoint, dialOpts...)
	if err != nil {
		return nil, err
	}
	defer cc.Close()

	// 将 grpc 的底层连接包装成 gossip client。
	client := pgossip.NewGossipClient(cc)
	ctx, cancel = context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	stream, err := client.GossipStream(ctx)
	if err != nil {
		return nil, err
	}
	info, err := c.authenticateRemotePeer(stream, true, true)
	if err != nil {
		return nil, err
	}
	if len(peer.PKIID) > 0 && !bytes.Equal(peer.PKIID, info.PkiID) {
		return nil, errors.NewErrorf("remote peer claims to be a different peer, expected pki-id is %s, but got %s.", peer.PKIID.String(), hex.EncodeToString(info.PkiID))
	}
	c.logger.Infof("Finish shaking hands with peer %s@%s.", peer.PKIID.String(), peer.Endpoint)
	return info.Identity, nil
}

func (c *commImpl) Send(msg *utils.SignedGossipMessage, peers ...*utils.RemotePeer) {
	if c.isStopping() || len(peers) == 0 {
		return
	}
	for _, peer := range peers {
		go func(peer *utils.RemotePeer, msg *utils.SignedGossipMessage) {
			c.sendToEndpoint(peer, msg, nonBlockingSend)
			c.logger.Debugf("Send message %s to peer %s@%s.", msg.String(), peer.PKIID.String(), peer.Endpoint)
		}(peer, msg)
	}
}

func (c *commImpl) SendWithAck(msg *utils.SignedGossipMessage, timeout time.Duration, minAck int, peers ...*utils.RemotePeer) AggregatedSendResult {
	if len(peers) == 0 {
		return nil
	}

	c.logger.Debugf("Prepare to send message %s to %d peer(s), and will wait for at least %d acknowledgement(s).", msg.String(), len(peers), minAck)

	var err error
	msg.Nonce = utils.RandomUint64()
	msg, err = utils.NoopSign(msg.GossipMessage)
	if c.isStopping() || err != nil {
		if err == nil {
			err = errors.NewError("comm instance is already closed")
		}
		results := []SendResult{}
		for _, peer := range peers {
			results = append(results, SendResult{result: err.Error(), RemotePeer: utils.RemotePeer{Endpoint: peer.Endpoint, PKIID: peer.PKIID}})
		}
		return results
	}

	subscriptions := make(map[string]func() error)
	for _, p := range peers {
		topic := topicForAck(msg.Nonce, p.PKIID)
		subscription := c.pubsub.Subscribe(topic, timeout)
		subscriptions[p.PKIID.String()] = func() error {
			msg, err := subscription.Listen()
			if err != nil {
				return err
			}
			if msg, ok := msg.(*pgossip.Acknowledgement); !ok {
				return errors.NewErrorf("expected *Acknowledgement, but got %T", msg)
			} else {
				if msg.Error != "" {
					return errors.NewError(msg.Error)
				}
			}
			return nil
		}
	}

	waitForAck := func(peer *utils.RemotePeer) error {
		return subscriptions[peer.PKIID.String()]()
	}
	send := func(peer *utils.RemotePeer, msg *utils.SignedGossipMessage) {
		c.sendToEndpoint(peer, msg, blockingSend)
	}
	ackOperation := newAckSendOperation(send, waitForAck)
	return ackOperation.send(msg, minAck, peers...)
}

func (c *commImpl) Accept(acceptor utils.MessageAcceptor) <-chan utils.ReceivedMessage {
	genericChan := c.msgPublisher.AddChannel(acceptor)
	specificChan := make(chan utils.ReceivedMessage, 10)

	if c.isStopping() {
		return specificChan
	}

	c.mutex.Lock()
	c.subscriptions = append(c.subscriptions, specificChan)
	c.mutex.Unlock()

	c.stopWg.Add(1)
	go func() {
		defer c.stopWg.Done()
		for {
			select {
			case msg, channelOpen := <-genericChan:
				if !channelOpen {
					return
				}
				select {
				case specificChan <- msg.(*ReceivedMessageImpl):
				case <-c.exitCh:
					return
				}
			case <-c.exitCh:
				return
			}
		}
	}()
	return specificChan
}

func (c *commImpl) PresumedDead() <-chan utils.PKIidType {
	return c.deadEndpoints
}

func (c *commImpl) IdentitySwitch() <-chan utils.PKIidType {
	return c.identityChanges
}

func (c *commImpl) CloseConn(peer *utils.RemotePeer) {
	c.disconnect(peer.PKIID)
}

func (c *commImpl) GetPKIid() utils.PKIidType {
	return c.PKIID
}

// GossipStream 当别人主动与我们建立连接时，底层的 gRPC 会将建立的连接数据流 stream 传给此方法，然后我们基于
// GossipStream 方法的逻辑验证对等方的身份，并且将它包装成我们的连接存储下来。
func (c *commImpl) GossipStream(stream pgossip.Gossip_GossipStreamServer) error {
	if c.isStopping() {
		return errors.NewError("comm instance is already closed")
	}
	connInfo, err := c.authenticateRemotePeer(stream, false, false)
	if err == errProbe {
		c.logger.Infof("Peer %s@%s probed us.", connInfo.PkiID.String(), connInfo.Endpoint)
		return nil
	}

	if err != nil {
		c.logger.Errorf("Failed authenticating the other peer, because %s.", err.Error())
		return err
	}

	c.logger.Debugf("Start servicing peer %s@%s.", connInfo.PkiID.String(), connInfo.Endpoint)
	conn := c.connStore.onConnected(stream, connInfo, c.metrics)
	h := func(msg *utils.SignedGossipMessage) {
		c.msgPublisher.DeMultiplex(&ReceivedMessageImpl{
			conn:                conn,
			SignedGossipMessage: msg,
			connInfo:            connInfo,
		})
	}
	conn.handler = interceptAcks(h, connInfo.PkiID, c.pubsub)
	defer func() {
		c.logger.Infof("Disconnect from client %s@%s.", connInfo.PkiID.String(), connInfo.Endpoint)
		c.connStore.closeConnByPKIid(conn.pkiID)
	}()

	return conn.serviceConnection()
}

func (c *commImpl) Ping(context.Context, *pgossip.Empty) (*pgossip.Empty, error) {
	return &pgossip.Empty{}, nil
}

func (c *commImpl) Stop() {
	c.stopOnce.Do(func() {
		c.connStore.shutdown()
		c.msgPublisher.Close()
		c.idMapper.Stop()
		close(c.exitCh)
		c.stopWg.Wait()
		c.closeSubscriptions()
		atomic.StoreInt32(&c.stopping, 1)
		c.logger.Infof("Closing comm instance, then, disconnect from %d peers.", c.connStore.connNum())
	})

}

/* ------------------------------------------------------------------------------------------ */

func (c *commImpl) sendToEndpoint(peer *utils.RemotePeer, msg *utils.SignedGossipMessage, shouldBlock blockingBehavior) {
	if c.isStopping() || c.connStore.isClosed() {
		return
	}

	conn, err := c.connStore.getConnection(peer)
	if err != nil {
		c.logger.Errorf("Failed to send message to %s@%s, error: %s.", peer.PKIID.String(), peer.Endpoint, err.Error())
		return
	} else {
		onErr := func(err error) {
			c.logger.Errorf("Failed to send message to %s@%s, error: %s, we would disconnect from this peer.", peer.PKIID.String(), peer.Endpoint, err.Error())
			c.disconnect(peer.PKIID)
		}
		conn.send(msg, onErr, shouldBlock)
		return
	}
}

func (c *commImpl) createConnection(endpoint string, expectedPKIID utils.PKIidType) (*connection, error) {
	var dialOpts []grpc.DialOption
	var cc *grpc.ClientConn
	var err error
	var connInfo *utils.ConnectionInfo
	var stream pgossip.Gossip_GossipStreamClient

	if c.isStopping() {
		return nil, errors.NewErrorf("failed to create connection to %s@%s, because the comm instance is closed", expectedPKIID.String(), endpoint)
	}
	c.logger.Debugf("Create a connection to %s@%s.", expectedPKIID.String(), endpoint)

	// 1. 建立连接
	dialOpts = append(dialOpts, c.secureDialOpts()...)
	dialOpts = append(dialOpts, grpc.WithBlock())
	dialOpts = append(dialOpts, c.opts...)
	ctx, cancel := context.WithTimeout(context.Background(), c.dialTimeout)
	defer cancel()
	cc, err = grpc.DialContext(ctx, endpoint, dialOpts...)
	if err != nil {
		return nil, errors.NewErrorf("failed to create connection to %s@%s, error: %s", expectedPKIID.String(), endpoint, err.Error())
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
			pkiID := connInfo.PkiID
			if len(expectedPKIID) != 0 && !bytes.Equal(expectedPKIID, pkiID) {
				actualOrg := c.sa.OrgByPeerIdentity(connInfo.Identity)
				expectedIdentity, _ := c.idMapper.Get(expectedPKIID)
				oldOrg := c.sa.OrgByPeerIdentity(expectedIdentity)
				if !bytes.Equal(actualOrg, oldOrg) {
					c.logger.Warnf("Remote peer claims to be from a different organization, should be from %s, but actually from %s.", oldOrg.String(), actualOrg.String())
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

			var h handler = func(message *utils.SignedGossipMessage) {
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

func (c *commImpl) authenticateRemotePeer(stream stream, initiator, isProbe bool) (*utils.ConnectionInfo, error) {
	ctx := stream.Context()
	remoteAddress := extractRemoteAddress(stream)
	remoteCertHash := extractCertificateHashFromContext(ctx) // TODO 对方的证书什么时候存起来的？
	useTLS := c.tlsCerts != nil
	var selfCertHash []byte
	c.logger.Debugf("Start authenticating peer (%s).", remoteAddress)
	defer c.logger.Debugf("Finish authenticating peer (%s).", remoteAddress)

	if useTLS {
		certReference := c.tlsCerts.TLSServerCert
		if initiator { // 如果是验证过程的发起者，代表我主动连接对方的 server 端
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

	connMsg, err := createConnectionMsg(c.PKIID, selfCertHash, c.peerIdentity, signer, isProbe)
	if err != nil {
		return nil, err
	}
	c.logger.Debugf("Send my connection information %s to %s.", utils.ConnEstablishToString(connMsg.GetConnEstablish()), remoteAddress)
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
		c.logger.Errorf("Peer from %s didn't send his/her pki-id.", remoteAddress)
		return nil, errors.NewError("no pki-id")
	}

	c.logger.Debugf("Receive connection information %s from %s@%s.", utils.ConnEstablishToString(receivedMsg), hex.EncodeToString(receivedMsg.PkiId), remoteAddress)
	if err = c.idMapper.Put(receivedMsg.PkiId, receivedMsg.Identity); err != nil {
		c.logger.Errorf("Identity store rejected storing identity from %s, error: %s.", remoteAddress, err.Error())
		return nil, err
	}

	connInfo := &utils.ConnectionInfo{
		PkiID:    receivedMsg.PkiId,
		Identity: receivedMsg.Identity,
		Endpoint: remoteAddress,
		AuthInfo: &utils.AuthInfo{
			SignedData: m.Payload,
			Signature:  m.Signature,
		},
	}

	if useTLS {
		if !bytes.Equal(remoteCertHash, receivedMsg.TlsCertHash) {
			return nil, errors.NewErrorf("expected %s in remote hash of TLS cert, but got %s.", hex.EncodeToString(remoteCertHash), hex.EncodeToString(receivedMsg.TlsCertHash))
		}
	}

	verifier := func(peerIdentity utils.PeerIdentityType, signature, message []byte) error {
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

func (c *commImpl) closeSubscriptions() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for _, ch := range c.subscriptions {
		close(ch)
	}
}

func (c *commImpl) isStopping() bool {
	return atomic.LoadInt32(&c.stopping) == 1
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

func readWithTimeout(stream stream, timeout time.Duration, address string) (*utils.SignedGossipMessage, error) {
	inCh := make(chan *utils.SignedGossipMessage, 1)
	errCh := make(chan error, 1)
	go func() {
		if m, err := stream.Recv(); err == nil {
			msg, err := utils.EnvelopeToSignedGossipMessage(m)
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

// createConnectionMsg 创建连接信息。
func createConnectionMsg(pkiID utils.PKIidType, certHash []byte, cert utils.PeerIdentityType, signer utils.SignFuncType, isProbe bool) (*utils.SignedGossipMessage, error) {
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
	smg := &utils.SignedGossipMessage{
		GossipMessage: m,
	}
	_, err := smg.Sign(signer)
	return smg, err
}
