package comm

import (
	"context"
	"sync"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/metrics"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
	"google.golang.org/grpc"
)

type handler func(message *utils.SignedGossipMessage)

type blockingBehavior bool

const (
	blockingSend    = blockingBehavior(true)
	nonBlockingSend = blockingBehavior(false)
)

type connFactory interface {
	createConnection(endpoint string, pkiID utils.PKIidType) (*connection, error)
}

type connStore struct {
	config           ConnConfig
	logger           mlog.Logger
	isClosing        bool
	shutdownOnce     sync.Once
	connFactory      connFactory
	mutex            *sync.RWMutex
	pki2Conn         map[string]*connection
	destinationLocks map[string]*sync.Mutex // 用于防止建立到同一远程端点的并发连接
}

func newConnStore(connFactory connFactory, logger mlog.Logger, config ConnConfig) *connStore {
	return &connStore{
		connFactory:      connFactory,
		isClosing:        false,
		pki2Conn:         make(map[string]*connection),
		destinationLocks: make(map[string]*sync.Mutex),
		logger:           logger,
		config:           config,
		mutex:            &sync.RWMutex{},
	}
}

func (cs *connStore) getConnection(peer *utils.RemotePeer) (*connection, error) {
	if cs.isClosed() {
		return nil, errors.NewError("conn store is closed")
	}

	pkiID := peer.PKIID
	endpoint := peer.Endpoint

	cs.lockPeer(pkiID)
	defer cs.unlockPeer(pkiID)

	// 如果已经建立过连接，则返回旧连接，不要再建立新的连接了
	cs.mutex.RLock()
	conn, exists := cs.pki2Conn[pkiID.String()]
	if exists {
		cs.mutex.RUnlock()
		return conn, nil
	}
	cs.mutex.RUnlock()

	createdConnection, err := cs.connFactory.createConnection(endpoint, pkiID)
	if err == nil {
		cs.logger.Debugf("The new connection to %s@%s has been established.", pkiID.String(), endpoint)
		// 检查一下对方是不是已经主动与我们建立了连接，如果已经主动建立了连接，那就把新建立的连接删除掉，然后返回之前建立的连接
		conn, exists = cs.pki2Conn[pkiID.String()]
		if exists {
			if createdConnection != nil {
				createdConnection.close()
			}
			return conn, nil
		}
		// 在已建立的连接中，可能存在有连接的对等方的 id 变更了，那么就将旧连接给关闭掉，并存入新的连接
		if conn, exists := cs.pki2Conn[createdConnection.pkiID.String()]; exists {
			cs.logger.Debugf("Close the old connection to %s@%s.", pkiID.String(), endpoint)
			conn.close()
		}
		cs.pki2Conn[createdConnection.pkiID.String()] = createdConnection
		go createdConnection.serviceConnection()

		return createdConnection, nil
	} else {
		return nil, err
	}
}

func (cs *connStore) lockPeer(pkiID utils.PKIidType) {
	cs.mutex.Lock()
	destinationLock, goingToConnect := cs.destinationLocks[pkiID.String()]
	if !goingToConnect {
		destinationLock = &sync.Mutex{}
		cs.destinationLocks[pkiID.String()] = destinationLock
	}
	cs.mutex.Unlock()
	destinationLock.Lock()
}

func (cs *connStore) unlockPeer(pkiID utils.PKIidType) {
	destinationLock, exists := cs.destinationLocks[pkiID.String()]
	if exists {
		destinationLock.Unlock()
	}
}

func (cs *connStore) connNum() int {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	return len(cs.pki2Conn)
}

func (cs *connStore) shutdown() {
	cs.shutdownOnce.Do(func() {
		cs.mutex.Lock()
		cs.isClosing = true
		for _, conn := range cs.pki2Conn {
			conn.close()
		}
		cs.pki2Conn = make(map[string]*connection)
		cs.mutex.Unlock()
	})
}

func (cs *connStore) isClosed() bool {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	return cs.isClosing
}

// onConnected 关闭到远程对等点的任何连接，并为其创建一个新的连接对象，以便在一对对等点之间只有一个单向连接
func (cs *connStore) onConnected(serverStream pgossip.Gossip_GossipStreamServer, connInfo *utils.ConnectionInfo, metrics *metrics.CommMetrics) *connection {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	if conn, exists := cs.pki2Conn[connInfo.PkiID.String()]; exists {
		conn.close()
	}

	conn := newConnection(nil, nil, serverStream, metrics, cs.config)
	conn.pkiID = connInfo.PkiID
	conn.info = connInfo
	conn.logger = cs.logger
	cs.pki2Conn[connInfo.PkiID.String()] = conn
	return conn
}

func (cs *connStore) closeConnByPKIid(pkiID utils.PKIidType) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	if conn, exists := cs.pki2Conn[pkiID.String()]; exists {
		conn.close()
		cs.logger.Warnf("Close connection %s@%s.", conn.pkiID.String(), conn.info.Endpoint)
		delete(cs.pki2Conn, pkiID.String())
	}
}

/* ------------------------------------------------------------------------------------------ */

type connection struct {
	recvBuffSize int
	metrics      *metrics.CommMetrics
	cancel       context.CancelFunc
	info         *utils.ConnectionInfo
	outBuff      chan *msgSending
	logger       mlog.Logger
	pkiID        utils.PKIidType
	handler      handler
	conn         *grpc.ClientConn
	gossipClient pgossip.GossipClient
	gossipStream stream
	stopCh       chan struct{}
	stopOnce     sync.Once
}

func newConnection(gossipClient pgossip.GossipClient, clientConn *grpc.ClientConn, s stream, metrics *metrics.CommMetrics, config ConnConfig) *connection {
	return &connection{
		metrics:      metrics,
		outBuff:      make(chan *msgSending, config.SendBuffSize),
		gossipClient: gossipClient,
		conn:         clientConn,
		gossipStream: s,
		stopCh:       make(chan struct{}),
		recvBuffSize: config.RecvBuffSize,
	}
}

func (c *connection) close() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
		if c.conn != nil {
			c.conn.Close()
		}
		if c.cancel != nil {
			c.cancel()
		}
	})
}

func (c *connection) send(msg *utils.SignedGossipMessage, onErr func(error), shouldBlock blockingBehavior) {
	m := &msgSending{
		envelope: msg.Envelope,
		onErr:    onErr,
	}

	select {
	case c.outBuff <- m:
	case <-c.stopCh:
		c.logger.Debugf("Stopping sending message to %s, because the connection is closed.", c.info.Endpoint)
	default:
		if shouldBlock {
			select {
			case c.outBuff <- m:
			case <-c.stopCh:
			}
		} else {
			c.metrics.BufferOverflow.Add(1)
			c.logger.Warnf("Buffer to %s overflowed, dropping message.", c.info.Endpoint)
		}
	}
}

func (c *connection) serviceConnection() error {
	errCh := make(chan error, 1)
	msgCh := make(chan *utils.SignedGossipMessage, c.recvBuffSize)

	go c.readFromStream(errCh, msgCh)
	go c.writeToStream()

	for {
		select {
		case <-c.stopCh:
			return nil
		case err := <-errCh:
			return err
		case msg := <-msgCh:
			c.handler(msg)
		}
	}
}

func (c *connection) writeToStream() {
	stream := c.gossipStream
	for {
		select {
		case m := <-c.outBuff:
			err := stream.Send(m.envelope)
			if err != nil {
				go m.onErr(err)
				return
			}
			c.metrics.SentMessages.Add(1)
		case <-c.stopCh:
			c.logger.Debug("Stopping writing to stream.")
			return
		}
	}
}

func (c *connection) readFromStream(errChan chan error, msgChan chan *utils.SignedGossipMessage) {
	stream := c.gossipStream
	for {
		select {
		case <-c.stopCh:
			c.logger.Debug("Stopping reading from stream.")
			return
		default:
			envelope, err := stream.Recv()
			if err != nil {
				errChan <- err
				c.logger.Warnf("Got an error [%s] when reading from stream.", err.Error())
				return
			}
			c.metrics.ReceivedMessages.Add(1)
			msg, err := utils.EnvelopeToSignedGossipMessage(envelope)
			if err != nil {
				errChan <- err
				c.logger.Warnf("Got an error [%s] when reading from stream.", err.Error())
				return
			}
			select {
			case <-c.stopCh:
			case msgChan <- msg:
				c.logger.Debugf("Receive message %s from %s@%s.", msg.String(), c.pkiID.String(), c.info.Endpoint)
			}
		}
	}
}

/* ------------------------------------------------------------------------------------------ */

type ConnConfig struct {
	RecvBuffSize int
	SendBuffSize int
}

type msgSending struct {
	envelope *pgossip.Envelope
	onErr    func(error)
}

type stream interface {
	Send(envelope *pgossip.Envelope) error
	Recv() (*pgossip.Envelope, error)
	Context() context.Context
}
