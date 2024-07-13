/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package election

import (
	"bytes"
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
)

// Gossip 中的领导者选举模型
// Algorithm properties:
// - Peer 节点通过对比 PKI-ID 来竞选 leader。
// - 每个 peer 节点要么是 leader，要么就是 follower，并且当全网节点的视图达到一致时，全网应该在特定时间内只有一个 leader。
// - 如果网络被分成了 n 个区，那么应该存在 n 个 leader，但是如果当所有分片的网络聚拢到一起，最终应该只有一个 leader。
// - Peer 节点之间通过广播 leader declaration 和 follower proposal 来协商出 leader。

//
//
// 变量：
// leaderKnown = false
//
// 规则：
// 	Peer 节点监听来自其他节点的消息，只要其他节点发来一个 leader declaration，就将 leaderKnown 设置成 true。
//
// Startup():
// 等待全网结构达到稳定，或者收到来自其他节点的 leader declaration，或者等待的超时时间结束。
// 进入 SteadyState()
//
// SteadyState()：
// 一直循环：
//		如果 leaderKnown 等于 false：
// 			进入 LeaderElection()
//		如果自己是 leader：
//			广播 leader declaration
//			如果收到一个来自比自己 PKI-ID 更小的 proposal 消息，则让自己成为 follower
//		否则如果自己是 follower：
//			如果在超时时间内没收到 leader declaration 消息，就让 leaderKnown 等于 false
//
// LeaderElection()：
// 	广播 follower proposal 消息
//	收集一段时间内来自其他 peer 节点的 follower proposal 消息
//	如果收到一个 leader declaration 消息：
//		退出 LeaderElection()
//	遍历所有 proposal，如果有 proposal 来自比自己更小的 PKI-ID 的 peer 节点，则退出 LeaderElection()，否则让自己成为 leader。

type leadershipCallback func(isLeader bool)

// LeaderElectionService is the object that runs the leader election algorithm
type LeaderElectionService interface {
	// IsLeader returns whether this peer is a leader or not
	IsLeader() bool

	// Stop stops the LeaderElectionService
	Stop()

	// Yield relinquishes the leadership until a new leader is elected,
	// or a timeout expires
	Yield()
}

func noopCallback(_ bool) {
}

const (
	DefStartupGracePeriod       = time.Second * 15
	DefMembershipSampleInterval = time.Second
	DefLeaderAliveThreshold     = time.Second * 10
	DefLeaderElectionDuration   = time.Second * 5
)

type ElectionConfig struct {
	StartupGracePeriod       time.Duration
	MembershipSampleInterval time.Duration
	LeaderAliveThreshold     time.Duration
	LeaderElectionDuration   time.Duration
}

// NewLeaderElectionService returns a new LeaderElectionService
func NewLeaderElectionService(adapter LeaderElectionAdapter, id utils.PKIidType, callback leadershipCallback, config ElectionConfig, logger mlog.Logger) LeaderElectionService {
	if len(id) == 0 {
		panic("nil id")
	}
	le := &leaderElectionSvcImpl{
		id:            id,
		proposals:     utils.NewSet(),
		adapter:       adapter,
		stopChan:      make(chan struct{}),
		interruptChan: make(chan struct{}, 1),
		logger:        logger,
		callback:      noopCallback,
		config:        config,
		mutex:         &sync.Mutex{},
	}

	if callback != nil {
		le.callback = callback
	}

	go le.start()
	return le
}

// leaderElectionSvcImpl is an implementation of a LeaderElectionService
type leaderElectionSvcImpl struct {
	id            utils.PKIidType
	proposals     *utils.Set
	mutex         *sync.Mutex
	stopChan      chan struct{}
	interruptChan chan struct{}
	stopWG        sync.WaitGroup
	isLeader      int32
	leaderExists  int32
	yield         int32
	sleeping      bool
	adapter       LeaderElectionAdapter
	logger        mlog.Logger
	callback      leadershipCallback
	yieldTimer    *time.Timer
	config        ElectionConfig
}

func (le *leaderElectionSvcImpl) start() {
	le.stopWG.Add(2)
	go le.handleMessages()
	le.waitForMembershipStabilization(le.config.StartupGracePeriod)
	go le.run()
}

func (le *leaderElectionSvcImpl) handleMessages() {
	defer le.stopWG.Done()
	msgChan := le.adapter.Accept()
	for {
		select {
		case <-le.stopChan:
			return
		case msg := <-msgChan:
			leaderMsg := msg.GetLeadershipMsg()
			pkiID := utils.PKIidType(leaderMsg.PkiId)
			if !le.isAlive(leaderMsg.PkiId) {
				le.logger.Debugf("Got message from %s which is not in the view.", pkiID.String())
				break
			}
			le.handleMessage(leaderMsg)
		}
	}
}

func (le *leaderElectionSvcImpl) handleMessage(msg *pgossip.LeadershipMessage) {
	pkiID := utils.PKIidType(msg.PkiId)
	le.mutex.Lock()
	defer le.mutex.Unlock()

	if !msg.IsDeclaration {
		le.logger.Debugf("Peer %s sent us a proposal.", pkiID.String())
		le.proposals.Add(pkiID.String())
	} else {
		le.logger.Debugf("Peer %s sent us a leader declaration.", pkiID.String())
		atomic.StoreInt32(&le.leaderExists, int32(1))
		if le.sleeping && len(le.interruptChan) == 0 {
			le.interruptChan <- struct{}{}
		}
		if bytes.Compare(pkiID, le.id) < 0 && le.IsLeader() {
			le.stopBeingLeader()
		}
	}
}

// waitForInterrupt sleeps until the interrupt channel is triggered
// or given timeout expires
func (le *leaderElectionSvcImpl) waitForInterrupt(timeout time.Duration) {
	le.mutex.Lock()
	le.sleeping = true
	le.mutex.Unlock()

	select {
	case <-le.interruptChan:
	case <-le.stopChan:
	case <-time.After(timeout):
	}

	le.mutex.Lock()
	le.sleeping = false
	// We drain the interrupt channel
	// because we might get 2 leadership declarations messages
	// while sleeping, but we would only read 1 of them in the select block above
	le.drainInterruptChannel()
	le.mutex.Unlock()
}

func (le *leaderElectionSvcImpl) run() {
	defer le.stopWG.Done()
	for !le.isClosed() {
		if !le.isLeaderExists() {
			le.leaderElection()
		}
		// If we are yielding and some leader has been elected,
		// stop yielding
		if le.isLeaderExists() && le.isYielding() {
			le.stopYielding()
		}
		if le.isClosed() {
			return
		}
		if le.IsLeader() {
			le.leader()
		} else {
			le.follower()
		}
	}
}

func (le *leaderElectionSvcImpl) leaderElection() {
	if le.isYielding() {
		return
	}
	// Propose ourselves as a leader
	le.propose()
	// Collect other proposals
	le.waitForInterrupt(le.config.LeaderElectionDuration)
	// If someone declared itself as a leader, give up
	// on trying to become a leader too
	if le.isLeaderExists() {
		le.logger.Info("Some peer is already a leader.")
		return
	}

	if le.isYielding() {
		le.logger.Debug("Aborting leader election because yielding.")
		return
	}
	// Leader doesn't exist, let's see if there is a better candidate than us
	// for being a leader
	for _, o := range le.proposals.ToArray() {
		id := o.(string)
		if bytes.Compare(utils.StringToPKIidType(id), le.id) < 0 {
			return
		}
	}
	// If we got here, there is no one that proposed being a leader
	// that's a better candidate than us.
	le.beLeader()
	atomic.StoreInt32(&le.leaderExists, int32(1))
}

// propose sends a leadership proposal message to remote peers
func (le *leaderElectionSvcImpl) propose() {
	leadershipProposal := le.adapter.CreateMessage(false)
	le.adapter.Gossip(leadershipProposal)
}

func (le *leaderElectionSvcImpl) follower() {
	le.proposals.Clear()
	atomic.StoreInt32(&le.leaderExists, int32(0))
	le.adapter.ReportMetrics(false)
	select {
	case <-time.After(le.config.LeaderAliveThreshold):
	case <-le.stopChan:
	}
}

func (le *leaderElectionSvcImpl) leader() {
	leaderDeclaration := le.adapter.CreateMessage(true)
	le.adapter.Gossip(leaderDeclaration)
	le.adapter.ReportMetrics(true)
	le.waitForInterrupt(le.config.LeaderAliveThreshold / 2)
}

// waitForMembershipStabilization waits for membership view to stabilize
// or until a time limit expires, or until a peer declares itself as a leader
func (le *leaderElectionSvcImpl) waitForMembershipStabilization(timeLimit time.Duration) {
	defer le.logger.Debugf("A total of %d peers are found.", len(le.adapter.Peers()))
	endTime := time.Now().Add(timeLimit)
	viewSize := len(le.adapter.Peers())
	for !le.isClosed() {
		time.Sleep(le.config.MembershipSampleInterval)
		newSize := len(le.adapter.Peers())
		if newSize == viewSize || time.Now().After(endTime) || le.isLeaderExists() {
			return
		}
		viewSize = newSize
	}
}

// drainInterruptChannel clears the interruptChannel
// if needed
func (le *leaderElectionSvcImpl) drainInterruptChannel() {
	if len(le.interruptChan) == 1 {
		<-le.interruptChan
	}
}

// isAlive returns whether peer of given id is considered alive
func (le *leaderElectionSvcImpl) isAlive(id utils.PKIidType) bool {
	for _, p := range le.adapter.Peers() {
		if bytes.Equal(p.PKIid, id) {
			return true
		}
	}
	return false
}

func (le *leaderElectionSvcImpl) isLeaderExists() bool {
	return atomic.LoadInt32(&le.leaderExists) == int32(1)
}

// IsLeader returns whether this peer is a leader
func (le *leaderElectionSvcImpl) IsLeader() bool {
	isLeader := atomic.LoadInt32(&le.isLeader) == int32(1)
	return isLeader
}

func (le *leaderElectionSvcImpl) beLeader() {
	atomic.StoreInt32(&le.isLeader, int32(1))
	le.callback(true)
	le.logger.Info("Becoming a leader.")
}

func (le *leaderElectionSvcImpl) stopBeingLeader() {
	le.logger.Info("Stopped being a leader.")
	atomic.StoreInt32(&le.isLeader, int32(0))
	le.callback(false)
}

func (le *leaderElectionSvcImpl) isClosed() bool {
	select {
	case <-le.stopChan:
		return true
	default:
		return false
	}
}

func (le *leaderElectionSvcImpl) isYielding() bool {
	return atomic.LoadInt32(&le.yield) == int32(1)
}

func (le *leaderElectionSvcImpl) stopYielding() {
	le.logger.Debug("Stopped yielding.")
	le.mutex.Lock()
	defer le.mutex.Unlock()
	atomic.StoreInt32(&le.yield, int32(0))
	le.yieldTimer.Stop()
}

// Yield relinquishes the leadership until a new leader is elected,
// or a timeout expires
func (le *leaderElectionSvcImpl) Yield() {
	le.mutex.Lock()
	defer le.mutex.Unlock()
	if !le.IsLeader() || le.isYielding() {
		return
	}
	// Turn on the yield flag
	atomic.StoreInt32(&le.yield, int32(1))
	// Stop being a leader
	le.stopBeingLeader()
	// Clear the leader exists flag since it could be that we are the leader
	atomic.StoreInt32(&le.leaderExists, int32(0))
	// Clear the yield flag in any case afterwards
	le.yieldTimer = time.AfterFunc(le.config.LeaderAliveThreshold*6, func() {
		atomic.StoreInt32(&le.yield, int32(0))
	})
}

// Stop stops the LeaderElectionService
func (le *leaderElectionSvcImpl) Stop() {
	select {
	case <-le.stopChan:
	default:
		close(le.stopChan)
		le.logger.Info("Stopped leader election service.")
		le.stopWG.Wait()
	}
}
