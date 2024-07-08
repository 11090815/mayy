package election

import (
	"bytes"
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/utils"
)

const (
	DefaultStartupGracePeriod       = time.Second * 15
	DefaultMembershipSampleInterval = time.Second
	DefaultLeaderAliveThreshold     = time.Second * 10
	DefaultLeaderElectionDuration   = time.Second * 5
)

/* ------------------------------------------------------------------------------------------ */

type leadershipCallback func(isLeader bool)

var noopCallback leadershipCallback = func(_ bool) {}

/* ------------------------------------------------------------------------------------------ */

type LeaderElectionService interface {
	// IsLeader 返回一个布尔值指示此 peer 节点是否是 leader。
	IsLeader() bool

	Stop()

	// Yield 在自己已经是 leader 的情况下，调用此方法将放弃领导权，直到选出新的领导人，或者超时。
	Yield()
}

type ElectionConfig struct {
	StartupGracePeriod time.Duration
	// MembershipSampleInterval 在网络建立之初，每隔这段时间会检查一下网络状态是否达到稳定。
	MembershipSampleInterval time.Duration
	LeaderAliveThreshold     time.Duration
	// LeaderElectionDuration 发送完 proposal 后，等待这段时间，让全网节点自己评估自己是否能够当选 leader。
	LeaderElectionDuration time.Duration
}

type leaderElectionService struct {
	id           utils.PKIidType
	adapter      leaderElectionAdapter
	isLeader     int32
	yield        int32
	leaderExists int32
	// yieldTimer 一个计时器，在 6 个任期后，停止放弃竞选 leader。
	yieldTimer  *time.Timer
	proposals   *utils.Set
	stopCh      chan struct{}
	stopWg      sync.WaitGroup
	interruptCh chan struct{}
	sleeping    bool
	callback    leadershipCallback
	config      ElectionConfig
	logger      mlog.Logger
	mutex       *sync.RWMutex
}

func NewLeaderElectionService(adapter leaderElectionAdapter, id utils.PKIidType, callback leadershipCallback, config ElectionConfig, logger mlog.Logger) LeaderElectionService {
	if len(id) == 0 {
		panic("Empty id")
	}
	srv := &leaderElectionService{
		id:          id,
		adapter:     adapter,
		proposals:   utils.NewSet(),
		stopCh:      make(chan struct{}),
		interruptCh: make(chan struct{}),
		callback:    noopCallback,
		config:      config,
		logger:      logger,
		mutex:       &sync.RWMutex{},
	}

	if callback != nil {
		srv.callback = callback
	}

	srv.start()
	return srv
}

func (les *leaderElectionService) IsLeader() bool {
	return atomic.LoadInt32(&les.isLeader) == int32(1)
}

// Yield 只有当节点是 leader 时，调用此方法才会有效，此方法的作用一是放弃自己的 leader 身份，二是在 6 个任期内，放弃竞选 leader。
// 但是对于后一个作用，如果在之后的视图中出现了 leader，那么直接停止放弃竞选 leader。
func (les *leaderElectionService) Yield() {
	les.mutex.Lock()
	defer les.mutex.Unlock()
	if !les.IsLeader() || les.isYielding() {
		return
	}

	atomic.StoreInt32(&les.yield, 1)
	atomic.StoreInt32(&les.isLeader, 0)
	les.callback(false)
	atomic.StoreInt32(&les.leaderExists, 0)
	les.yieldTimer = time.AfterFunc(les.config.LeaderAliveThreshold*6, func() {
		atomic.StoreInt32(&les.yield, 0)
	})
}

func (les *leaderElectionService) Stop() {
	select {
	case <-les.stopCh:
		return
	default:
		close(les.stopCh)
		les.stopWg.Wait()
	}
}

func (les *leaderElectionService) start() {
	les.stopWg.Add(2)
	go les.handleMessages()
	les.waitForMembershipStabilization(les.config.StartupGracePeriod)
	go les.run()
}

func (les *leaderElectionService) handleMessages() {
	defer les.stopWg.Done()
	for {
		select {
		case <-les.stopCh:
			return
		case msg := <-les.adapter.Accept():
			if !les.isAlive(msg.PkiId) {
				les.logger.Warnf("Got message from a peer who is not alive.")
				break
			}

			pkiID := utils.PKIidType(msg.PkiId)
			msgType := "proposal"
			if msg.IsDeclaration() {
				msgType = "declaration"
			}
			les.logger.Debugf("Peer %s sent us %s.", pkiID.String(), msgType)

			if msgType == "proposal" {
				les.proposals.Add(pkiID)
			} else if msgType == "declaration" {
				atomic.StoreInt32(&les.leaderExists, 1)
				if les.sleeping && len(les.interruptCh) == 0 {
					les.mutex.Lock()
					les.interruptCh <- struct{}{}
					les.mutex.Unlock()
				}
				if bytes.Compare(pkiID, les.id) < 0 && les.IsLeader() {
					atomic.StoreInt32(&les.isLeader, 0)
					les.callback(false)
				}
			}
		}
	}
}

func (les *leaderElectionService) run() {
	defer les.stopWg.Done()
	for !les.isClosed() {
		if !les.isLeaderExists() {
			les.leaderElection()
		}

		if les.isLeaderExists() && les.isYielding() {
			// 如果有人当选了 leader，并且自己已经放弃竞选 leader，那么就停止放弃竞选 leader。
			atomic.StoreInt32(&les.yield, 0)
			les.mutex.Lock()
			les.yieldTimer.Stop()
			les.mutex.Unlock()
		}

		if les.IsLeader() { // 如果自己有资格当 leader，就把此消息广而告之给其他节点。
			leaderDeclaration := les.adapter.CreateMessage(true)
			les.adapter.Gossip(leaderDeclaration)
			les.adapter.ReportMetrics(true)
			les.waitForInterrupt(les.config.LeaderAliveThreshold / 2)
		} else { // 自己尚无资格担任 leader，在这里卡住一段时间，这段时间即是 leader 的一轮任期时间
			les.proposals.Clear()
			atomic.StoreInt32(&les.leaderExists, 0)
			les.adapter.ReportMetrics(false)
			select {
			case <-time.After(les.config.LeaderAliveThreshold):
			case <-les.stopCh:
			}
		}
	}
}

func (les *leaderElectionService) leaderElection() {
	// 1. 首先判断自己是否放弃竞选 leader，如果已放弃，则直接退出。
	if les.isYielding() {
		return
	}

	// 2. 广播自己的提案，内含自己的 ID 值。
	proposal := les.adapter.CreateMessage(false)
	les.adapter.Gossip(proposal)

	// 3. 自己的提案已发送出去，我们等待一个 leader 选举的超时时间，看看是不是有人已经宣告自己是 leader 了。
	les.waitForInterrupt(les.config.LeaderElectionDuration)
	if les.isLeaderExists() {
		les.logger.Info("Some peer is already a leader.")
		return
	}

	// 4. 到目前为止，还没有人宣告自己是 leader，但是再检查一下自己是否放弃了选举。
	if les.isYielding() {
		les.logger.Debug("Aborting leader election because yielding.")
		return
	}

	// 5. 到目前为止，没有人认为他们自己有资格当选 leader，那么我自己检查一下，看看是不是自己能够当选。
	for _, proposal := range les.proposals.ToArray() {
		id := proposal.(utils.PKIidType)
		if bytes.Compare(id, les.id) < 0 {
			// 有比自己更适合成为 leader 的候选节点。
			return
		}
	}

	// 6. 最终到了这里，可以明确自己有资格当选 leader
	atomic.StoreInt32(&les.isLeader, 1)
	les.callback(true)
	atomic.StoreInt32(&les.leaderExists, 1)
}

func (les *leaderElectionService) waitForMembershipStabilization(timelimit time.Duration) {
	endTime := time.Now().Add(timelimit)
	viewSize := len(les.adapter.Peers())
	for !les.isClosed() {
		time.Sleep(les.config.MembershipSampleInterval)
		newSize := len(les.adapter.Peers())
		if newSize == viewSize || time.Now().After(endTime) || les.isLeaderExists() {
			return
		}
		viewSize = newSize
	}
}

// isAlive 给定一个 peer 节点的 id，判断此节点在本节点此时视图内是否是 alive 的。
func (les *leaderElectionService) isAlive(id utils.PKIidType) bool {
	for _, p := range les.adapter.Peers() {
		if bytes.Equal(p.PKIid, id) {
			return true
		}
	}
	return false
}

// waitForInterrupt 如果有人宣告自己是 leader，或者 timeout 超时，则此函数不再阻塞进程。
func (les *leaderElectionService) waitForInterrupt(timeout time.Duration) {
	les.mutex.Lock()
	les.sleeping = true
	les.mutex.Unlock()

	select {
	case <-les.interruptCh:
	case <-les.stopCh:
	case <-time.After(timeout):
	}

	les.mutex.Lock()
	les.sleeping = false
	les.drainInterruptChannel()
	les.mutex.Unlock()
}

// drainInterruptChannel 清空 interruptCh 通道。
func (les *leaderElectionService) drainInterruptChannel() {
	if len(les.interruptCh) == 1 {
		<-les.interruptCh
	}
}

func (les *leaderElectionService) isLeaderExists() bool {
	return atomic.LoadInt32(&les.leaderExists) == int32(1)
}

// isYielding 是否处在放弃竞选 leader 的状态。
func (les *leaderElectionService) isYielding() bool {
	return atomic.LoadInt32(&les.yield) == int32(1)
}

func (les *leaderElectionService) isClosed() bool {
	select {
	case <-les.stopCh:
		return true
	default:
		return false
	}
}
