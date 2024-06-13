package algo

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/stretchr/testify/require"
)

var logger = mlog.GetLogger("test", mlog.DebugLevel, false)

type messageHook func(any)

type pullTestInstance struct {
	msgHooks          []messageHook
	peers             map[string]*pullTestInstance
	name              string
	nextPeerSelection []string
	msgQueue          chan any
	mutex             *sync.Mutex
	stopCh            chan struct{}
	PullEngine
}

func newPushPullTestInstance(name string, peers map[string]*pullTestInstance) *pullTestInstance {
	inst := &pullTestInstance{
		msgHooks:          make([]messageHook, 0),
		peers:             peers,
		name:              name,
		nextPeerSelection: make([]string, 0),
		msgQueue:          make(chan any, 100),
		mutex:             &sync.Mutex{},
		stopCh:            make(chan struct{}),
	}

	config := PullEngineConfig{
		DigestWaitTime:   time.Millisecond * 100,
		RequestWaitTime:  time.Millisecond * 200,
		ResponseWaitTime: time.Millisecond * 200,
	}

	inst.PullEngine = NewPullEngine(inst, time.Millisecond*500, config)

	peers[name] = inst

	go func() {
		for {
			select {
			case <-inst.stopCh:
				return
			case m := <-inst.msgQueue:
				inst.handleMessage(m)
			}
		}
	}()

	return inst
}

type helloMsg struct {
	nonce  uint64
	source string
}

type digestMsg struct {
	nonce   uint64
	digests []string
	source  string
}

type reqMsg struct {
	items  []string
	nonce  uint64
	source string
}

type resMsg struct {
	items []string
	nonce uint64
}

/* ------------------------------------------------------------------------------------------ */

func (p *pullTestInstance) handleMessage(m any) {
	p.mutex.Lock()
	for _, hook := range p.msgHooks {
		hook(m)
	}
	p.mutex.Unlock()

	if hello, ok := m.(*helloMsg); ok {
		logger.Infof("Peer %s is receiving hello message (nonce: %d) from %s.", p.name, hello.nonce, hello.source)
		p.OnHello(hello.nonce, hello.source)
		return
	}

	if digest, ok := m.(*digestMsg); ok {
		logger.Infof("Peer %s is handling digests %v (nonce: %d) from %s.", p.name, digest.digests, digest.nonce, digest.source)
		p.OnDigests(digest.digests, digest.nonce, digest.source)
	}

	if req, ok := m.(*reqMsg); ok {
		logger.Infof("Peer %s is handling request message (nonce: %d, items: %v) from %s.", p.name, req.nonce, req.items, req.source)
		p.OnReq(req.items, req.nonce, req.source)
	}

	if res, ok := m.(*resMsg); ok {
		logger.Infof("Peer %s is handling response message (nonce: %d, items: %v).", p.name, res.nonce, res.items)
		p.OnRes(res.items, res.nonce)
	}
}

func (p *pullTestInstance) hook(f messageHook) {
	p.mutex.Lock()
	p.msgHooks = append(p.msgHooks, f)
	p.mutex.Unlock()
}

func (p *pullTestInstance) stop() {
	close(p.stopCh)
	p.Stop()
}

func (p *pullTestInstance) setNextPeerSelection(selection []string) {
	p.mutex.Lock()
	p.nextPeerSelection = selection
	p.mutex.Unlock()
}

func (p *pullTestInstance) SelectPeers() []string {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.nextPeerSelection
}

func (p *pullTestInstance) Hello(dest string, nonce uint64) {
	p.peers[dest].msgQueue <- &helloMsg{nonce: nonce, source: p.name}
}

func (p *pullTestInstance) SendDigest(digests []string, nonce uint64, context any) {
	p.peers[context.(string)].msgQueue <- &digestMsg{nonce: nonce, digests: digests, source: p.name}
}

func (p *pullTestInstance) SendReq(dest string, items []string, nonce uint64) {
	p.peers[dest].msgQueue <- &reqMsg{items: items, nonce: nonce, source: p.name}
}

func (p *pullTestInstance) SendRes(items []string, nonce uint64, context any) {
	p.peers[context.(string)].msgQueue <- &resMsg{items: items, nonce: nonce}
}

/* ------------------------------------------------------------------------------------------ */

func TestPullEngineAdd(t *testing.T) {
	peers := make(map[string]*pullTestInstance)
	inst1 := newPushPullTestInstance("p1", peers)
	defer inst1.stop()
	inst1.Add("0")
	inst1.Add("0")
	require.True(t, inst1.PullEngine.(*pullEngineImpl).state.Exists("0"))
	require.Len(t, inst1.PullEngine.(*pullEngineImpl).state.ToArray(), 1)
}

func TestPullEngineRemove(t *testing.T) {
	peers := make(map[string]*pullTestInstance)
	inst1 := newPushPullTestInstance("p1", peers)
	defer inst1.stop()
	inst1.Add("0")
	require.True(t, inst1.PullEngine.(*pullEngineImpl).state.Exists("0"))
	inst1.Remove("0")
	require.False(t, inst1.PullEngine.(*pullEngineImpl).state.Exists("0"))
	inst1.Remove("0")
	require.False(t, inst1.PullEngine.(*pullEngineImpl).state.Exists("0"))
}

func TestPullEngineStop(t *testing.T) {
	peers := make(map[string]*pullTestInstance)
	inst1 := newPushPullTestInstance("p1", peers)
	inst2 := newPushPullTestInstance("p2", peers)
	defer inst2.stop()
	inst2.setNextPeerSelection([]string{"p1"})
	go func() {
		for i := 0; i < 100; i++ {
			inst1.Add(fmt.Sprintf("item%d", i))
			time.Sleep(time.Millisecond * 10)
		}
	}()

	time.Sleep(time.Millisecond * 800)
	len1 := len(inst2.PullEngine.(*pullEngineImpl).state.ToArray())
	inst1.stop()
	time.Sleep(time.Millisecond * 800)
	len2 := len(inst2.PullEngine.(*pullEngineImpl).state.ToArray())
	require.Equal(t, len1, len2)
}

func TestPullEngineAll2All(t *testing.T) {
	instCount := 10
	peers := make(map[string]*pullTestInstance)
	nextPeers := make(map[string][]string)

	for i := 0; i < instCount; i++ {
		pID := fmt.Sprintf("p%d", i+1)
		nextPeers[pID] = make([]string, 0)
		for j := 0; j < instCount; j++ {
			if j == i {
				continue
			}
			nextPeers[pID] = append(nextPeers[pID], fmt.Sprintf("p%d", j+1))
		}
		inst := newPushPullTestInstance(pID, peers)
		inst.setNextPeerSelection(nextPeers[pID])
		inst.Add(strconv.Itoa(i + 1))
		time.Sleep(time.Millisecond * 50)
	}

	time.Sleep(time.Millisecond * 4000)

	for i := 0; i < instCount; i++ {
		require.Equal(t, instCount, len(peers[fmt.Sprintf("p%d", i+1)].PullEngine.(*pullEngineImpl).state.ToArray()))
	}
}

func TestPullEngineSelectiveUpdates(t *testing.T) {
	peers := make(map[string]*pullTestInstance)
	inst1 := newPushPullTestInstance("p1", peers)
	inst2 := newPushPullTestInstance("p2", peers)
	defer inst1.stop()
	defer inst2.stop()

	inst1.Add("1", "3")
	inst2.Add("0", "1", "2", "3")

	inst1.hook(func(a any) {
		if digest, ok := a.(*digestMsg); ok {
			require.True(t, utils.IndexInSlice(digest.digests, "0", cmp) != -1)
			require.True(t, utils.IndexInSlice(digest.digests, "1", cmp) != -1)
			require.True(t, utils.IndexInSlice(digest.digests, "2", cmp) != -1)
			require.True(t, utils.IndexInSlice(digest.digests, "3", cmp) != -1)
		}
	})

	inst2.hook(func(a any) {
		if req, ok := a.(*reqMsg); ok {
			require.True(t, utils.IndexInSlice(req.items, "1", cmp) == -1)
			require.True(t, utils.IndexInSlice(req.items, "3", cmp) == -1)
			require.True(t, utils.IndexInSlice(req.items, "0", cmp) != -1)
			require.True(t, utils.IndexInSlice(req.items, "2", cmp) != -1)
		}
	})

	inst1.hook(func(a any) {
		if res, ok := a.(*resMsg); ok {
			require.True(t, utils.IndexInSlice(res.items, "1", cmp) == -1)
			require.True(t, utils.IndexInSlice(res.items, "3", cmp) == -1)
			require.True(t, utils.IndexInSlice(res.items, "0", cmp) != -1)
			require.True(t, utils.IndexInSlice(res.items, "2", cmp) != -1)
		}
	})

	inst1.setNextPeerSelection([]string{"p2"})
	time.Sleep(time.Millisecond * 2000)
	require.Len(t, inst2.PullEngine.(*pullEngineImpl).state.ToArray(), len(inst1.PullEngine.(*pullEngineImpl).state.ToArray()))
}

func TestByzantineResponder(t *testing.T) {
	peers := make(map[string]*pullTestInstance)
	inst1 := newPushPullTestInstance("p1", peers)
	inst2 := newPushPullTestInstance("p2", peers)
	inst3 := newPushPullTestInstance("p3", peers)
	defer inst1.stop()
	defer inst2.stop()
	defer inst3.stop()

	receivedDigestFromInst3 := int32(0)

	inst2.Add("1", "2", "3")
	inst3.Add("1", "6", "7")

	inst2.hook(func(a any) {
		if _, isHello := a.(*helloMsg); isHello {
			inst3.SendDigest([]string{"5", "6", "7"}, 0, "p1") // 此 nonce 不在 inst1 已发送的 nonce 队列里
		}
	})

	inst1.hook(func(a any) {
		if digest, ok := a.(*digestMsg); ok {
			if digest.source == "p3" {
				atomic.StoreInt32(&receivedDigestFromInst3, 1)
				time.AfterFunc(time.Millisecond*150, func() {
					inst3.SendRes([]string{"5", "6", "7"}, 0, "p1")
				})
			}
		}

		if res, ok := a.(*resMsg); ok {
			if utils.IndexInSlice(res.items, "6", cmp) != -1 {
				require.Equal(t, int32(1), atomic.LoadInt32(&(inst1.PullEngine.(*pullEngineImpl).acceptingResponses)))
			}
		}
	})

	inst1.setNextPeerSelection([]string{"p2"})
	time.Sleep(time.Second)
	require.Equal(t, int32(1), atomic.LoadInt32(&receivedDigestFromInst3))

	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "1", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "2", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "3", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "5", cmp) == -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "6", cmp) == -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "7", cmp) == -1)
}

func TestMultipleInitiators(t *testing.T) {
	peers := make(map[string]*pullTestInstance)
	inst1 := newPushPullTestInstance("p1", peers)
	inst2 := newPushPullTestInstance("p2", peers)
	inst3 := newPushPullTestInstance("p3", peers)
	inst4 := newPushPullTestInstance("p4", peers)
	defer inst1.stop()
	defer inst2.stop()
	defer inst3.stop()
	defer inst4.stop()

	inst4.Add("1", "2", "3", "4")
	inst1.setNextPeerSelection([]string{"p4"})
	inst2.setNextPeerSelection([]string{"p4"})
	inst3.setNextPeerSelection([]string{"p4"})

	time.Sleep(time.Second * 2)

	for _, inst := range []*pullTestInstance{inst1, inst2, inst3} {
		require.True(t, utils.IndexInSlice(inst.PullEngine.(*pullEngineImpl).state.ToArray(), "1", cmp) != -1)
		require.True(t, utils.IndexInSlice(inst.PullEngine.(*pullEngineImpl).state.ToArray(), "2", cmp) != -1)
		require.True(t, utils.IndexInSlice(inst.PullEngine.(*pullEngineImpl).state.ToArray(), "3", cmp) != -1)
		require.True(t, utils.IndexInSlice(inst.PullEngine.(*pullEngineImpl).state.ToArray(), "4", cmp) != -1)
	}
}

func TestLatePeers(t *testing.T) {
	peers := make(map[string]*pullTestInstance)
	inst1 := newPushPullTestInstance("p1", peers)
	inst2 := newPushPullTestInstance("p2", peers)
	inst3 := newPushPullTestInstance("p3", peers)
	defer inst1.stop()
	defer inst2.stop()
	defer inst3.stop()

	inst2.Add("1", "2", "3", "4")
	inst3.Add("5", "6", "7", "8")
	inst2.hook(func(a any) {
		time.Sleep(time.Millisecond * 600)
	})
	inst1.setNextPeerSelection([]string{"p2", "p3"})

	time.Sleep(time.Millisecond * 2000)

	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "1", cmp) == -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "2", cmp) == -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "3", cmp) == -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "4", cmp) == -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "5", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "6", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "7", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "8", cmp) != -1)
}

func TestBiDiUpdates(t *testing.T) {
	peers := make(map[string]*pullTestInstance)
	inst1 := newPushPullTestInstance("p1", peers)
	inst2 := newPushPullTestInstance("p2", peers)
	defer inst1.stop()
	defer inst2.stop()

	inst1.Add("1", "3")
	inst2.Add("0", "2")

	inst1.setNextPeerSelection([]string{"p2"})
	inst2.setNextPeerSelection([]string{"p1"})

	time.Sleep(time.Millisecond * 2000)

	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "0", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "1", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "2", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst1.PullEngine.(*pullEngineImpl).state.ToArray(), "3", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst2.PullEngine.(*pullEngineImpl).state.ToArray(), "0", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst2.PullEngine.(*pullEngineImpl).state.ToArray(), "1", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst2.PullEngine.(*pullEngineImpl).state.ToArray(), "2", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst2.PullEngine.(*pullEngineImpl).state.ToArray(), "3", cmp) != -1)
}

func TestSpread(t *testing.T) {
	peers := make(map[string]*pullTestInstance)
	inst1 := newPushPullTestInstance("p1", peers)
	inst2 := newPushPullTestInstance("p2", peers)
	inst3 := newPushPullTestInstance("p3", peers)
	inst4 := newPushPullTestInstance("p4", peers)
	inst5 := newPushPullTestInstance("p5", peers)
	defer inst1.stop()
	defer inst2.stop()
	defer inst3.stop()
	defer inst4.stop()
	defer inst5.stop()

	chooseCounters := make(map[string]int)
	chooseCounters["p2"] = 0
	chooseCounters["p3"] = 0
	chooseCounters["p4"] = 0
	chooseCounters["p5"] = 0

	mutex := &sync.Mutex{}

	addToCounters := func(dest string) func(m any) {
		return func(m any) {
			if _, isReq := m.(*reqMsg); isReq {
				mutex.Lock()
				chooseCounters[dest]++
				mutex.Unlock()
			}
		}
	}

	inst2.hook(addToCounters("p2"))
	inst3.hook(addToCounters("p3"))
	inst4.hook(addToCounters("p4"))
	inst5.hook(addToCounters("p5"))

	for i := 0; i < 100; i++ {
		item := strconv.Itoa(i)
		inst2.Add(item)
		inst3.Add(item)
		inst4.Add(item)
	}

	inst1.setNextPeerSelection([]string{"p2", "p3", "p4"})

	time.Sleep(time.Millisecond * 2000)

	mutex.Lock()
	for peer, counter := range chooseCounters {
		if peer == "p5" {
			require.Equal(t, 0, counter)
		} else {
			require.True(t, counter > 0)
		}
	}
	mutex.Unlock()
}

func TestFilter(t *testing.T) {
	peers := make(map[string]*pullTestInstance)
	inst1 := newPushPullTestInstance("p1", peers)
	inst2 := newPushPullTestInstance("p2", peers)
	inst3 := newPushPullTestInstance("p3", peers)
	defer inst1.stop()
	defer inst2.stop()
	defer inst3.stop()

	inst1.PullEngine.(*pullEngineImpl).digFilter = func(context any) func(digestItem string) bool {
		return func(digestItem string) bool {
			n, _ := strconv.Atoi(digestItem)
			if context == "p2" {
				return n%2 == 0
			}
			return n%2 == 1
		}
	}

	inst1.Add("0", "1", "2", "3", "4", "5")
	inst2.setNextPeerSelection([]string{"p1"})
	inst3.setNextPeerSelection([]string{"p1"})

	time.Sleep(time.Millisecond * 2000)

	require.True(t, utils.IndexInSlice(inst2.PullEngine.(*pullEngineImpl).state.ToArray(), "0", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst2.PullEngine.(*pullEngineImpl).state.ToArray(), "1", cmp) == -1)
	require.True(t, utils.IndexInSlice(inst2.PullEngine.(*pullEngineImpl).state.ToArray(), "2", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst2.PullEngine.(*pullEngineImpl).state.ToArray(), "3", cmp) == -1)
	require.True(t, utils.IndexInSlice(inst2.PullEngine.(*pullEngineImpl).state.ToArray(), "4", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst2.PullEngine.(*pullEngineImpl).state.ToArray(), "5", cmp) == -1)

	require.True(t, utils.IndexInSlice(inst3.PullEngine.(*pullEngineImpl).state.ToArray(), "0", cmp) == -1)
	require.True(t, utils.IndexInSlice(inst3.PullEngine.(*pullEngineImpl).state.ToArray(), "1", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst3.PullEngine.(*pullEngineImpl).state.ToArray(), "2", cmp) == -1)
	require.True(t, utils.IndexInSlice(inst3.PullEngine.(*pullEngineImpl).state.ToArray(), "3", cmp) != -1)
	require.True(t, utils.IndexInSlice(inst3.PullEngine.(*pullEngineImpl).state.ToArray(), "4", cmp) == -1)
	require.True(t, utils.IndexInSlice(inst3.PullEngine.(*pullEngineImpl).state.ToArray(), "5", cmp) != -1)
}

func cmp(a, b any) bool {
	return a.(string) == b.(string)
}
