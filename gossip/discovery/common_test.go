package discovery

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

type Once struct {
	done int32
}

func (o *Once) Do() {
	atomic.StoreInt32(&o.done, 1)
}

type testComm struct {
	once Once
}

func (c *testComm) close() {
	c.once.Do()
}

func TestOnceDo(t *testing.T) {
	comm := &testComm{}
	require.Equal(t, int32(0), comm.once.done)
	comm.close()
	require.Equal(t, int32(1), comm.once.done)

	if comm.once.done == 1 {
		t.Log("测试成功")
	}
}

type Obj struct {
	mu *sync.Mutex
}

func (o Obj) Lock() {o.mu.Lock()}
func (o Obj) Unlock() {o.mu.Unlock()}
func (o Obj) Do() {fmt.Println("do something")}

func TestCopyLock(t *testing.T) {
	o := Obj{mu: &sync.Mutex{}}
	o.Lock()
	o.Do()
	o.Unlock()

	o.Lock()
	o.Do()
	o.Unlock()
}

func TestLock(t *testing.T) {
	mutex := &sync.RWMutex{}
	mutex.RLock()
	mutex.RLock()
	mutex.RUnlock()
	mutex.RUnlock()
	t.Log("finish")
}

func TestChannel(t *testing.T) {
	ch := make(chan int, 1000)
	go func() {
		for i := 1; i <= 54; i++ {
			ch <- i
		}
	}()
	time.Sleep(time.Second)
	close(ch)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second * 10)
	defer cancel()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func(cha <-chan int) {
		c := cha
		for {
			select {
			case m := <- c:
				time.Sleep(time.Millisecond * 10)
				t.Log("m:", m)
			case <-ctx.Done():
				wg.Done()
				return
			}
		}
	}(ch)
	wg.Wait()
}

func TestConcurrency(t *testing.T) {
	logger := utils.GetLogger(utils.DiscoveryLogger, "p1", mlog.DebugLevel, true, true)
	
	type consenter struct {
		logger mlog.Logger
		cost time.Duration
	}

	c := &consenter{
		logger: logger,
		cost: time.Millisecond * 30,
	}

	doSomething := func(c *consenter) {
		for i := 1; i < 10; i++ {
			c.logger.Debugf("计数：%d.", i+1)
			time.Sleep(c.cost)
		}
	}

	go doSomething(c)
}
