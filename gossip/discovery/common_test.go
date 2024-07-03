package discovery

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
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
