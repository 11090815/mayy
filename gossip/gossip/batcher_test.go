package gossip

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBatchingEmitterAddAndSize(t *testing.T) {
	emitter := newBatchingEmitter(1, 10, time.Second, func(a []any) {})
	defer emitter.Stop()
	emitter.Add(1)
	emitter.Add(2)
	emitter.Add(3)
	require.Equal(t, 3, emitter.Size())
}

func TestBatchingEmitterStop(t *testing.T) {
	times := int32(0)
	callback := func(a []any) {
		atomic.AddInt32(&times, int32(len(a)))
	}
	emitter := newBatchingEmitter(10, 1, time.Millisecond * 100, callback)
	emitter.Add(1)
	time.Sleep(time.Millisecond * 390)
	emitter.Stop()
	time.Sleep(time.Second)
	t.Log(times)
}

func TestBatchingEmitterExpiration(t *testing.T) {
	times := int32(0)
	callback := func(a []any) {
		atomic.AddInt32(&times, 1)
	}

	emitter := newBatchingEmitter(10, 1, time.Millisecond * 10, callback)
	defer emitter.Stop()

	emitter.Add(1)
	time.Sleep(time.Millisecond * 500)
	require.Equal(t, int32(10), atomic.LoadInt32(&times))
	require.Equal(t, 0, emitter.Size())
}

func TestBatchingEmitterCounter(t *testing.T) {
	counters := make(map[int]int)
	lock := &sync.Mutex{}
	callback := func(a []any) {
		lock.Lock()
		defer lock.Unlock()
		for _, e := range a {
			n := e.(int)
			if _, exists := counters[n]; !exists {
				counters[n] = 1
			} else {
				counters[n]++
			}
		}
	}

	emitter := newBatchingEmitter(5, 100, 500 * time.Millisecond, callback)
	defer emitter.Stop()

	for i := 1; i <= 5; i++ {
		emitter.Add(i)
		time.Sleep(time.Millisecond * 600)
	}
	
	lock.Lock()
	t.Log(counters)
	lock.Unlock()
}

func TestBatchingEmitterBurstSizeCap(t *testing.T) {
	times := int32(0)
	callback := func(a []any) {
		atomic.AddInt32(&times, 1)
	}
	emitter := newBatchingEmitter(1, 10, time.Millisecond*800, callback)
	defer emitter.Stop()

	for i := 0; i < 50; i++ {
		emitter.Add(i)
	}
	require.Equal(t, int32(5), atomic.LoadInt32(&times))
}
