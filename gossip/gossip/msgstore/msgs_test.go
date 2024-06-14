package msgstore

import (
	"math/rand"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/11090815/mayy/gossip/utils"
	"github.com/stretchr/testify/require"
)

var random = rand.New(rand.NewSource(time.Now().UnixNano()))

func compareInts(this, that any) utils.InfluenceResult {
	a := this.(int)
	b := that.(int)

	if a == b {
		return utils.MessageNoAction
	}

	if a > b {
		return utils.MessageInvalidates
	}

	return utils.MessageInvalidated
}

func nonReplaceInts(this, that any) utils.InfluenceResult {
	a := this.(int)
	b := that.(int)
	if a == b {
		return utils.MessageInvalidated
	}
	return utils.MessageNoAction
}

func alwaysNoAction(_, _ any) utils.InfluenceResult {
	return utils.MessageNoAction
}

func TestSize(t *testing.T) {
	store := NewMessageStore(alwaysNoAction, Noop)
	store.Add(0)
	store.Add(0)
	store.Add(0)
	require.Equal(t, 3, store.Size())
}

func TestStoreInvalidates(t *testing.T) {
	invalidated := make([]int, 0)
	store := NewMessageStore(compareInts, func(msg any) {
		invalidated = append(invalidated, msg.(int))
	})
	require.True(t, store.Add(0))
	for i := 1; i < 10; i++ {
		require.True(t, store.Add(i))
		require.Equal(t, i-1, invalidated[len(invalidated)-1])
		require.Equal(t, 1, store.Size())
		require.Equal(t, i, store.Get()[0].(int))
	}
}

func TestMessageGet(t *testing.T) {
	contains := func(a []any, b any) bool {
		for _, v := range a {
			if reflect.DeepEqual(v, b) {
				return true
			}
		}
		return false
	}

	store := NewMessageStore(alwaysNoAction, Noop)
	expected := []int{}
	for i := 0; i < 2; i++ {
		n := random.Int()
		expected = append(expected, n)
		store.Add(n)
	}

	for _, num := range expected {
		require.True(t, contains(store.Get(), num))
	}
}

func TestInvalidated(t *testing.T) {
	store := NewMessageStore(compareInts, Noop)
	require.True(t, store.Add(10))
	for i := 9; i > 0; i-- {
		require.False(t, store.Add(i))
		require.Len(t, store.Get(), 1)
		require.Equal(t, 10, store.Get()[0].(int))
	}
}

func TestConcurrency(t *testing.T) {
	stopFlag := int32(0)
	wg := sync.WaitGroup{}
	wg.Add(3)
	store := NewMessageStore(compareInts, Noop)
	looper := func(f func()) func() {
		return func() {
			for {
				if atomic.LoadInt32(&stopFlag) == 1 {
					wg.Done()
					return
				}
				f()
			}
		}
	}

	addProcess := looper(func() {
		store.Add(random.Int())
	})

	getProcess := looper(func() {
		store.Get()
	})

	sizeProcess := looper(func() {
		store.Size()
	})

	go addProcess()
	go getProcess()
	go sizeProcess()

	time.Sleep(time.Millisecond * 3000)
	atomic.StoreInt32(&stopFlag, 1)
	wg.Wait()
}

func TestExpiration(t *testing.T) {
	expired := make(chan int, 50)
	msgTTL := time.Millisecond * 3000

	store := NewMessageStoreExpirable(nonReplaceInts, Noop, msgTTL, nil, nil, func(a any) {
		expired <- a.(int)
	})

	for i := 0; i < 10; i++ {
		require.True(t, store.Add(i))
	}

	require.Equal(t, 10, store.Size())

	time.Sleep(time.Millisecond * 2000)

	for i := 0; i < 10; i++ {
		require.False(t, store.CheckValid(i))
		require.False(t, store.Add(i))
	}

	for i := 10; i < 20; i++ {
		require.True(t, store.CheckValid(i))
		require.True(t, store.Add(i))
		require.False(t, store.CheckValid(i))
	}

	require.Equal(t, 20, store.Size())

	time.Sleep(time.Second * 2)

	for i := 0; i < 20; i++ {
		require.False(t, store.Add(i))
	}

	require.Equal(t, 10, store.Size())
	require.Equal(t, 10, len(expired))

	time.Sleep(time.Millisecond * 4000)
	require.Equal(t, 0, store.Size())
	require.Equal(t, 20, len(expired))

	for i := 0; i < 10; i++ {
		require.True(t, store.CheckValid(i))
		require.True(t, store.Add(i))
		require.False(t, store.CheckValid(i))
	}

	require.Equal(t, 10, store.Size())
}

func TestExpirationConcurrency(t *testing.T) {
	expired := make([]int, 0)
	msgTTL := time.Millisecond * 3000
	lock := &sync.Mutex{}

	store := NewMessageStoreExpirable(nonReplaceInts, Noop, msgTTL, func() { lock.Lock() }, func() { lock.Unlock() }, func(a any) { expired = append(expired, a.(int)) })

	lock.Lock()
	for i := 0; i < 10; i++ {
		require.True(t, store.Add(i))
	}
	require.Equal(t, 10, store.Size())
	lock.Unlock()

	time.Sleep(time.Millisecond * 2000)

	lock.Lock()
	time.Sleep(time.Millisecond * 2000)
	for i := 0; i < 10; i++ {
		require.False(t, store.Add(i))
	}
	require.Equal(t, 10, store.Size())
	require.Equal(t, 0, len(expired))
	lock.Unlock()

	time.Sleep(time.Millisecond * 1000)

	lock.Lock()
	for i := 0; i < 10; i++ {
		require.False(t, store.Add(i))
	}
	require.Equal(t, 0, store.Size())
	require.Equal(t, 10, len(expired))
	lock.Unlock()
}

func TestStop(t *testing.T) {
	expired := make([]int, 0)
	msgTTL := time.Millisecond * 3000

	store := NewMessageStoreExpirable(nonReplaceInts, Noop, msgTTL, nil, nil, func(a any) { expired = append(expired, a.(int)) })
	for i := 0; i < 10; i++ {
		require.True(t, store.Add(i))
	}
	require.Equal(t, 10, store.Size())

	store.Stop()

	time.Sleep(time.Millisecond * 4000)
	require.Equal(t, 10, store.Size())
	require.Equal(t, 0, len(expired))
	store.Stop()
}

func TestPurge(t *testing.T) {
	purged := make(chan int, 5)
	store := NewMessageStore(alwaysNoAction, func(msg any) {
		purged <- msg.(int)
	})

	for i := 0; i < 10; i++ {
		require.True(t, store.Add(i))
	}

	store.Purge(func(a any) bool {
		return a.(int) > 9
	})
	require.Equal(t, 10, store.Size())

	store.Purge(func(a any) bool {
		return a.(int)%2 == 0
	})
	require.Equal(t, 5, store.Size())

	for _, num := range store.Get() {
		require.Equal(t, 1, num.(int)%2)
	}
	close(purged) // 关闭通道后再遍历通道就不会被阻塞
	i := 0
	for n := range purged {
		require.Equal(t, i, n)
		i += 2
	}
}
