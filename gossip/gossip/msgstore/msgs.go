package msgstore

import (
	"sync"
	"time"

	"github.com/11090815/mayy/gossip/utils"
)

// invalidationTrigger 当 messageA 因为 messageB 而失效时，会调用 messageA 上的这个触发器。
type invalidationTrigger func(msg any)

var NoopTrigger = func(msg any) {}

var noopLock = func() {}

type MessageStore interface {
	Add(msg any) bool

	// CheckValid 检查消息是否有效。
	CheckValid(msg any) bool

	// Size 返回有效消息的数量。
	Size() int

	// Get 返回所有存储的未过期消息。
	Get() []any

	Stop()

	// Purge 清除掉满足要求的消息。
	Purge(func(any) bool)
}

func Noop(_ any) {}

func NewMessageStoreExpirable(policy utils.MessageReplacingPolicy, trigger invalidationTrigger, msgTTL time.Duration, externalLock, externalUnlock func(), externalExpire func(any)) MessageStore {
	store := newMessageStore(policy, trigger)
	store.msgTTL = msgTTL
	if externalLock != nil {
		store.externalLock = externalLock
	}
	if externalUnlock != nil {
		store.externalUnlock = externalUnlock
	}
	if externalExpire != nil {
		store.expireMsgCallback = externalExpire
	}
	go store.expirationRoutine()
	return store
}

func NewMessageStore(policy utils.MessageReplacingPolicy, trigger invalidationTrigger) MessageStore {
	return newMessageStore(policy, trigger)
}

/* ------------------------------------------------------------------------------------------ */

type messageStoreImpl struct {
	policy            utils.MessageReplacingPolicy
	mutex             *sync.RWMutex
	msgs              []*msg
	invTrigger        invalidationTrigger
	msgTTL            time.Duration
	expiredCount      int
	externalLock      func()
	externalUnlock    func()
	expireMsgCallback func(msg any)
	stopCh            chan struct{}
	stopOnce          sync.Once
}

type msg struct {
	data    any
	created time.Time
	expired bool
}

func newMessageStore(policy utils.MessageReplacingPolicy, trigger invalidationTrigger) *messageStoreImpl {
	return &messageStoreImpl{
		policy:            policy,
		msgs:              make([]*msg, 0),
		invTrigger:        trigger,
		externalLock:      noopLock,
		externalUnlock:    noopLock,
		expireMsgCallback: func(msg any) {},
		expiredCount:      0,
		mutex:             &sync.RWMutex{},
		stopCh:            make(chan struct{}),
	}
}

func (impl *messageStoreImpl) Add(message any) bool {
	impl.mutex.Lock()
	defer impl.mutex.Unlock()

	n := len(impl.msgs)
	for i := 0; i < n; i++ {
		stored := impl.msgs[i]
		switch impl.policy(message, stored.data) {
		case utils.MessageInvalidated:
			return false
		case utils.MessageInvalidates:
			impl.invTrigger(stored.data)
			impl.msgs = append(impl.msgs[:i], impl.msgs[i+1:]...)
			n--
			i--
		}
	}

	impl.msgs = append(impl.msgs, &msg{data: message, created: time.Now()})
	return true
}

func (impl *messageStoreImpl) CheckValid(message any) bool {
	impl.mutex.RLock()
	defer impl.mutex.RUnlock()
	for _, stored := range impl.msgs {
		if impl.policy(message, stored.data) == utils.MessageInvalidated {
			return false
		}
	}

	return true
}

func (impl *messageStoreImpl) Size() int {
	impl.mutex.Lock()
	defer impl.mutex.Unlock()

	return len(impl.msgs) - impl.expiredCount
}

func (impl *messageStoreImpl) Get() []any {
	res := make([]any, 0)

	impl.mutex.RLock()
	defer impl.mutex.RUnlock()

	for _, stored := range impl.msgs {
		if !stored.expired {
			res = append(res, stored.data)
		}
	}

	return res
}

func (impl *messageStoreImpl) Stop() {
	impl.stopOnce.Do(func() {
		close(impl.stopCh)
	})
}

func (impl *messageStoreImpl) Purge(shouldBePurged func(any) bool) {
	// 先检查一遍有没有消息需要被删除
	shouldMsgBePurged := func(m *msg) bool {
		return shouldBePurged(m.data)
	}

	if !impl.isPurgeNeeded(shouldMsgBePurged) {
		return
	}

	impl.mutex.Lock()
	defer impl.mutex.Unlock()

	n := len(impl.msgs)
	for i := 0; i < n; i++ {
		if !shouldMsgBePurged(impl.msgs[i]) {
			continue
		}
		impl.invTrigger(impl.msgs[i].data)
		impl.msgs = append(impl.msgs[:i], impl.msgs[i+1:]...)
		n--
		i--
	}
}

/* ------------------------------------------------------------------------------------------ */

func (impl *messageStoreImpl) isPurgeNeeded(shouldBePurged func(*msg) bool) bool {
	impl.mutex.RLock()
	defer impl.mutex.RUnlock()

	for _, stored := range impl.msgs {
		if shouldBePurged(stored) {
			return true
		}
	}

	return false
}

func (impl *messageStoreImpl) expireMessages() {
	impl.externalLock()
	impl.mutex.Lock()
	defer impl.mutex.Unlock()
	defer impl.externalUnlock()

	n := len(impl.msgs)
	for i := 0; i < n; i++ {
		stored := impl.msgs[i]
		if !stored.expired {
			if time.Since(stored.created) > impl.msgTTL {
				stored.expired = true
				impl.expireMsgCallback(stored.data)
				impl.expiredCount++
			}
		} else {
			if time.Since(stored.created) > (2 * impl.msgTTL) {
				impl.msgs = append(impl.msgs[:i], impl.msgs[i+1:]...)
				n--
				i--
				impl.expiredCount--
			}
		}
	}
}

func (impl *messageStoreImpl) expirationRoutine() {
	for {
		select {
		case <-impl.stopCh:
			return
		case <-time.After(impl.expirationCheckInterval()):
			impl.expireMessages()
		}
	}
}

func (impl *messageStoreImpl) expirationCheckInterval() time.Duration {
	return impl.msgTTL / 100
}
