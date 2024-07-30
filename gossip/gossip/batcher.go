package gossip

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/common/errors"
)

type emitBatchCallback func([]any)

type BatchingEmitter interface {
	Add(any)

	Stop()

	// Size 返回要被发送的消息数量。
	Size() int
}

type batchingEmitter struct {
	// iterations 定义了批处理中每个消息能被触发执行 emit 的次数。
	iterations int
	// burstSize 批处理的消息上限，如果批处理增加的消息数量达到 burstSize，则主动执行一次批处理。
	burstSize int
	delay     time.Duration
	callback  emitBatchCallback
	mutex     *sync.Mutex
	buff      []*batchedMessage
	stopFlag  int32
}

func newBatchingEmitter(iterations, burstSize int, delay time.Duration, callback emitBatchCallback) BatchingEmitter {
	if iterations < 0 {
		panic(errors.NewErrorf("got a negative iteration number: %d", iterations))
	}

	be := &batchingEmitter{
		iterations: iterations,
		burstSize:  burstSize,
		delay:      delay,
		callback:   callback,
		mutex:      &sync.Mutex{},
		buff:       make([]*batchedMessage, 0),
		stopFlag:   int32(0),
	}

	if iterations != 0 {
		go be.periodicalEmit()
	}

	return be
}

type batchedMessage struct {
	data any
	// 当 iterationsLeft 等于 0 的时候，这个消息就要从 batcher 里被删除了，
	// 每触发一次发送此消息的动作，该值就会自减 1。
	iterationsLeft int
}

func (be *batchingEmitter) Add(message any) {
	if be.iterations == 0 {
		return
	}
	be.mutex.Lock()
	defer be.mutex.Unlock()
	be.buff = append(be.buff, &batchedMessage{data: message, iterationsLeft: be.iterations})
	if len(be.buff) >= be.burstSize {
		be.emit()
	}
}

func (be *batchingEmitter) Size() int {
	be.mutex.Lock()
	defer be.mutex.Unlock()
	return len(be.buff)
}

func (be *batchingEmitter) Stop() {
	atomic.StoreInt32(&be.stopFlag, 1)
}

func (be *batchingEmitter) emit() {
	if be.toDie() {
		return
	}
	if len(be.buff) == 0 {
		return
	}

	msgs2beEmitted := make([]any, len(be.buff))
	for i, v := range be.buff {
		msgs2beEmitted[i] = v.data
	}
	be.callback(msgs2beEmitted)
	be.decrementCounters()
}

func (be *batchingEmitter) decrementCounters() {
	n := len(be.buff)
	for i := 0; i < n; i++ {
		msg := be.buff[i]
		msg.iterationsLeft--
		if msg.iterationsLeft == 0 {
			be.buff = append(be.buff[:i], be.buff[i+1:]...)
			n--
			i--
		}
	}
}

func (be *batchingEmitter) toDie() bool {
	return atomic.LoadInt32(&be.stopFlag) == int32(1)
}

func (be *batchingEmitter) periodicalEmit() {
	for !be.toDie() {
		time.Sleep(be.delay)
		be.mutex.Lock()
		be.emit()
		be.mutex.Unlock()
	}
}
