package comm

import (
	"sync"

	"github.com/11090815/mayy/gossip/utils"
)

type ChannelDeMultiplexer struct {
	mutex           sync.Mutex
	closed          bool
	stopCh          chan struct{}
	deMuxInProgress sync.WaitGroup
	channels        []*channel
}

type channel struct {
	pred utils.MessageAcceptor
	ch   chan<- any
}

func NewChannelDeMultiplexer() *ChannelDeMultiplexer {
	return &ChannelDeMultiplexer{stopCh: make(chan struct{})}
}

func (demux *ChannelDeMultiplexer) Close() {
	demux.mutex.Lock()
	if demux.closed {
		demux.mutex.Unlock()
		return
	}
	demux.closed = true
	close(demux.stopCh)
	demux.deMuxInProgress.Wait()
	for _, ch := range demux.channels {
		close(ch.ch)
	}
	demux.channels = nil
	demux.mutex.Unlock()
}

// AddChannel 根据接收消息的 predicate 注册一个信道，然后返回此信道消息 read-only 通道。
func (demux *ChannelDeMultiplexer) AddChannel(predicate utils.MessageAcceptor) <-chan any {
	demux.mutex.Lock()
	if demux.closed {
		demux.mutex.Unlock()
		ch := make(chan any)
		close(ch)
		return ch
	}

	bidirectionalCh := make(chan any, 10)
	ch := &channel{ch: bidirectionalCh, pred: predicate}
	demux.channels = append(demux.channels, ch)
	demux.mutex.Unlock()
	return bidirectionalCh
}

// DeMultiplex 将消息转发给对应的信道。
func (demux *ChannelDeMultiplexer) DeMultiplex(msg any) {
	demux.mutex.Lock()
	if demux.closed {
		demux.mutex.Unlock()
		return
	}
	channels := demux.channels
	demux.deMuxInProgress.Add(1)
	demux.mutex.Unlock()

	for _, ch := range channels {
		if ch.pred(msg) {
			select {
			case <-demux.stopCh:
				demux.deMuxInProgress.Done()
				return
			case ch.ch <- msg:
			}
		}
	}
	demux.deMuxInProgress.Done()
}
