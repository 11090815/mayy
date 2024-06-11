package utils

import (
	"sync"
	"time"

	"github.com/11090815/mayy/errors"
)

const (
	subscriptionBuffSize = 50
)

/* ------------------------------------------------------------------------------------------ */

type Subscription interface {
	Listen() (any, error)
}

type subscription struct {
	topic string
	ttl   time.Duration
	c     chan any
}

func (s *subscription) Listen() (any, error) {
	select {
	case <-time.After(s.ttl):
		return nil, errors.NewError("timed out")
	case item := <-s.c:
		return item, nil
	}
}

/* ------------------------------------------------------------------------------------------ */

type PubSub struct {
	mutex         *sync.RWMutex
	subscriptions map[string]*Set
}

func NewPubSub() *PubSub {
	return &PubSub{
		subscriptions: make(map[string]*Set),
		mutex:         &sync.RWMutex{},
	}
}

func (ps *PubSub) Publish(topic string, item any) error {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()
	s, subscribed := ps.subscriptions[topic]
	if !subscribed {
		return errors.NewErrorf("no subscribers have subscribed the topic \"%s\"", topic)
	}

	for _, sub := range s.ToArray() {
		c := sub.(*subscription).c
		select {
		case c <- item:
		default: // 非阻塞
		}
	}
	return nil
}

func (ps *PubSub) Subscribe(topic string, ttl time.Duration) Subscription {
	sub := &subscription{
		topic: topic,
		ttl:   ttl,
		c:     make(chan any, subscriptionBuffSize),
	}

	ps.mutex.Lock()
	s, subscribed := ps.subscriptions[topic]
	if !subscribed {
		s = NewSet()
		ps.subscriptions[topic] = s
	}
	ps.mutex.Unlock()

	s.Add(sub)
	time.AfterFunc(ttl, func() {
		ps.mutex.Lock()
		defer ps.mutex.Unlock()
		ps.subscriptions[topic].Remove(sub)
		if ps.subscriptions[topic].Size() != 0 {
			return
		}
		delete(ps.subscriptions, topic)
	})

	return sub
}
