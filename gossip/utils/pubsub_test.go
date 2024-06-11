package utils

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPubSub(t *testing.T) {
	ps := NewPubSub()
	sub1 := ps.Subscribe("xxx_1", time.Second)
	sub2 := ps.Subscribe("xxx_2", time.Second)

	go func() {
		err := ps.Publish("xxx_1", 5)
		require.NoError(t, err)
	}()

	item, err := sub1.Listen()
	require.NoError(t, err)
	require.Equal(t, 5, item)

	err = ps.Publish("xxx_3", 6)
	require.ErrorContains(t, err, "no subscribers have subscribed the topic \"xxx_3\"")

	go func() {
		time.Sleep(time.Second * 2)
		ps.Publish("xxx_2", 7)
	}()
	item, err = sub2.Listen()
	require.ErrorContains(t, err, "timed out")
	require.Nil(t, item)

	subscriptions := []Subscription{}
	n := 100
	for i := 0; i < n; i++ {
		subscriptions = append(subscriptions, ps.Subscribe("xxx_3", time.Second))
	}
	go func() {
		for i := 0; i <= subscriptionBuffSize; i++ {
			err := ps.Publish("xxx_3", 100+i)
			require.NoError(t, err)
		}
	}()
	wg := sync.WaitGroup{}
	wg.Add(n)
	for _, s := range subscriptions {
		go func(s Subscription) {
			time.Sleep(time.Millisecond * 200) // 等待 200ms，让 150 因为通道满了而溢出
			defer wg.Done()
			for i := 0; i < subscriptionBuffSize; i++ {
				item, err := s.Listen()
				require.NoError(t, err)
				require.Equal(t, 100+i, item)
			}
			item, err := s.Listen()
			require.Nil(t, item)
			require.Error(t, err)
		}(s)
	}
	wg.Wait()

	for i := 0; i < 10; i++ {
		time.Sleep(time.Second)
		ps.mutex.Lock()
		empty := len(ps.subscriptions) == 0
		ps.mutex.Unlock()
		if empty {
			break
		}
	}
	require.Empty(t, ps.subscriptions)
}
