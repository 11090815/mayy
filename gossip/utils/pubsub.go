package utils

import "sync"

const (
	subscriptionBuffSize = 50
)

type PubSub struct {
	mutex         sync.RWMutex
	subscriptions map[string]*Set
}
