package algo

import (
	"time"

	"github.com/11090815/mayy/gossip/utils"
)

const (
	DefaultDigestWaitTime   = 1000 * time.Millisecond
	DefaultRequestWaitTime  = 1500 * time.Millisecond
	DefaultResponseWaitTime = 2000 * time.Millisecond
)

type DigestFilter func(context any) func(digestItem string) bool

type PullAdapter interface {
	SelectPeers() []string

	Hello(dest string, nonce uint64)

	SendDigest(digest []string, nonce uint64, context any)

	SendReq(dest string, items []string, nonce uint64)

	SendRes(items []string, nonce uint64, context any)
}

type pullEngine struct {
	stopFlag    int32
	state       *utils.Set
	item2owners map[string][]string
}
