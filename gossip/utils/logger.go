package utils

import (
	"sync"

	"github.com/11090815/mayy/common/mlog"
)

const (
	CommLogger      = "gossip.comm"
	DiscoveryLogger = "gossip.discovery"
	ElectionLogger  = "gossip.election"
	PullLogger      = "gossip.pull"
)

var (
	loggers = make(map[string]mlog.Logger)
	mutex   = &sync.Mutex{}
)

func GetLogger(name string, peerID string, level mlog.Level, test bool, printPath bool) mlog.Logger {
	if peerID != "" && test {
		name = name + "@" + peerID
	}

	mutex.Lock()
	defer mutex.Unlock()

	if l, ok := loggers[name]; ok {
		return l
	}

	var l mlog.Logger
	if test {
		l = mlog.GetTestLogger(name, level, true)
	} else {
		l = mlog.GetLogger(name, level, printPath)
	}

	loggers[name] = l

	return l
}
