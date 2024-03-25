package mlog_test

import (
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/11090815/mayy/common/mlog"
)

func TestLog(t *testing.T) {
	l := mlog.GetLogger("test-module", mlog.DebugLevel, true)
	l.Debug("哈哈哈哈哈哈👌")
	l.Debugf("%s 哈哈哈哈哈哈👌", "7671236")
	l.Info("哈哈哈哈哈哈👌")
	l.Infof("%s 哈哈哈哈哈哈👌", "7671236")
	l.Warn("哈哈哈哈哈哈👌")
	l.Warnf("%s 哈哈哈哈哈哈👌", "7671236")
	l.Error("哈哈哈哈哈哈👌")
	l.Errorf("%s 哈哈哈哈哈哈👌", "7671236")
	l.Panic("哈哈哈哈哈哈👌")
	l.Panicf("%s 哈哈哈哈哈哈👌", "7671236")
	l.Stop()

	otherL := mlog.GetLogger("p2p", mlog.DebugLevel, true)
	otherL.Debug("哈哈哈哈哈哈👌")
	otherL.Debugf("%s 哈哈哈哈哈哈👌", "7671236")
	otherL.Info("哈哈哈哈哈哈👌")
	otherL.Infof("%s 哈哈哈哈哈哈👌", "7671236")
	otherL.Warn("哈哈哈哈哈哈👌")
	otherL.Warnf("%s 哈哈哈哈哈哈👌", "7671236")
	otherL.Error("哈哈哈哈哈哈👌")
	otherL.Errorf("%s 哈哈哈哈哈哈👌", "7671236")
	otherL.Panic("哈哈哈哈哈哈👌")
	otherL.Panicf("%s 哈哈哈哈哈哈👌", "7671236")
	otherL.Stop()
}

func TestAsync(t *testing.T) {
	l1 := mlog.GetLogger("peer1", mlog.DebugLevel, true)
	l2 := mlog.GetLogger("chaincode", mlog.DebugLevel, true)
	l3 := mlog.GetLogger("consenter", mlog.DebugLevel, true)
	l4 := mlog.GetLogger("org", mlog.DebugLevel, true)
	l5 := mlog.GetLogger("orderer", mlog.DebugLevel, true)
	l6 := mlog.GetLogger("peer2", mlog.DebugLevel, true)
	wg := &sync.WaitGroup{}
	wg.Add(6)

	process := func(l mlog.Logger) {
		for i := 0; i < 1000; i++ {
			l.Debug("abcdefghijklmnopqrstuvwxyz1234567890")
			l.Debugf("%s abcdefghijklmnopqrstuvwxyz1234567890", "blockchain")
			l.Info("abcdefghijklmnopqrstuvwxyz1234567890")
			l.Infof("%s abcdefghijklmnopqrstuvwxyz1234567890", "blockchain")
			l.Warn("abcdefghijklmnopqrstuvwxyz1234567890")
			l.Warnf("%s abcdefghijklmnopqrstuvwxyz1234567890", "blockchain")
			l.Error("abcdefghijklmnopqrstuvwxyz1234567890")
			l.Errorf("%s abcdefghijklmnopqrstuvwxyz1234567890", "blockchain")
			l.Panic("abcdefghijklmnopqrstuvwxyz1234567890")
			l.Panicf("%s abcdefghijklmnopqrstuvwxyz1234567890", "blockchain")
			interval := rand.Intn(10)
			time.Sleep(time.Duration(interval) * time.Millisecond)
		}
		wg.Done()
	}

	go process(l1)
	go process(l2)
	go process(l3)
	go process(l4)
	go process(l5)
	go process(l6)

	wg.Wait()
	l1.Stop()
	l2.Stop()
	l3.Stop()
	l4.Stop()
	l5.Stop()
	l6.Stop()
}

func Benchmark(b *testing.B) {
	// 写入文件
	// Benchmark-8         1651           2215214 ns/op            1217 B/op         21 allocs/op

	// 不写入文件
	// Benchmark-8        10000            107012 ns/op             864 B/op         15 allocs/op
	l1 := mlog.GetLogger("peer1", mlog.DebugLevel, true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l1.Debug("abcdefghijklmnopqrstuvwxyz1234567890")
	}
}
