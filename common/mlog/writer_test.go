package mlog

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func createRandomEntry() *entry {
	r := rand.Intn(5)
	return newEntry(now(), "consensus", Level(r+1), "Successfully reach consensus among the whole network", "ip=192.168.1.1", true)
}

func TestFileWriter(t *testing.T) {
	mfw, err := NewMultiFileWriter()
	require.NoError(t, err)
	for i := 0; i < 1000; i++ {
		mfw.writeEntry(createRandomEntry())
	}
	err = mfw.close()
	require.NoError(t, err)
}

func TestNilWriter(t *testing.T) {
	l1 := GetLogger("111", DebugLevel, true)
	l2 := GetLogger("222", DebugLevel, true)
	// l3 := GetLogger("333", DebugLevel, true)

	l1.(*logger).file.(*multiFileWriter).writers[DebugLevel.String()] = nil
	require.Nil(t, l2.(*logger).file.(*multiFileWriter).writers[DebugLevel.String()])
}
