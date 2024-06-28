package discovery

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type Once struct {
	done int32
}

func (o *Once) Do() {
	atomic.StoreInt32(&o.done, 1)
}

type testComm struct {
	once Once
}

func (c *testComm) close() {
	c.once.Do()
}

func TestOnceDo(t *testing.T) {
	comm := &testComm{}
	require.Equal(t, int32(0), comm.once.done)
	comm.close()
	require.Equal(t, int32(1), comm.once.done)

	if comm.once.done == 1 {
		t.Log("测试成功")
	}
}
