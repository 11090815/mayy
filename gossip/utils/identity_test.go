package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTimer(t *testing.T) {
	ch := make(chan struct{})
	timer := time.AfterFunc(time.Second * 3, func() {
		close(ch)
		t.Log("hello")
	})
	<-ch
	ok := timer.Stop()
	require.False(t, ok)
}
