package utils

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConcatenateBytes(t *testing.T) {
	first := []byte("first")
	second := []byte("second")
	c := ConcatenateBytes(first, second)
	require.Equal(t, c, []byte("firstsecond"))

	third := []byte(nil)
	c = ConcatenateBytes(second, third, first)
	require.Equal(t, c, []byte("secondfirst"))

	c2 := bytes.Join([][]byte{second, first}, nil)
	require.Equal(t, c, c2)
}
