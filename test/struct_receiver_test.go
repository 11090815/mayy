package test_test

import (
	"testing"
	"github.com/stretchr/testify/require"
)

type testStruct struct {
	val int
}

func (p *testStruct) modify1(val int) {
	p.val = val
}

func (p testStruct) modify2(val int) {
	p.val = val
}

func TestStructPointerReceiver(t *testing.T) {
	test1 := &testStruct{val:100}
	test1.modify2(50)
	require.Equal(t, test1.val, 100)

	test1.modify1(200)
	require.Equal(t, test1.val, 200)

	test2 := testStruct{val: 1000}
	test2.modify2(500)
	require.Equal(t, test2.val, 1000)

	test2.modify1(500)
	require.Equal(t, test2.val, 500)
}
