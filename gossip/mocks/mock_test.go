package mocks

import (
	"testing"

	"github.com/stretchr/testify/mock"
)

func TestMock(t *testing.T) {
	m := mock.Mock{}
	m.On("TestMock", "test").Return("testRet", 1)
	ret := m.Called("test")
	t.Log(ret...)
}
