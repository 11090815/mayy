package mocks

import (
	"context"

	"github.com/11090815/mayy/protobuf/pgossip"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/metadata"
)

type MockStream struct {
	mock.Mock
}

func (m *MockStream) CloseSend() error {
	ret := m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		return rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

func (m *MockStream) Context() context.Context {
	ret := m.Called()

	var r0 context.Context
	if rf, ok := ret.Get(0).(func() context.Context); ok {
		return rf()
	} else {
		r0 = ret.Get(0).(context.Context)
	}
	return r0
}

func (m *MockStream) Header() (metadata.MD, error) {
	ret := m.Called()

	var r0 metadata.MD
	var r1 error

	if rf, ok := ret.Get(0).(func() metadata.MD); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(metadata.MD)
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

func (m *MockStream) Recv() (*pgossip.Envelope, error) {
	ret := m.Called()

	var r0 *pgossip.Envelope
	var r1 error

	if rf, ok := ret.Get(0).(func() *pgossip.Envelope); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(*pgossip.Envelope)
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

func (m *MockStream) RecvMsg(msg any) error {
	ret := m.Called(msg)

	var r0 error
	if rf, ok := ret.Get(0).(func(any) error); ok {
		r0 = rf(msg)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

func (m *MockStream) Send(msg *pgossip.Envelope) error {
	ret := m.Called(msg)

	var r0 error
	if rf, ok := ret.Get(0).(func(*pgossip.Envelope) error); ok {
		r0 = rf(msg)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

func (m *MockStream) SendMsg(msg any) error {
	ret := m.Called(msg)

	var r0 error
	if rf, ok := ret.Get(0).(func(any) error); ok {
		r0 = rf(msg)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

func (m *MockStream) Trailer() metadata.MD {
	ret := m.Called()

	var r0 metadata.MD
	if rf, ok := ret.Get(0).(func() metadata.MD); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(metadata.MD)
	}

	return r0
}
