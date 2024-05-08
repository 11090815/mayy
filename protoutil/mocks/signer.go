package mocks

import (
	"sync"
)

type Signer struct {
	SerializeStub        func() ([]byte, error)
	serializeMutex       sync.RWMutex
	serializeArgsForCall []struct{}

	// serializeReturns 可以让外界直接设置 Serialize 方法的返回值。
	serializeReturns struct {
		result1 []byte
		result2 error
	}
	serializeReturnsOnCall map[int]struct {
		result1 []byte
		result2 error
	}
	SignStub        func([]byte) ([]byte, error)
	signMutex       sync.RWMutex
	signArgsForCall []struct {
		arg1 []byte
	}
	signReturns struct {
		result1 []byte
		result2 error
	}
	signReturnsOnCall map[int]struct {
		result1 []byte
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (signer *Signer) recordInvocations(method string, args []interface{}) {
	signer.invocationsMutex.Lock()
	defer signer.invocationsMutex.Unlock()
	if signer.invocations == nil {
		signer.invocations = make(map[string][][]interface{})
	}
	if signer.invocations[method] == nil {
		signer.invocations[method] = make([][]interface{}, 0)
	}
	signer.invocations[method] = append(signer.invocations[method], args)
}

func (signer *Signer) Serialize() ([]byte, error) {
	signer.serializeMutex.Lock()
	defer signer.serializeMutex.Unlock()

	// 获取上一次调用此方法返回的结果
	last, exists := signer.serializeReturnsOnCall[len(signer.serializeArgsForCall)]
	signer.serializeArgsForCall = append(signer.serializeArgsForCall, struct{}{})
	signer.recordInvocations("Serialize", []interface{}{})
	if signer.SerializeStub != nil {
		return signer.SerializeStub()
	}
	if exists {
		return last.result1, last.result2
	}

	return signer.serializeReturns.result1, signer.serializeReturns.result2
}

func (signer *Signer) SetSerializeReturns(result1 []byte, result2 error) {
	signer.serializeMutex.Lock()
	defer signer.serializeMutex.Unlock()
	signer.SerializeStub = nil
	signer.serializeReturns = struct {
		result1 []byte
		result2 error
	}{
		result1: result1,
		result2: result2,
	}
}

func (signer *Signer) SetSerializeReturnsOnCall(i int, result1 []byte, result2 error) {
	signer.serializeMutex.Lock()
	defer signer.serializeMutex.Unlock()
	if signer.serializeReturnsOnCall == nil {
		signer.serializeReturnsOnCall = make(map[int]struct {
			result1 []byte
			result2 error
		})
	}
	signer.serializeReturnsOnCall[i] = struct {
		result1 []byte
		result2 error
	}{
		result1: result1,
		result2: result2,
	}
}

func (signer *Signer) SerializeCallCount() int {
	signer.serializeMutex.RLock()
	defer signer.serializeMutex.RUnlock()
	return len(signer.serializeArgsForCall)
}

func (signer *Signer) SetSerializeStub(stub func() ([]byte, error)) {
	signer.serializeMutex.Lock()
	defer signer.serializeMutex.Unlock()
	signer.SerializeStub = stub
}

func (signer *Signer) Sign(arg []byte) ([]byte, error) {
	signer.signMutex.Lock()
	defer signer.signMutex.Unlock()

	// 获取上一次调用此方法返回的结果
	last, exists := signer.signReturnsOnCall[len(signer.signArgsForCall)]
	signer.signArgsForCall = append(signer.signArgsForCall, struct{ arg1 []byte }{arg1: arg})
	signer.recordInvocations("Sign", []interface{}{arg})
	if signer.SignStub != nil {
		return signer.SignStub(arg)
	}
	if exists {
		return last.result1, last.result2
	}

	return signer.signReturns.result1, signer.signReturns.result2
}

func (signer *Signer) SetSignReturns(result1 []byte, result2 error) {
	signer.signMutex.Lock()
	defer signer.signMutex.Unlock()
	signer.SignStub = nil
	signer.signReturns = struct {
		result1 []byte
		result2 error
	}{
		result1: result1,
		result2: result2,
	}
}

func (signer *Signer) SetSignReturnsOnCall(i int, result1 []byte, result2 error) {
	signer.signMutex.Lock()
	defer signer.signMutex.Unlock()
	if signer.signReturnsOnCall == nil {
		signer.signReturnsOnCall = make(map[int]struct {
			result1 []byte
			result2 error
		})
	}
	signer.signReturnsOnCall[i] = struct {
		result1 []byte
		result2 error
	}{
		result1: result1,
		result2: result2,
	}
}

func (signer *Signer) SignCallCount() int {
	signer.signMutex.RLock()
	defer signer.signMutex.RUnlock()
	return len(signer.signArgsForCall)
}

func (signer *Signer) SetSignStub(stub func(arg []byte) ([]byte, error)) {
	signer.signMutex.Lock()
	defer signer.signMutex.Unlock()
	signer.SignStub = stub
}
