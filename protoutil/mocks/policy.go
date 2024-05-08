package mocks

import (
	"sync"

	"github.com/11090815/mayy/protoutil"
)

type Policy struct {
	EvaluateSignedDataStub          func([]*protoutil.SignedData) error
	evaluateSignedDataMutex         sync.RWMutex
	evaluateSignedDataArgsForCall   []struct{ arg1 []*protoutil.SignedData }
	evaluateSignedDataReturns       struct{ result1 error }
	evaluateSignedDataReturnsOnCall map[int]struct{ result1 error }
	invocations                     map[string][][]interface{}
	invocationsMutex                sync.RWMutex
}

func (p *Policy) EvaluateSignedData(arg1 []*protoutil.SignedData) error {
	p.evaluateSignedDataMutex.Lock()
	ret, specificReturn := p.evaluateSignedDataReturnsOnCall[len(p.evaluateSignedDataArgsForCall)]
	p.evaluateSignedDataArgsForCall = append(p.evaluateSignedDataArgsForCall, struct{ arg1 []*protoutil.SignedData }{arg1: arg1})
	stub := p.EvaluateSignedDataStub
	fakeRetuns := p.evaluateSignedDataReturns
	p.recordInvocations("EvaluateSignedData", []interface{}{arg1})
	p.evaluateSignedDataMutex.Unlock()
	if stub != nil {
		return stub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	return fakeRetuns.result1
}

func (p *Policy) EvaluateSignedDataArgsForCall(i int) []*protoutil.SignedData {
	p.evaluateSignedDataMutex.RLock()
	defer p.evaluateSignedDataMutex.RUnlock()
	return p.evaluateSignedDataArgsForCall[i].arg1
}

func (p *Policy) recordInvocations(method string, args []interface{}) {
	p.invocationsMutex.Lock()
	defer p.invocationsMutex.Unlock()
	if p.invocations == nil {
		p.invocations = make(map[string][][]interface{})
	}
	p.invocations[method] = append(p.invocations[method], args)
}
