package mocks

import (
	"github.com/11090815/mayy/gossip/utils"
	"github.com/stretchr/testify/mock"
)

type SecurityAdvisor struct {
	mock.Mock
}

func (sa *SecurityAdvisor) OrgByPeerIdentity(identity utils.PeerIdentityType) utils.OrgIdentityType {
	ret := sa.Called(identity)

	var r0 utils.OrgIdentityType
	if rf, ok := ret.Get(0).(func(utils.PeerIdentityType) utils.OrgIdentityType); ok {
		r0 = rf(identity)
	} else {
		r0 = ret.Get(0).(utils.OrgIdentityType)
	}

	return r0
}
