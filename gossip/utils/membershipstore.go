package utils

import (
	"sync"

	"github.com/11090815/mayy/gossip/protoext"
)

type MembershipStore struct {
	m     map[string]*protoext.SignedGossipMessage // pki-id => SignedGossipMessage
	mutex *sync.RWMutex
}

func NewMembershipStore() *MembershipStore {
	return &MembershipStore{
		m:     make(map[string]*protoext.SignedGossipMessage), // string(PKIidType) => *protoext.SignedGossipMessage
		mutex: &sync.RWMutex{},
	}
}

func (ms *MembershipStore) Put(pkiID PKIidType, sgm *protoext.SignedGossipMessage) {
	ms.mutex.Lock()
	ms.m[string(pkiID)] = sgm
	ms.mutex.Unlock()
}

func (ms *MembershipStore) Remove(pkiID PKIidType) {
	ms.mutex.Lock()
	delete(ms.m, string(pkiID))
	ms.mutex.Unlock()
}

func (ms *MembershipStore) Size() int {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	return len(ms.m)
}

// MsgByID 返回由给定的 PKIidType 对应的 SignedGossipMessage。
func (ms *MembershipStore) MsgByID(pkiID PKIidType) *protoext.SignedGossipMessage {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	if msg, exists := ms.m[string(pkiID)]; exists {
		return msg
	}
	return nil
}

func (ms *MembershipStore) ToSlice() []*protoext.SignedGossipMessage {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	members := make([]*protoext.SignedGossipMessage, len(ms.m))
	i := 0
	for _, member := range ms.m {
		members[i] = member
		i++
	}
	return members
}
