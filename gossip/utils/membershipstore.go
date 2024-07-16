package utils

import (
	"sync"
)

// MembershipStore 存储的数据结构：pkiID => *SignedGossipMessage。
type MembershipStore struct {
	m     map[string]*SignedGossipMessage // pki-id => SignedGossipMessage
	mutex *sync.RWMutex
}

func NewMembershipStore() *MembershipStore {
	return &MembershipStore{
		m:     make(map[string]*SignedGossipMessage), // string(PKIidType) => *SignedGossipMessage
		mutex: &sync.RWMutex{},
	}
}

func (ms *MembershipStore) Put(pkiID PKIidType, sgm *SignedGossipMessage) {
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
func (ms *MembershipStore) MsgByID(pkiID PKIidType) *SignedGossipMessage {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	if msg, exists := ms.m[string(pkiID)]; exists {
		return msg
	}
	return nil
}

func (ms *MembershipStore) ToSlice() []*SignedGossipMessage {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	members := make([]*SignedGossipMessage, len(ms.m))
	i := 0
	for _, member := range ms.m {
		members[i] = member
		i++
	}
	return members
}
