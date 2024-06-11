package utils

import (
	"bytes"
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/errors"
)

var usageThreshold = time.Hour

type IdentityMapper interface {
	Put(id PKIidType, identity PeerIdentityType) error

	Get(id PKIidType) (PeerIdentityType, error)

	Sign(msg []byte) ([]byte, error)

	Verify(id, signature, message []byte) error

	GetPKIidOfCert(PeerIdentityType) PKIidType

	// SuspectPeers 检测 peer 的身份证书或者其上的 CA 证书是否被撤销。
	SuspectPeers(isSuspected PeerSuspector)

	// IdentityInfo 返回本地存储的所有 peer 节点的信息。
	IdentityInfo() PeerIdentitySet

	Stop()
}

func GetIdentityUsageThreshold() time.Duration {
	return time.Duration(atomic.LoadInt64((*int64)(&usageThreshold)))
}

func SetIdentityUsageThreshold(threshold time.Duration) {
	atomic.StoreInt64((*int64)(&usageThreshold), int64(threshold))
}

/* ------------------------------------------------------------------------------------------ */

type purgeTrigger func(id PKIidType, identity PeerIdentityType)

type identityMapperImpl struct {
	onPurge    purgeTrigger
	advisor    SecurityAdvisor
	mcs        MessageCryptoService
	pkiID2Cert map[string]*storedIdentity
	mutex      *sync.RWMutex
	stopCh     chan struct{}
	once       sync.Once
	selfPKIID  string
}

func NewIdentityMapper(mcs MessageCryptoService, selfIdentity PeerIdentityType, onPurge purgeTrigger, advisor SecurityAdvisor) IdentityMapper {
	selfPKIID := mcs.GetPKIidOfCert(selfIdentity)
	idMapper := &identityMapperImpl{
		onPurge:    onPurge,
		mcs:        mcs,
		pkiID2Cert: make(map[string]*storedIdentity),
		stopCh:     make(chan struct{}),
		selfPKIID:  selfPKIID.String(),
		advisor:    advisor,
		mutex:      &sync.RWMutex{},
	}
	if err := idMapper.Put(selfPKIID, selfIdentity); err != nil {
		panic(err)
	}

	go idMapper.purgeUnusedIdentitiesRoutine()

	return idMapper
}

func (impl *identityMapperImpl) purgeUnusedIdentitiesRoutine() {
	usageTh := GetIdentityUsageThreshold()
	for {
		select {
		case <-impl.stopCh:
			return
		case <-time.After(usageTh / 10):
			impl.SuspectPeers(func(identity PeerIdentityType) bool {
				return false
			})
		}
	}
}

func (impl *identityMapperImpl) Put(id PKIidType, identity PeerIdentityType) error {
	if len(id) == 0 {
		return errors.NewError("nil peer pki-id")
	}
	if len(identity) == 0 {
		return errors.NewError("nil peer identity")
	}

	expirationTime, err := impl.mcs.Expiration(identity)
	if err != nil {
		return err
	}

	if err = impl.mcs.ValidateIdentity(identity); err != nil {
		return err
	}

	retrivedID := impl.mcs.GetPKIidOfCert(identity)
	if !bytes.Equal(retrivedID, id) {
		return errors.NewError("identity doesn't match the peer pki-id")
	}

	impl.mutex.Lock()
	defer impl.mutex.Unlock()

	if _, exists := impl.pkiID2Cert[id.String()]; exists {
		return nil
	}

	var expirationTimer *time.Timer
	if !expirationTime.IsZero() {
		if time.Now().After(expirationTime) {
			return errors.NewError("the given identity is already expired")
		}
		ttl := time.Until(expirationTime)
		expirationTimer = time.AfterFunc(ttl, func() {
			impl.delete(id, identity)
		})
	}

	impl.pkiID2Cert[id.String()] = newStoredIdentity(id, identity, expirationTimer, impl.advisor.OrgByPeerIdentity(identity))
	return nil
}

func (impl *identityMapperImpl) Get(id PKIidType) (PeerIdentityType, error) {
	impl.mutex.RLock()
	defer impl.mutex.RUnlock()
	storedIdentity, exists := impl.pkiID2Cert[id.String()]
	if !exists {
		return nil, errors.NewErrorf("pki-id %s is not exists", id.String())
	}
	return storedIdentity.fetchIdentity(), nil
}

func (impl *identityMapperImpl) Sign(msg []byte) ([]byte, error) {
	return impl.mcs.Sign(msg)
}

func (impl *identityMapperImpl) Verify(id, signature, message []byte) error {
	cert, err := impl.Get(id)
	if err != nil {
		return err
	}
	return impl.mcs.Verify(cert, signature, message)
}

func (impl *identityMapperImpl) GetPKIidOfCert(identity PeerIdentityType) PKIidType {
	return impl.mcs.GetPKIidOfCert(identity)
}

// SuspectPeers 检测 peer 的身份证书或者其上的 CA 证书是否被撤销。
func (impl *identityMapperImpl) SuspectPeers(isSuspected PeerSuspector) {
	for _, identity := range impl.validateIdentities(isSuspected) {
		identity.cancelExpirationTimer()
		impl.delete(identity.pkiID, identity.peerIdentity)
	}
}

func (impl *identityMapperImpl) IdentityInfo() PeerIdentitySet {
	var set PeerIdentitySet
	impl.mutex.RLock()
	defer impl.mutex.RUnlock()
	for _, si := range impl.pkiID2Cert {
		set = append(set, PeerIdentityInfo{
			PKIid:        si.pkiID,
			Identity:     si.peerIdentity,
			Organization: si.orgIdentity,
		})
	}
	return set
}

func (impl *identityMapperImpl) Stop() {
	impl.once.Do(func() {
		close(impl.stopCh)
	})
}

func (impl *identityMapperImpl) validateIdentities(isSuspected PeerSuspector) []*storedIdentity {
	now := time.Now()
	usageTh := GetIdentityUsageThreshold()
	impl.mutex.RLock()
	defer impl.mutex.RUnlock()
	var revokedIdentities []*storedIdentity

	for id, si := range impl.pkiID2Cert {
		if id != impl.selfPKIID && si.fetchLastAccessTime().Add(usageTh).Before(now) {
			revokedIdentities = append(revokedIdentities, si)
			continue
		}
		if !isSuspected(si.peerIdentity) {
			// 没有嫌疑，所以跳过
			continue
		}
		if err := impl.mcs.ValidateIdentity(si.fetchIdentity()); err != nil {
			revokedIdentities = append(revokedIdentities, si)
		}
	}
	return revokedIdentities
}

func (impl *identityMapperImpl) delete(id PKIidType, identity PeerIdentityType) {
	impl.mutex.Lock()
	impl.onPurge(id, identity)
	delete(impl.pkiID2Cert, id.String())
	impl.mutex.Unlock()
}

/* ------------------------------------------------------------------------------------------ */

type storedIdentity struct {
	pkiID           PKIidType
	lastAccessTime  int64
	peerIdentity    PeerIdentityType
	orgIdentity     OrgIdentityType
	expirationTimer *time.Timer
}

func newStoredIdentity(id PKIidType, identity PeerIdentityType, expirationTimer *time.Timer, org OrgIdentityType) *storedIdentity {
	return &storedIdentity{
		pkiID:           id,
		lastAccessTime:  time.Now().UnixNano(),
		peerIdentity:    identity,
		orgIdentity:     org,
		expirationTimer: expirationTimer,
	}
}

func (si *storedIdentity) fetchIdentity() PeerIdentityType {
	atomic.StoreInt64(&si.lastAccessTime, time.Now().UnixNano())
	return si.peerIdentity
}

func (si *storedIdentity) fetchLastAccessTime() time.Time {
	return time.Unix(0, atomic.LoadInt64(&si.lastAccessTime))
}

func (si *storedIdentity) cancelExpirationTimer() {
	if si.expirationTimer == nil {
		return
	}
	si.expirationTimer.Stop()
}
