package mocks

import (
	"bytes"
	"encoding/hex"
	"errors"
	"hash"
	"reflect"

	"github.com/11090815/mayy/csp"
)

type MockCSP struct {
	SignArgKey    csp.Key
	SignDigestArg []byte
	SignOptsArg   csp.SignerOpts

	SignValue []byte
	SignErr   error

	VerifyValue bool
	VerifyErr   error

	ExpectedSig []byte

	KeyImportValue csp.Key
	KeyImportErr   error

	EncryptErr error
	DecryptErr error

	HashValue []byte
	HashErr   error
}

func (*MockCSP) KeyGen(csp.KeyGenOpts) (csp.Key, error) {
	panic("Not yet implemented")
}

func (*MockCSP) KeyDeriv(csp.KeyDerivOpts) (csp.Key, error) {
	panic("Not yet implemented")
}

func (m *MockCSP) KeyImport(raw interface{}, opts csp.KeyImportOpts) (csp.Key, error) {
	return m.KeyImportValue, m.KeyImportErr
}

func (*MockCSP) GetKey(ski []byte) (csp.Key, error) {
	panic("Not yet implemented")
}

func (m *MockCSP) Hash(msg []byte, opts csp.HashOpts) ([]byte, error) {
	return m.HashValue, m.HashErr
}

func (*MockCSP) GetHash(opts csp.HashOpts) (hash.Hash, error) {
	panic("Not yet implemented")
}

func (m *MockCSP) Sign(key csp.Key, digest []byte, opts csp.SignerOpts) ([]byte, error) {
	if !reflect.DeepEqual(m.SignArgKey, key) {
		return nil, errors.New("invalid key")
	}
	if !reflect.DeepEqual(m.SignDigestArg, digest) {
		return nil, errors.New("invalid digest")
	}
	if !reflect.DeepEqual(m.SignOptsArg, opts) {
		return nil, errors.New("invalid opts")
	}

	return m.SignValue, m.SignErr
}

func (m *MockCSP) Verify(key csp.Key, signature, digest []byte, opts csp.SignerOpts) (bool, error) {
	if m.VerifyValue {
		return m.VerifyValue, nil
	}

	if m.VerifyErr != nil {
		return m.VerifyValue, m.VerifyErr
	}

	return bytes.Equal(m.ExpectedSig, signature), nil
}

func (m *MockCSP) Encrypt(key csp.Key, plaintext []byte, opts csp.EncrypterOpts) ([]byte, error) {
	if m.EncryptErr == nil {
		return plaintext, nil
	} else {
		return nil, m.EncryptErr
	}
}

func (m *MockCSP) Decrypt(key csp.Key, ciphertext []byte, opts csp.DecrypterOpts) ([]byte, error) {
	if m.DecryptErr == nil {
		return ciphertext, nil
	} else {
		return nil, m.DecryptErr
	}
}

type MockKeyStore struct {
	storedKey map[string]csp.Key
}

func NewMockKeyStore() csp.KeyStore {
	return &MockKeyStore{storedKey: make(map[string]csp.Key)}
}

func (m *MockKeyStore) ReadOnly() bool {
	return false
}

func (m *MockKeyStore) GetKey(ski []byte) (csp.Key, error) {
	return m.storedKey[hex.EncodeToString(ski)], nil
}

func (m *MockKeyStore) StoreKey(key csp.Key) error {
	m.storedKey[hex.EncodeToString(key.SKI())] = key
	return nil
}

func (m *MockKeyStore) Num() int {
	return len(m.storedKey)
}
