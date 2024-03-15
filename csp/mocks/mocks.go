package mocks

import (
	"bytes"
	"encoding/hex"
	"errors"
	"hash"
	"reflect"

	"github.com/11090815/mayy/csp/interfaces"
)

type MockCSP struct {
	SignArgKey    interfaces.Key
	SignDigestArg []byte
	SignOptsArg   interfaces.SignerOpts

	SignValue []byte
	SignErr   error

	VerifyValue bool
	VerifyErr   error

	ExpectedSig []byte

	KeyImportValue interfaces.Key
	KeyImportErr   error

	EncryptErr error
	DecryptErr error

	HashValue []byte
	HashErr   error
}

func (*MockCSP) KeyGen(interfaces.KeyGenOpts) (interfaces.Key, error) {
	panic("Not yet implemented")
}

func (*MockCSP) KeyDeriv(interfaces.KeyDerivOpts) (interfaces.Key, error) {
	panic("Not yet implemented")
}

func (m *MockCSP) KeyImport(raw interface{}, opts interfaces.KeyImportOpts) (interfaces.Key, error) {
	return m.KeyImportValue, m.KeyImportErr
}

func (*MockCSP) GetKey(ski []byte) (interfaces.Key, error) {
	panic("Not yet implemented")
}

func (m *MockCSP) Hash(msg []byte, opts interfaces.HashOpts) ([]byte, error) {
	return m.HashValue, m.HashErr
}

func (*MockCSP) GetHash(opts interfaces.HashOpts) (hash.Hash, error) {
	panic("Not yet implemented")
}

func (m *MockCSP) Sign(key interfaces.Key, digest []byte, opts interfaces.SignerOpts) ([]byte, error) {
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

func (m *MockCSP) Verify(key interfaces.Key, signature, digest []byte, opts interfaces.SignerOpts) (bool, error) {
	if m.VerifyValue {
		return m.VerifyValue, nil
	}

	if m.VerifyErr != nil {
		return m.VerifyValue, m.VerifyErr
	}

	return bytes.Equal(m.ExpectedSig, signature), nil
}

func (m *MockCSP) Encrypt(key interfaces.Key, plaintext []byte, opts interfaces.EncrypterOpts) ([]byte, error) {
	if m.EncryptErr == nil {
		return plaintext, nil
	} else {
		return nil, m.EncryptErr
	}
}

func (m *MockCSP) Decrypt(key interfaces.Key, ciphertext []byte, opts interfaces.DecrypterOpts) ([]byte, error) {
	if m.DecryptErr == nil {
		return ciphertext, nil
	} else {
		return nil, m.DecryptErr
	}
}

type MockKeyStore struct {
	storedKey map[string]interfaces.Key
}

func NewMockKeyStore() interfaces.KeyStore {
	return &MockKeyStore{storedKey: make(map[string]interfaces.Key)}
}

func (m *MockKeyStore) ReadOnly() bool {
	return false
}

func (m *MockKeyStore) GetKey(ski []byte) (interfaces.Key, error) {
	return m.storedKey[hex.EncodeToString(ski)], nil
}

func (m *MockKeyStore) StoreKey(key interfaces.Key) error {
	m.storedKey[hex.EncodeToString(key.SKI())] = key
	return nil
}

func (m *MockKeyStore) Num() int {
	return len(m.storedKey)
}
