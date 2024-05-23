package aes

import (
	"crypto/sha256"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/csp/softimpl/utils"
	"github.com/11090815/mayy/errors"
)

type AESKey struct {
	key        []byte
	exportable bool
}

func NewAESKey(key []byte) csp.Key {
	return &AESKey{key: key}
}

func AESKeyToPEM(key *AESKey) []byte {
	return utils.AESToPEM(key.key)
}

// Bytes 返回 AES 密钥自身。
func (key *AESKey) Bytes() ([]byte, error) {
	if key.exportable {
		return key.key, nil
	}

	return nil, errors.NewError("this AES key cannot be exported")
}

func (key *AESKey) SKI() []byte {
	hashFunc := sha256.New()
	hashFunc.Write(key.key)
	return hashFunc.Sum(nil)
}

func (key *AESKey) Symmetric() bool {
	return true
}

func (key *AESKey) Private() bool {
	return true
}

func (key *AESKey) PublicKey() (csp.Key, error) {
	return nil, errors.NewError("AES doesn't have public key")
}
