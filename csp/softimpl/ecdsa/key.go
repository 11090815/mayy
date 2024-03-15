package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"

	"github.com/11090815/mayy/csp/interfaces"
	"github.com/11090815/mayy/csp/softimpl/utils"
	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

type ECDSAPrivateKey struct {
	privateKey *ecdsa.PrivateKey
}

func ECDSAPrivateKeyToPEM(key *ECDSAPrivateKey) ([]byte, error) {
	return utils.PrivateKeyToPEM(key.privateKey)
}

func NewECDSAPrivateKey(sk *ecdsa.PrivateKey) interfaces.Key {
	return &ECDSAPrivateKey{privateKey: sk}
}

func (key *ECDSAPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.NewError("the ECDSA private key cannot call this method")
}

func (key *ECDSAPrivateKey) SKI() []byte {
	if key.privateKey == nil {
		return nil
	}

	raw := elliptic.Marshal(key.privateKey.Curve, key.privateKey.PublicKey.X, key.privateKey.PublicKey.Y)

	hashFunc := sha256.New()
	hashFunc.Write(raw)
	return hashFunc.Sum(nil)
}

func (key *ECDSAPrivateKey) Symmetric() bool {
	return false
}

func (key *ECDSAPrivateKey) Private() bool {
	return true
}

func (key *ECDSAPrivateKey) PublicKey() (publicKey interfaces.Key, err error) {
	return &ECDSAPublicKey{publicKey: &key.privateKey.PublicKey}, nil
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAPublicKey struct {
	publicKey *ecdsa.PublicKey
}

func ECDSAPublicKeyToPEM(key *ECDSAPublicKey) ([]byte, error) {
	return utils.PublicKeyToPEM(key.publicKey)
}

func NewECDSAPublicKey(pk *ecdsa.PublicKey) interfaces.Key {
	return &ECDSAPublicKey{publicKey: pk}
}

func (key *ECDSAPublicKey) Bytes() ([]byte, error) {
	raw, err := x509.MarshalPKIXPublicKey(key.publicKey)
	if err != nil {
		return nil, errors.NewErrorf("cannot get bytes of this ECDSA public key, error is \"%s\"", err.Error())
	}

	return raw, nil
}

func (key *ECDSAPublicKey) SKI() []byte {
	if key.publicKey == nil {
		return nil
	}

	raw := elliptic.Marshal(key.publicKey.Curve, key.publicKey.X, key.publicKey.Y)

	hashFunc := sha256.New()
	hashFunc.Write(raw)
	return hashFunc.Sum(nil)
}

func (key *ECDSAPublicKey) Symmetric() bool {
	return false
}

func (key *ECDSAPublicKey) Private() bool {
	return false
}

func (key *ECDSAPublicKey) PublicKey() (publicKey interfaces.Key, err error) {
	return key, nil
}
