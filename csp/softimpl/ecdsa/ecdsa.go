package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/common/errors"
)

/* ------------------------------------------------------------------------------------------ */

type ECDSASigner struct{}

func NewECDSASigner() *ECDSASigner {
	return &ECDSASigner{}
}

// Sign 此方法传入的第一个参数必须是 *ECDSAPrivateKey，第三个参数 SignerOpts 可以是 nil。
func (signer *ECDSASigner) Sign(key csp.Key, digest []byte, opts csp.SignerOpts) ([]byte, error) {
	return sign(key.(*ECDSAPrivateKey).privateKey, digest)
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAPrivateKeyVerifier struct{}

func NewECDSAPrivateKeyVerifier() *ECDSAPrivateKeyVerifier {
	return &ECDSAPrivateKeyVerifier{}
}

// Verify 此方法传入的第一个参数必须是 *ECDSAPrivateKey，第四个参数 SignerOpts 可以是 nil。
func (verifier *ECDSAPrivateKeyVerifier) Verify(key csp.Key, signature, digest []byte, opts csp.SignerOpts) (bool, error) {
	return verify(&key.(*ECDSAPrivateKey).privateKey.PublicKey, signature, digest)
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAPublicKeyVerifier struct{}

func NewECDSAPublicKeyVerifier() *ECDSAPublicKeyVerifier {
	return &ECDSAPublicKeyVerifier{}
}

// Verify 此方法传入的第一个参数必须是 *ECDSAPublicKey，第四个参数 SignerOpts 可以是 nil。
func (verifier *ECDSAPublicKeyVerifier) Verify(key csp.Key, signature, digest []byte, opts csp.SignerOpts) (bool, error) {
	return verify(key.(*ECDSAPublicKey).publicKey, signature, digest)
}

/* ------------------------------------------------------------------------------------------ */

func sign(key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}

	s, err = ToLowS(&key.PublicKey, s)
	if err != nil {
		return nil, errors.NewError(err.Error())
	}

	return MarshalECDSASignature(r, s)
}

func verify(key *ecdsa.PublicKey, signature, digest []byte) (bool, error) {
	r, s, err := UnmarshalECDSASignature(signature)
	if err != nil {
		return false, errors.NewError(err.Error())
	}

	lowS, err := IsLowS(key, s)
	if err != nil {
		return false, errors.NewError(err.Error())
	}
	if !lowS {
		return false, errors.NewError("signature is invalid, because \"s\" is not smaller than the half order of the curve")
	}

	return ecdsa.Verify(key, digest, r, s), nil
}
