package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

type ECDSAKeyGenerator struct {
	curve elliptic.Curve
}

func NewECDSAKeyGenerator(curve elliptic.Curve) *ECDSAKeyGenerator {
	return &ECDSAKeyGenerator{curve: curve}
}

// KeyGen 方法不需要传入 KeyGenOpts 参数。
func (kg *ECDSAKeyGenerator) KeyGen(opts csp.KeyGenOpts) (csp.Key, error) {
	privateKey, err := ecdsa.GenerateKey(kg.curve, rand.Reader)
	if err != nil {
		return nil, errors.NewErrorf("failed generating ECDSA key, the error is \"%s\"", err.Error())
	}

	return &ECDSAPrivateKey{privateKey: privateKey}, nil
}
