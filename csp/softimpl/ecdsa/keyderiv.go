package ecdsa

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

type ECDSAPublicKeyDeriver struct{}

func NewECDSAPublicKeyDeriver() *ECDSAPublicKeyDeriver {
	return &ECDSAPublicKeyDeriver{}
}

// KeyDeriv 此方法的第二个参数必须是 *ECDSAReRandKeyOpts 实例。
func (kd *ECDSAPublicKeyDeriver) KeyDeriv(key csp.Key, opts csp.KeyDerivOpts) (csp.Key, error) {
	if opts == nil {
		return nil, errors.NewError("invalid opts, it must be non-nil")
	}

	pk := key.(*ECDSAPublicKey)

	ecdsaReRandOpts, ok := opts.(*ECDSAReRandKeyOpts)
	if !ok {
		return nil, errors.NewErrorf("only support *ECDSAReRandKeyOpts, but got \"%T\"", opts)
	}

	tempPK := &ecdsa.PublicKey{
		Curve: pk.publicKey.Curve,
		X:     pk.publicKey.X,
		Y:     pk.publicKey.Y,
	}

	// 1. 确定随机值 r
	r := new(big.Int).SetBytes(ecdsaReRandOpts.Expansion)

	// 2. 椭圆曲线的阶减去1：n = order - 1
	one := big.NewInt(1)
	n := new(big.Int).Sub(pk.publicKey.Params().N, one)

	// 3. r = r mod n
	// r = r + 1
	r.Mod(r, n)
	r.Add(r, one)

	tempX, tempY := pk.publicKey.ScalarBaseMult(r.Bytes())
	tempPK.X, tempPK.Y = tempPK.Add(pk.publicKey.X, pk.publicKey.Y, tempX, tempY)

	isOn := tempPK.Curve.IsOnCurve(tempPK.X, tempPK.Y)
	if !isOn {
		return nil, errors.NewError("failed get a new rand public key, because it is not on the curve")
	}

	return &ECDSAPublicKey{publicKey: tempPK}, nil
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAPrivateKeyDeriver struct{}

func NewECDSAPrivateKeyDeriver() *ECDSAPrivateKeyDeriver {
	return &ECDSAPrivateKeyDeriver{}
}

// KeyDeriv 此方法的第二个参数必须是 *ECDSAReRandKeyOpts 实例。
func (kd *ECDSAPrivateKeyDeriver) KeyDeriv(key csp.Key, opts csp.KeyDerivOpts) (csp.Key, error) {
	if opts == nil {
		return nil, errors.NewError("invalid opts, it must be non-nil")
	}

	sk := key.(*ECDSAPrivateKey)

	ecdsaReRandOpts, ok := opts.(*ECDSAReRandKeyOpts)
	if !ok {
		return nil, errors.NewErrorf("only support *ECDSAReRandKeyOpts, but got \"%T\"", opts)
	}

	tempSK := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: sk.privateKey.Curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: new(big.Int),
	}

	// 1. 确定随机值 r
	r := new(big.Int).SetBytes(ecdsaReRandOpts.Expansion)

	// 2. 椭圆曲线的阶减去1：n = order - 1
	one := big.NewInt(1)
	n := new(big.Int).Sub(sk.privateKey.Params().N, one)

	// 3. r = r mod n
	// r = r + 1
	r.Mod(r, n)
	r.Add(r, one)

	tempSK.D.Add(sk.privateKey.D, r)
	tempSK.D.Mod(tempSK.D, sk.privateKey.Params().N)

	tempX, tempY := sk.privateKey.PublicKey.ScalarBaseMult(r.Bytes())
	tempSK.PublicKey.X, tempSK.PublicKey.Y = tempSK.PublicKey.Add(sk.privateKey.PublicKey.X, sk.privateKey.PublicKey.Y, tempX, tempY)

	isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
	if !isOn {
		return nil, errors.NewError("failed get a new rand private/public key, because it is not on the curve")
	}

	return &ECDSAPrivateKey{privateKey: tempSK}, nil
}
