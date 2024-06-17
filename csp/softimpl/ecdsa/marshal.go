/*
	此文件中定义的代码是为了解决 ECDSA 面临的签名伪造问题。
	详细问题定义和解释，可查看以下链接：
		https://yondon.blog/2019/01/01/how-not-to-use-ecdsa/
*/

package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"

	"github.com/11090815/mayy/common/errors"
)

/* ------------------------------------------------------------------------------------------ */

var curveHalfOrders = map[elliptic.Curve]*big.Int{
	elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
	elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
	elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
	elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
}

func GetCurveHalfOrderAt(curve elliptic.Curve) *big.Int {
	return new(big.Int).Set(curveHalfOrders[curve])
}

/* ------------------------------------------------------------------------------------------ */

type ECDSASignature struct {
	R, S *big.Int
}

func MarshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ECDSASignature{R: r, S: s})
}

func UnmarshalECDSASignature(raw []byte) (r, s *big.Int, err error) {
	sig := new(ECDSASignature)
	_, err = asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, errors.NewErrorf("failed unmarshaling ecdsa signature, the error is \"%s\"", err.Error())
	}

	if sig.R == nil {
		return nil, nil, errors.NewError("invalid signature, \"r\" must be different from nil")
	}
	if sig.S == nil {
		return nil, nil, errors.NewError("invalid signature, \"s\" must be different from nil")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.NewError("invalid signature, \"r\" must be larger than 0")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.NewError("invalid signature, \"s\" must be larger than 0")
	}

	return sig.R, sig.S, nil
}

func SignatureToLowS(key *ecdsa.PublicKey, signature []byte) ([]byte, error) {
	r, s, err := UnmarshalECDSASignature(signature)
	if err != nil {
		return nil, errors.NewError(err.Error())
	}

	s, err = ToLowS(key, s)
	if err != nil {
		return nil, errors.NewError(err.Error())
	}

	return MarshalECDSASignature(r, s)
}

/* ------------------------------------------------------------------------------------------ */

func IsLowS(key *ecdsa.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[key.Curve]
	if !ok {
		return false, errors.NewErrorf("curve \"%s\" not recognized", key.Curve.Params().Name)
	}
	return s.Cmp(halfOrder) <= 0, nil
}

func ToLowS(key *ecdsa.PublicKey, s *big.Int) (*big.Int, error) {
	lowS, err := IsLowS(key, s)
	if err != nil {
		return nil, err
	}

	if !lowS {
		s.Sub(key.Params().N, s)
		return s, nil
	}

	return s, nil
}
