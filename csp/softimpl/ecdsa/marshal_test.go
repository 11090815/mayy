package ecdsa_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	myecdsa "github.com/11090815/mayy/csp/softimpl/ecdsa"

	"github.com/stretchr/testify/require"
)

func TestRecognizeCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	_, err = myecdsa.IsLowS(&key.PublicKey, new(big.Int).SetInt64(1))
	t.Log(err)
}

func TestUnmarshalSignature(t *testing.T) {
	// errors.SetTrace()
	_, _, err := myecdsa.UnmarshalECDSASignature(nil)
	fmt.Println(err)

	_, _, err = myecdsa.UnmarshalECDSASignature([]byte{})
	fmt.Println(err)

	_, _, err = myecdsa.UnmarshalECDSASignature([]byte{0})
	fmt.Println(err)

	sig, err := myecdsa.MarshalECDSASignature(big.NewInt(-1), big.NewInt(1))
	require.NoError(t, err)
	_, _, err = myecdsa.UnmarshalECDSASignature(sig)
	require.Error(t, err)
	fmt.Println(err)

	sig, err = myecdsa.MarshalECDSASignature(big.NewInt(1), big.NewInt(-1))
	require.NoError(t, err)
	_, _, err = myecdsa.UnmarshalECDSASignature(sig)
	require.Error(t, err)
	fmt.Println(err)

	sig, err = myecdsa.MarshalECDSASignature(big.NewInt(0), big.NewInt(1))
	require.NoError(t, err)
	_, _, err = myecdsa.UnmarshalECDSASignature(sig)
	require.Error(t, err)
	fmt.Println(err)

	sig, err = myecdsa.MarshalECDSASignature(big.NewInt(1), big.NewInt(0))
	require.NoError(t, err)
	_, _, err = myecdsa.UnmarshalECDSASignature(sig)
	require.Error(t, err)
	fmt.Println(err)

	sig, err = myecdsa.MarshalECDSASignature(big.NewInt(1), big.NewInt(1))
	require.NoError(t, err)
	_, _, err = myecdsa.UnmarshalECDSASignature(sig)
	require.NoError(t, err)
}

func TestIsLowS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	lowS, err := myecdsa.IsLowS(&key.PublicKey, big.NewInt(0))
	require.NoError(t, err)
	require.True(t, lowS)

	s := new(big.Int).Set(myecdsa.GetCurveHalfOrderAt(elliptic.P256()))
	lowS, err = myecdsa.IsLowS(&key.PublicKey, s)
	require.NoError(t, err)
	require.True(t, lowS)

	s.Add(s, big.NewInt(1))
	lowS, err = myecdsa.IsLowS(&key.PublicKey, s)
	require.NoError(t, err)
	require.False(t, lowS)

	s, err = myecdsa.ToLowS(&key.PublicKey, s)
	require.NoError(t, err)
	lowS, err = myecdsa.IsLowS(&key.PublicKey, s)
	require.NoError(t, err)
	require.True(t, lowS)
}

func TestSignatureToLowS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	s := myecdsa.GetCurveHalfOrderAt(elliptic.P256())
	s.Add(s, big.NewInt(1))
	lowS, err := myecdsa.IsLowS(&key.PublicKey, s)
	require.NoError(t, err)
	require.False(t, lowS)

	sig, err := myecdsa.MarshalECDSASignature(big.NewInt(1), s)
	require.NoError(t, err)

	sig, err = myecdsa.SignatureToLowS(&key.PublicKey, sig)
	require.NoError(t, err)

	_, s, err = myecdsa.UnmarshalECDSASignature(sig)
	require.NoError(t, err)
	lowS, err = myecdsa.IsLowS(&key.PublicKey, s)
	require.NoError(t, err)
	require.True(t, lowS)
}
