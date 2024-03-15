package ecdsa_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	goecdsa "crypto/ecdsa"

	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/csp/softimpl/hash"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestInitTestFiles(t *testing.T) {
	createTestFiles(t)
}

func TestSignAndVerify(t *testing.T) {
	kGenerator := ecdsa.NewECDSAKeyGenerator(elliptic.P256())
	sk1, err := kGenerator.KeyGen(nil)
	require.NoError(t, err)
	pk1, err := sk1.PublicKey()
	require.NoError(t, err)

	sk2, err := kGenerator.KeyGen(nil)
	require.NoError(t, err)
	pk2, err := sk2.PublicKey()
	require.NoError(t, err)

	hasher := hash.NewHasher(sha256.New)

	msg := []byte("我是特斯拉的CEO")
	digest, _ := hasher.Hash(msg, nil)

	signer := ecdsa.NewECDSASigner()
	sig, err := signer.Sign(sk1, digest, nil)
	require.NoError(t, err)

	fmt.Printf("签名 -> %x\n", sig)

	privateVerifier := ecdsa.NewECDSAPrivateKeyVerifier()
	isValid, err := privateVerifier.Verify(sk1, sig, digest, nil)
	require.NoError(t, err)
	require.True(t, isValid)

	publicVerifier := ecdsa.NewECDSAPublicKeyVerifier()
	isValid, err = publicVerifier.Verify(pk1, sig, digest, nil)
	require.NoError(t, err)
	require.True(t, isValid)

	isValid, err = privateVerifier.Verify(sk2, sig, digest, nil)
	require.NoError(t, err)
	require.False(t, isValid)

	isValid, err = publicVerifier.Verify(pk2, sig, digest, nil)
	require.NoError(t, err)
	require.False(t, isValid)
}

func TestKeyImport(t *testing.T) {
	keyPaths := []string{
		"testFile/testPrivateKey256.pem#testFile/testPublicKey256.pem",
		"testFile/testPrivateKey384.pem#testFile/testPublicKey384.pem",
	}
	for _, paths := range keyPaths {
		ps := strings.Split(paths, "#")
		f, err := os.Open(ps[0])
		require.NoError(t, err)
		raw, err := io.ReadAll(f)
		require.NoError(t, err)

		hasher := hash.NewHasher(sha3.New384)
		signer := ecdsa.NewECDSASigner()
		privateVerifier := ecdsa.NewECDSAPrivateKeyVerifier()
		publicVerifier := ecdsa.NewECDSAPublicKeyVerifier()

		kImporter := ecdsa.NewECDSAPrivateKeyImporter()
		der, _ := pem.Decode(raw)
		require.NotNil(t, der)
		sk, err := kImporter.KeyImport(der.Bytes, nil)
		require.NoError(t, err)
		pk, err := sk.PublicKey()
		require.NoError(t, err)

		msg := []byte("我是 Apple CEO")
		digest, _ := hasher.Hash(msg, nil)

		sig, err := signer.Sign(sk, digest, nil)
		require.NoError(t, err)
		isValid, err := privateVerifier.Verify(sk, sig, digest, nil)
		require.NoError(t, err)
		require.True(t, isValid)
		isValid, err = publicVerifier.Verify(pk, sig, digest, nil)
		require.NoError(t, err)
		require.True(t, isValid)
		f.Close()

		f, err = os.Open(ps[1])
		require.NoError(t, err)
		raw, err = io.ReadAll(f)
		require.NoError(t, err)
		pkImporter := ecdsa.NewECDSAPKIXPublicKeyImporter()
		der, _ = pem.Decode(raw)
		require.NotNil(t, der)
		pk2, err := pkImporter.KeyImport(der.Bytes, nil)
		require.NoError(t, err)
		isValid, err = publicVerifier.Verify(pk2, sig, digest, nil)
		require.NoError(t, err)
		require.True(t, isValid)
		f.Close()
	}
}

func TestKeyDeriv(t *testing.T) {
	opts := &ecdsa.ECDSAReRandKeyOpts{
		Temporary: true,
		Expansion: []byte{7, 9, 11},
	}

	keyPaths := []string{
		"testFile/testPrivateKey256.pem#testFile/testPublicKey256.pem",
		"testFile/testPrivateKey384.pem#testFile/testPublicKey384.pem",
	}

	privateKeyImporter := ecdsa.NewECDSAPrivateKeyImporter()
	publicKeyImporter := ecdsa.NewECDSAPKIXPublicKeyImporter()

	privateKeyDeriver := ecdsa.NewECDSAPrivateKeyDeriver()
	publicKeyDeriver := ecdsa.NewECDSAPublicKeyDeriver()

	hasher := hash.NewHasher(sha3.New384)
	msg := []byte("我是微软CEO")
	digest, _ := hasher.Hash(msg, nil)

	signer := ecdsa.NewECDSASigner()
	verifier := ecdsa.NewECDSAPublicKeyVerifier()

	for _, keyPath := range keyPaths {
		privatePath := strings.Split(keyPath, "#")[0]
		publicPath := strings.Split(keyPath, "#")[1]

		privateFile, err := os.Open(privatePath)
		require.NoError(t, err)

		publicFile, err := os.Open(publicPath)
		require.NoError(t, err)

		raw, err := io.ReadAll(privateFile)
		require.NoError(t, err)
		der, _ := pem.Decode(raw)
		require.NotNil(t, der)
		sk, err := privateKeyImporter.KeyImport(der.Bytes, nil)
		require.NoError(t, err)

		raw, err = io.ReadAll(publicFile)
		require.NoError(t, err)
		der, _ = pem.Decode(raw)
		require.NotNil(t, der)
		pk, err := publicKeyImporter.KeyImport(der.Bytes, nil)
		require.NoError(t, err)

		dsk, err := privateKeyDeriver.KeyDeriv(sk, opts)
		require.NoError(t, err)
		sig, err := signer.Sign(dsk, digest, nil)
		require.NoError(t, err)

		dpk, err := publicKeyDeriver.KeyDeriv(pk, opts)
		require.NoError(t, err)
		isValid, err := verifier.Verify(dpk, sig, digest, nil)
		require.NoError(t, err)
		require.True(t, isValid)

		pk, err = dsk.PublicKey()
		require.NoError(t, err)
		isValid, err = verifier.Verify(pk, sig, digest, nil)
		require.NoError(t, err)
		require.True(t, isValid)
	}
}

/* ------------------------------------------------------------------------------------------ */

func createTestFiles(t *testing.T) {
	privateKey256, err := goecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	asn1Bytes, err := x509.MarshalECPrivateKey(privateKey256)
	require.NoError(t, err)
	f, err := os.OpenFile("testFile/testPrivateKey256.pem", os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	require.NoError(t, err)
	err = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: asn1Bytes})
	require.NoError(t, err)
	f.Close()

	f, err = os.OpenFile("testFile/testPublicKey256.pem", os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	require.NoError(t, err)
	asn1Bytes, err = x509.MarshalPKIXPublicKey(&privateKey256.PublicKey)
	require.NoError(t, err)
	err = pem.Encode(f, &pem.Block{Type: "EC PUBLIC KEY", Bytes: asn1Bytes})
	require.NoError(t, err)
	f.Close()

	privateKey384, err := goecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	asn1Bytes, err = x509.MarshalECPrivateKey(privateKey384)
	require.NoError(t, err)
	f, err = os.OpenFile("testFile/testPrivateKey384.pem", os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	require.NoError(t, err)
	err = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: asn1Bytes})
	require.NoError(t, err)
	f.Close()

	f, err = os.OpenFile("testFile/testPublicKey384.pem", os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	require.NoError(t, err)
	asn1Bytes, err = x509.MarshalPKIXPublicKey(&privateKey384.PublicKey)
	require.NoError(t, err)
	err = pem.Encode(f, &pem.Block{Type: "EC PUBLIC KEY", Bytes: asn1Bytes})
	require.NoError(t, err)
	f.Close()
}
