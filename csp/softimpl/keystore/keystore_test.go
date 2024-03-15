package keystore_test

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/11090815/mayy/csp/softimpl/aes"
	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/csp/softimpl/hash"
	"github.com/11090815/mayy/csp/softimpl/keystore"
	"github.com/stretchr/testify/require"
)

func TestNewKeyStore(t *testing.T) {
	path := "testFile"
	ks, err := keystore.NewFileBasedKeyStore(path, true)
	require.NoError(t, err)
	require.True(t, ks.ReadOnly())

	key, err := ks.GetKey([]byte{1})
	require.Error(t, err)
	require.Nil(t, key)

	err = ks.StoreKey(&ecdsa.ECDSAPrivateKey{})
	require.Error(t, err)
	fmt.Println(err)
	clear()
}

func TestStoreAndGetKey(t *testing.T) {
	path := "testFile"
	ks, err := keystore.NewFileBasedKeyStore(path, false)
	require.NoError(t, err)
	// Store
	// ECDSA PRIVATE KEY
	ecdsaKG := ecdsa.NewECDSAKeyGenerator(elliptic.P384())
	sk, err := ecdsaKG.KeyGen(nil)
	require.NoError(t, err)
	err = ks.StoreKey(sk)
	require.NoError(t, err)

	// ECDSA PUBLIC KEY
	pk, err := sk.PublicKey()
	require.NoError(t, err)
	err = ks.StoreKey(pk)
	require.NoError(t, err)

	// AES KEY
	aesKG := aes.NewAESKeyGenerator(32)
	k, err := aesKG.KeyGen(nil)
	require.NoError(t, err)
	err = ks.StoreKey(k)
	require.NoError(t, err)

	// Get
	gettedSK, err := ks.GetKey(sk.SKI())
	require.NoError(t, err)

	hasher := hash.NewHasher(sha256.New)
	msg := []byte("我是大总管")
	digest, _ := hasher.Hash(msg, nil)
	signer := ecdsa.NewECDSASigner()
	sig, err := signer.Sign(sk, digest, nil)
	require.NoError(t, err)
	verifier := ecdsa.NewECDSAPublicKeyVerifier()
	gettedPK, err := gettedSK.PublicKey()
	require.NoError(t, err)
	isValid, err := verifier.Verify(gettedPK, sig, digest, nil)
	require.NoError(t, err)
	require.True(t, isValid)

	gettedK, err := ks.GetKey(k.SKI())
	require.NoError(t, err)
	encrypter := aes.NewAESCBCPKCS7Encrypter()
	ciphertext, err := encrypter.Encrypt(k, msg, &aes.AESCBCPKCS7ModeOpts{})
	require.NoError(t, err)
	decrypter := aes.NewAESCBCPKCS7Decrypter()
	plaintext, err := decrypter.Decrypt(gettedK, ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, plaintext, msg)

	// clear()
}

func clear() {
	files, err := os.ReadDir("testFile")
	if err != nil {
		if os.IsNotExist(err) {
			return
		} else {
			fmt.Println("cannot clear directory \"testFile\"")
			return
		}
	}

	for _, file := range files {
		os.RemoveAll(filepath.Join("testFile", file.Name()))
	}
}
