package aes_test

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/11090815/mayy/csp/softimpl/aes"
	"github.com/11090815/mayy/csp/softimpl/utils"
	"github.com/stretchr/testify/require"
)

func TestInitTestFiles(t *testing.T) {
	initFiles(t)
}

func TestAESWithoutIV(t *testing.T) {
	kg := aes.NewAESKeyGenerator(16)

	key, err := kg.KeyGen(nil)
	require.NoError(t, err)

	plaintext := []byte("Pleases provide as much information that you can with the issue you're experiencing: stack traces logs.")

	encrypter := aes.NewAESCBCPKCS7Encrypter()

	ciphertext, err := encrypter.Encrypt(key, plaintext, aes.AESCBCPKCS7ModeOpts{})
	require.NoError(t, err)

	fmt.Println(string(ciphertext))

	decrypter := aes.NewAESCBCPKCS7Decrypter()

	decrypted, err := decrypter.Decrypt(key, ciphertext, &aes.AESCBCPKCS7ModeOpts{})
	require.NoError(t, err)

	require.Equal(t, decrypted, plaintext)

	fmt.Println(string(decrypted))
}

func TestAESWithIV(t *testing.T) {
	kg := aes.NewAESKeyGenerator(16)

	key, err := kg.KeyGen(nil)
	require.NoError(t, err)

	plaintext := []byte("Pleases provide as much information that you can with the issue you're experiencing: stack traces logs.")

	encrypter := aes.NewAESCBCPKCS7Encrypter()

	ciphertext, err := encrypter.Encrypt(key, plaintext, aes.AESCBCPKCS7ModeOpts{IV: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f'}})
	require.NoError(t, err)

	fmt.Println(string(ciphertext))

	decrypter := aes.NewAESCBCPKCS7Decrypter()

	decrypted, err := decrypter.Decrypt(key, ciphertext, &aes.AESCBCPKCS7ModeOpts{IV: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f'}})
	require.NoError(t, err)

	require.Equal(t, decrypted, plaintext)

	fmt.Println(string(decrypted))
}

func TestKeyImport(t *testing.T) {
	raw, err := utils.GetRandomBytes(32)
	require.NoError(t, err)

	importer := aes.NewAESKeyImporter()
	sk, err := importer.KeyImport(raw, nil)
	require.NoError(t, err)

	msg := []byte("我是总统")

	encrypter := aes.NewAESCBCPKCS7Encrypter()
	ciphertext, err := encrypter.Encrypt(sk, msg, &aes.AESCBCPKCS7ModeOpts{})
	require.NoError(t, err)

	decrypter := aes.NewAESCBCPKCS7Decrypter()
	plaintext, err := decrypter.Decrypt(sk, ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, plaintext, msg)
}

func TestPemToAES(t *testing.T) {
	f, err := os.Open("testFile/aes.pem")
	require.NoError(t, err)
	raw, err := io.ReadAll(f)
	require.NoError(t, err)

	raw, err = utils.PEMToAES(raw)
	require.NoError(t, err)

	importer := aes.NewAESKeyImporter()
	sk, err := importer.KeyImport(raw, nil)
	require.NoError(t, err)

	msg := []byte("我是总统")

	encrypter := aes.NewAESCBCPKCS7Encrypter()
	ciphertext, err := encrypter.Encrypt(sk, msg, &aes.AESCBCPKCS7ModeOpts{})
	require.NoError(t, err)

	decrypter := aes.NewAESCBCPKCS7Decrypter()
	plaintext, err := decrypter.Decrypt(sk, ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, plaintext, msg)
	f.Close()
}

func initFiles(t *testing.T) {
	raw, err := utils.GetRandomBytes(32)
	require.NoError(t, err)

	p := utils.AESToPEM(raw)

	err = os.WriteFile("testFile/aes.pem", p, os.FileMode(0600))
	require.NoError(t, err)
}
