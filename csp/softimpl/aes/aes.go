package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"

	"github.com/11090815/mayy/csp/interfaces"
	"github.com/11090815/mayy/csp/softimpl/utils"
	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

type AESCBCPKCS7Encrypter struct{}

func NewAESCBCPKCS7Encrypter() *AESCBCPKCS7Encrypter {
	return &AESCBCPKCS7Encrypter{}
}

// Encrypt 此方法的第三个参数 EncrypterOpts 要么是 *AESCBCPKCS7ModeOpts，要么是 AESCBCPKCS7ModeOpts。
func (encrypter *AESCBCPKCS7Encrypter) Encrypt(key interfaces.Key, plaintext []byte, opts interfaces.EncrypterOpts) ([]byte, error) {
	switch o := opts.(type) {
	case *AESCBCPKCS7ModeOpts:
		if len(o.IV) != 0 {
			return encryptWithIV(o.IV, key.(*AESKey).key, plaintext)
		} else {
			return encrypt(key.(*AESKey).key, plaintext)
		}
	case AESCBCPKCS7ModeOpts:
		return encrypter.Encrypt(key, plaintext, &o)
	default:
		return nil, errors.NewErrorf("encryption option \"%T\" is not recognized", opts)
	}
}

/* ------------------------------------------------------------------------------------------ */

type AESCBCPKCS7Decrypter struct{}

func NewAESCBCPKCS7Decrypter() *AESCBCPKCS7Decrypter {
	return &AESCBCPKCS7Decrypter{}
}

// Decrypt 此方法的第三个参数 DecrypterOpts 可以是 nil。
func (decrypter *AESCBCPKCS7Decrypter) Decrypt(key interfaces.Key, ciphertext []byte, opts interfaces.DecrypterOpts) ([]byte, error) {
	return decrypt(key.(*AESKey).key, ciphertext)
}

/* ------------------------------------------------------------------------------------------ */

// pkcs7Padding 补全字节切片，使其长度达到 16 的倍数。
func pkcs7Padding(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	size := len(src)
	padding := int(src[size-1])

	if padding > aes.BlockSize || padding == 0 {
		return nil, errors.NewErrorf("the padded byte should be less than %d and larger than 0", aes.BlockSize)
	}

	pad := src[size-padding:]
	for i := 0; i < padding; i++ {
		if pad[i] != byte(padding) {
			return nil, errors.NewErrorf("invalid padding, pad[%d] != %d", i, padding)
		}
	}

	return src[:size-padding], nil
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	iv, err := utils.GetRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, errors.NewErrorf("failed get initial vector, the errors is \"%s\"", err.Error())
	}

	return encryptWithIV(iv, key, plaintext)
}

func encryptWithIV(iv []byte, key, plaintext []byte) ([]byte, error) {
	plaintext = pkcs7Padding(plaintext)
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.NewErrorf("invalid plaintext, the length of the plaintext must be multiple of \"%d\"", aes.BlockSize)
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.NewErrorf("the length of the initial vector must be \"%d\"", aes.BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.NewErrorf("failed encrypting plaintext, the error is \"%s\"", err.Error())
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	copy(ciphertext[:aes.BlockSize], iv) // 将初始向量拷贝到密文的前面

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.NewErrorf("failed decrypting plaintext, the error is \"%s\"", err.Error())
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.NewErrorf("invalid ciphertext, the length of the ciphertext must be multiple of \"%d\"", aes.BlockSize)
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.NewErrorf("invalid ciphertext, the length of the ciphertext must be multiple of \"%d\"", aes.BlockSize)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return pkcs7UnPadding(ciphertext)
}
