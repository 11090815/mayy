package keystore

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/csp/softimpl/aes"
	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/csp/softimpl/utils"
	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

const (
	key = "key"
	sk  = "sk"
	pk  = "pk"
)

/* ------------------------------------------------------------------------------------------ */

type fileBasedKeyStore struct {
	path     string
	readOnly bool
	isOpen   bool
	mutex    *sync.Mutex
}

func NewFileBasedKeyStore(path string, readOnly bool) (*fileBasedKeyStore, error) {
	if len(path) == 0 {
		return nil, errors.NewError("the file path to store the keys is not specified")
	}

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(path, os.FileMode(0755)); err != nil {
			return nil, errors.NewErrorf("cannot create a directory for key store at \"%s\", the error is \"%s\"", path, err.Error())
		}
	}

	return &fileBasedKeyStore{
		path:     path,
		readOnly: readOnly,
		isOpen:   true,
		mutex:    &sync.Mutex{},
	}, nil
}

func (ks *fileBasedKeyStore) ReadOnly() bool {
	return ks.readOnly
}

func (ks *fileBasedKeyStore) GetKey(ski []byte) (csp.Key, error) {
	if len(ski) == 0 {
		return nil, errors.NewError("invalid subject key identifier, nil subject key identifier")
	}

	suffix := ks.getSuffix(hex.EncodeToString(ski))

	keyPath := filepath.Join(ks.path, hex.EncodeToString(ski)+"_"+suffix)
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, errors.NewErrorf("cannot get the key \"%s\", the error is \"%s\"", keyPath, err.Error())
	}

	switch suffix {
	case sk:
		privateKey, err := utils.PEMToPrivateKey(raw)
		if err != nil {
			return nil, errors.NewErrorf("cannot get the ECDSA private key at \"%s\", the error is \"%s\"", keyPath, err.Error())
		}
		return ecdsa.NewECDSAPrivateKey(privateKey), nil
	case pk:
		publicKey, err := utils.PEMToPublicKey(raw)
		if err != nil {
			return nil, errors.NewErrorf("cannot get the ECDSA public key at \"%s\", the error is \"%s\"", keyPath, err.Error())
		}
		return ecdsa.NewECDSAPublicKey(publicKey), nil
	case key:
		aesKey, err := utils.PEMToAES(raw)
		if err != nil {
			return nil, errors.NewErrorf("cannot get the AES key at \"%s\", the error is \"%s\"", keyPath, err.Error())
		}
		return aes.NewAESKey(aesKey), nil
	default:
		return nil, errors.NewErrorf("cannot search for the key at \"%s\"", keyPath)
	}
}

func (ks *fileBasedKeyStore) StoreKey(k csp.Key) error {
	if ks.readOnly {
		return errors.NewError("the read-only key store cannot be overwritten")
	}

	if k == nil {
		return errors.NewError("the provided key is nil")
	}

	switch kk := k.(type) {
	case *aes.AESKey:
		keyPath := filepath.Join(ks.path, hex.EncodeToString(kk.SKI())+"_"+key)
		if err := os.WriteFile(keyPath, aes.AESKeyToPEM(kk), os.FileMode(0600)); err != nil {
			return errors.NewErrorf("cannot store the AES key, the error is \"%s\"", err.Error())
		}
		return nil
	case *ecdsa.ECDSAPrivateKey:
		keyPath := filepath.Join(ks.path, hex.EncodeToString(kk.SKI())+"_"+sk)
		raw, err := ecdsa.ECDSAPrivateKeyToPEM(kk)
		if err != nil {
			return errors.NewErrorf("cannot store the ECDSA private key, the error is \"%s\"", err.Error())
		}
		if err = os.WriteFile(keyPath, raw, os.FileMode(0600)); err != nil {
			return errors.NewErrorf("cannot store the ECDSA private key, the error is \"%s\"", err.Error())
		}
		return nil
	case *ecdsa.ECDSAPublicKey:
		keyPath := filepath.Join(ks.path, hex.EncodeToString(kk.SKI())+"_"+pk)
		raw, err := ecdsa.ECDSAPublicKeyToPEM(kk)
		if err != nil {
			return errors.NewErrorf("cannot store the ECDSA public key, the error is \"%s\"", err.Error())
		}
		if err = os.WriteFile(keyPath, raw, os.FileMode(0600)); err != nil {
			return errors.NewErrorf("cannot store the ECDSA public key, the error is \"%s\"", err.Error())
		}
		return nil
	default:
		return errors.NewErrorf("cannot store the key, because the type of the provided key is \"%T\", cannot recognized this type of the key", k)
	}
}

/* ------------------------------------------------------------------------------------------ */

func (ks *fileBasedKeyStore) getSuffix(skiStr string) string {
	files, _ := os.ReadDir(ks.path)
	for _, file := range files {
		if strings.HasPrefix(file.Name(), skiStr) {
			if strings.HasSuffix(file.Name(), sk) {
				return sk
			}
			if strings.HasSuffix(file.Name(), pk) {
				return pk
			}
			if strings.HasSuffix(file.Name(), key) {
				return key
			}
			break
		}
	}
	return ""
}
