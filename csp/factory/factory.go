package factory

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"reflect"

	"github.com/11090815/mayy/csp/interfaces"
	"github.com/11090815/mayy/csp/softimpl"
	"github.com/11090815/mayy/csp/softimpl/aes"
	"github.com/11090815/mayy/csp/softimpl/config"
	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/csp/softimpl/hash"
	"github.com/11090815/mayy/csp/softimpl/keystore"
	"github.com/11090815/mayy/errors"
	"golang.org/x/crypto/sha3"
)

type CSPFactory struct {
	opts *FactoryOpts
}

func NewCSPFactory(opts *FactoryOpts) *CSPFactory {
	return &CSPFactory{opts: opts}
}

func (factory *CSPFactory) CreateFactory() (interfaces.CSP, error) {
	if factory.opts == nil {
		return nil, errors.NewError("invalid options, nil options")
	}
	switch factory.opts.Kind {
	case "sw", "SW", "Sw", "sW":
		return createSoftBasedCSP(factory.opts)
	default:
		return nil, errors.NewErrorf("unknown crypto service provider mode \"%s\"", factory.opts.Kind)
	}
}

func createSoftBasedCSP(opts *FactoryOpts) (interfaces.CSP, error) {
	ks, err := keystore.NewFileBasedKeyStore(opts.KeyStorePath, opts.ReadOnly)
	if err != nil {
		return nil, errors.NewErrorf("cannot create crypto service provider based on soft ware, the error is \"%s\"", err.Error())
	}

	softImpl, err := softimpl.NewSoftCSPImpl(ks)
	if err != nil {
		return nil, errors.NewErrorf("cannot create crypto service provider based on soft ware, the error is \"%s\"", err.Error())
	}

	cfg := &config.Config{}
	cfg.SetSecurityLevel(opts.SecurityLevel, opts.HashFamily)

	// Hash
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&hash.SHA256Opts{}), hash.NewHasher(sha256.New))
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&hash.SHA384Opts{}), hash.NewHasher(sha512.New384))
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&hash.SHA3_256Opts{}), hash.NewHasher(sha3.New256))
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&hash.SHA3_384Opts{}), hash.NewHasher(sha3.New384))

	// Sign
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAPrivateKey{}), ecdsa.NewECDSASigner())

	// Verify
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAPrivateKey{}), ecdsa.NewECDSAPrivateKeyVerifier())
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAPublicKey{}), ecdsa.NewECDSAPublicKeyVerifier())

	// Encrypt
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&aes.AESKey{}), aes.NewAESCBCPKCS7Encrypter())

	// Decrypt
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&aes.AESKey{}), aes.NewAESCBCPKCS7Decrypter())

	// Key Gen
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAP256KeyGenOpts{}), ecdsa.NewECDSAKeyGenerator(elliptic.P256()))
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAP384KeyGenOpts{}), ecdsa.NewECDSAKeyGenerator(elliptic.P384()))
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&aes.AES128KeyGenOpts{}), aes.NewAESKeyGenerator(16))
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&aes.AES256KeyGenOpts{}), aes.NewAESKeyGenerator(32))

	// Key Import
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAPrivateKeyImportOpts{}), ecdsa.NewECDSAPrivateKeyImporter())
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAGoPublicKeyImportOpts{}), ecdsa.NewECDSAGoPublicKeyImporter())
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAPKIXPublicKeyImportOpts{}), ecdsa.NewECDSAPKIXPublicKeyImporter())
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&aes.AESKeyImportOpts{}), aes.NewAESKeyImporter())

	// Key Derive
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAPrivateKey{}), ecdsa.NewECDSAPrivateKeyDeriver())
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAPublicKey{}), ecdsa.NewECDSAPublicKeyDeriver())
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&aes.AESKey{}), aes.NewAESKeyDeriver(cfg))

	return softImpl, nil
}
