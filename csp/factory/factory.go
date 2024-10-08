package factory

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"reflect"
	"sync"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/csp/softimpl"
	"github.com/11090815/mayy/csp/softimpl/aes"
	"github.com/11090815/mayy/csp/softimpl/config"
	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/csp/softimpl/hash"
	"github.com/11090815/mayy/csp/softimpl/keystore"
	"golang.org/x/crypto/sha3"
)

var (
	defaultFactory      *CSPFactory
	temporaryCSP        csp.CSP
	getTemporaryCSPOnce sync.Once
	logger              = mlog.GetLogger("csp", mlog.DebugLevel, true)

	defaultFactoryOpts = &FactoryOpts{
		Kind:          "sw",
		KeyStorePath:  "/tmp/mayy/keystore",
		SecurityLevel: 256,
		HashFamily:    "SHA2",
		ReadOnly:      false,
	}

	mutex = sync.Mutex{}
)

type CSPFactory struct {
	opts *FactoryOpts
	csps map[string]csp.CSP
}

func InitCSPFactoryWithOpts(opts *FactoryOpts) {
	if defaultFactory == nil {
		defaultFactory = &CSPFactory{
			opts: opts,
			csps: make(map[string]csp.CSP),
		}
	} else {
		changed := false
		if opts.Kind != defaultFactory.opts.Kind {
			panic(fmt.Sprintf("once the csp factory's kind is specified, it can not be changed from %s to %s", defaultFactory.opts.Kind, opts.Kind))
		}
		if opts.HashFamily != defaultFactory.opts.HashFamily {
			defaultFactory.opts.HashFamily = opts.HashFamily
			changed = true
		}
		if opts.KeyStorePath != defaultFactory.opts.KeyStorePath {
			defaultFactory.opts.KeyStorePath = opts.KeyStorePath
			changed = true
		}
		if opts.ReadOnly != defaultFactory.opts.ReadOnly {
			defaultFactory.opts.ReadOnly = opts.ReadOnly
			changed = true
		}
		if opts.SecurityLevel != defaultFactory.opts.SecurityLevel {
			defaultFactory.opts.SecurityLevel = opts.SecurityLevel
			changed = true
		}
		if changed {
			_, exists := defaultFactory.csps[opts.Kind]
			if exists {
				newCsp, err := createSoftBasedCSP(defaultFactory.opts)
				if err != nil {
					panic(err)
				}
				defaultFactory.csps[opts.Kind] = newCsp
			}
		}
	}
}

func GetCSP() (csp.CSP, error) {
	if defaultFactory == nil || defaultFactory.opts == nil {
		getTemporaryCSPOnce.Do(func() {
			logger.Warn("Before using CSP, please call InitCSPFactoryWithOpts(), falling back to temporary csp.")
			var err error
			temporaryCSP, err = createSoftBasedCSP(defaultFactoryOpts)
			if err != nil {
				panic(err)
			}
		})
		return temporaryCSP, nil
	}
	switch defaultFactory.opts.Kind {
	case "sw", "SW", "Sw", "sW":
		mutex.Lock()
		defer mutex.Unlock()
		if csp, ok := defaultFactory.csps["sw"]; ok {
			return csp, nil
		}
		csp, err := createSoftBasedCSP(defaultFactory.opts)
		if err != nil {
			return nil, err
		}
		defaultFactory.csps["sw"] = csp
		return defaultFactory.csps["sw"], nil
	default:
		return nil, errors.NewErrorf("unknown crypto service provider mode \"%s\"", defaultFactory.opts.Kind)
	}
}

func createSoftBasedCSP(opts *FactoryOpts) (csp.CSP, error) {
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
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAX509PublicKeyImportOpts{}), ecdsa.NewECDSAX509PublicKeyImporter(softImpl.(*softimpl.SoftCSPImpl)))
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&aes.AESKeyImportOpts{}), aes.NewAESKeyImporter())

	// Key Derive
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAPrivateKey{}), ecdsa.NewECDSAPrivateKeyDeriver())
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAPublicKey{}), ecdsa.NewECDSAPublicKeyDeriver())
	softimpl.RegisterWidget(softImpl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&aes.AESKey{}), aes.NewAESKeyDeriver(cfg))

	return softImpl, nil
}
