package ecdsa

import (
	"crypto/ecdsa"
	"crypto/x509"
	"reflect"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/csp/softimpl"
	"github.com/11090815/mayy/csp/softimpl/utils"
	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

type ECDSAPKIXPublicKeyImporter struct{}

func NewECDSAPKIXPublicKeyImporter() *ECDSAPKIXPublicKeyImporter {
	return &ECDSAPKIXPublicKeyImporter{}
}

// KeyImport 次方的第一个参数必须是 ECDSA 公钥的 PKIX, ASN.1 DER 格式，第二个参数 KeyImportOpts 可以是 nil。
func (*ECDSAPKIXPublicKeyImporter) KeyImport(raw interface{}, opts csp.KeyImportOpts) (csp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.NewErrorf("invalid raw material, expected bytes, but got \"%T\"", raw)
	}

	if len(der) == 0 {
		return nil, errors.NewError("invalid raw material, nil material")
	}

	ecdsaPK, err := utils.DerToPublicKey(der)
	if err != nil {
		return nil, errors.NewErrorf("failed converting to ECDSA public key, the error is \"%s\"", err.Error())
	}

	return &ECDSAPublicKey{publicKey: ecdsaPK}, nil
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAGoPublicKeyImporter struct{}

func NewECDSAGoPublicKeyImporter() *ECDSAGoPublicKeyImporter {
	return &ECDSAGoPublicKeyImporter{}
}

// KeyImport 此方法的第一个参数必须是 *ecdsa.PublicKey，第二个参数 KeyImportOpts 可以是 nil。
func (*ECDSAGoPublicKeyImporter) KeyImport(raw interface{}, opts csp.KeyImportOpts) (csp.Key, error) {
	lowLevelKey, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.NewErrorf("expected *ecdsa.PublicKey, but got \"%s\", ", raw)
	}

	return &ECDSAPublicKey{publicKey: lowLevelKey}, nil
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAX509PublicKeyImporter struct {
	csp *softimpl.SoftCSPImpl
}

func NewECDSAX509PublicKeyImporter(csp *softimpl.SoftCSPImpl) *ECDSAX509PublicKeyImporter {
	return &ECDSAX509PublicKeyImporter{csp: csp}
}

// KeyImport 此方法的第一个参数必须是 *x509.Certificate，第二个参数 KeyImportOpts 可以是 nil。
func (importer *ECDSAX509PublicKeyImporter) KeyImport(raw interface{}, opts csp.KeyImportOpts) (csp.Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.NewErrorf("invalid raw material, expected *x509.Certificate, wanted \"%T\"", raw)
	}

	publicKey := x509Cert.PublicKey

	switch pk := publicKey.(type) {
	case *ecdsa.PublicKey:
		return importer.csp.KeyImporters[reflect.TypeOf(&ECDSAGoPublicKeyImportOpts{})].KeyImport(pk, &ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	default:
		return nil, errors.NewErrorf("certificate's public key type not recognized, supported ECDSA, but got \"%T\"", publicKey)
	}
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAPrivateKeyImporter struct{}

func NewECDSAPrivateKeyImporter() *ECDSAPrivateKeyImporter {
	return &ECDSAPrivateKeyImporter{}
}

// KeyImport 此方法的第一个参数必须是 ECDSA 私钥的 SEC 1, ASN.1 DER 格式，第二个参数 KeyImportOpts 可以是 nil。
func (*ECDSAPrivateKeyImporter) KeyImport(raw interface{}, opts csp.KeyImportOpts) (csp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.NewErrorf("invalid raw material, expected bytes, but got \"%T\"", raw)
	}

	if len(der) == 0 {
		return nil, errors.NewError("invalid raw material, nil material")
	}

	ecdsaSK, err := utils.DerToPrivateKey(der)
	if err != nil {
		return nil, errors.NewErrorf("failed converting to ECDSA private key, the error is \"%s\"", err.Error())
	}

	return &ECDSAPrivateKey{privateKey: ecdsaSK}, nil
}
