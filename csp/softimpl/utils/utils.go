package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

// ECDSA PUBLIC KEY

func DerToPublicKey(der []byte) (*ecdsa.PublicKey, error) {
	if len(der) == 0 {
		return nil, errors.NewError("invalid der bytes, nil der bytes")
	}

	pk, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.NewErrorf("failed parsing ECDSA public key, the error is \"%s\"", err.Error())
	}

	ecPK, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.NewErrorf("the parsed key is not the ECDSA public key, but it is \"%T\"", pk)
	}
	return ecPK, nil
}

/* ------------------------------------------------------------------------------------------ */

func PEMToPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.NewError("failed decoding PEM")
	}

	return DerToPublicKey(block.Bytes)
}

func PublicKeyToPEM(publickey *ecdsa.PublicKey) ([]byte, error) {
	if publickey == nil {
		return nil, errors.NewError("invalid public key, nil public key")
	}

	asn1Bytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return nil, errors.NewErrorf("failed marshaling ECDSA public key, the error is \"%s\"", err.Error())
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: asn1Bytes}), nil
}

/* ------------------------------------------------------------------------------------------ */

// ECDSA PRIVATE KEY

func DerToPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	} else {
		return nil, errors.NewErrorf("invalid raw material, parsing and getting a private key doesn't belong to ECDSA")
	}
}

func PrivateKeyToDER(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.NewError("invalid ECDSA private key, nil private key")
	}

	return x509.MarshalECPrivateKey(privateKey)
}

/* ------------------------------------------------------------------------------------------ */

func PrivateKeyToPEM(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.NewError("invalid private key, nil private key")
	}

	asn1Bytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, errors.NewErrorf("failed marshaling private key to DER, the error is \"%s\"", err.Error())
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: asn1Bytes}), nil
}

func PEMToPrivateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.NewErrorf("failed decoding PEM")
	}

	return DerToPrivateKey(block.Bytes)
}

/* ------------------------------------------------------------------------------------------ */

// AES KEY

func PEMToAES(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.NewError("invalid PEM, nil PEM")
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.NewError("failed decoding PEM")
	}

	return block.Bytes, nil
}

func AESToPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "AES PRIVATE KEY", Bytes: raw})
}

/* ------------------------------------------------------------------------------------------ */

func GetRandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.NewError("the size of the random bytes must be larger than 0")
	}

	buffer := make([]byte, size)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, errors.NewErrorf("cannot generate random bytes, the error is \"%s\"", err.Error())
	}

	if n != size {
		return nil, errors.NewErrorf("want to generate \"%d\" bytes, but got \"%d\"", size, n)
	}

	return buffer, nil
}
