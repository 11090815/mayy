package aes

import (
	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

type AESKeyImporter struct{}

func NewAESKeyImporter() *AESKeyImporter {
	return &AESKeyImporter{}
}

// KeyImport 此方法的第二个参数 KeyImportOpts 可以是 nil。
func (importer *AESKeyImporter) KeyImport(raw interface{}, opts csp.KeyImportOpts) (csp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.NewErrorf("invalid raw material, expected bytes, but got \"%T\"", raw)
	}

	if len(aesRaw) == 0 {
		return nil, errors.NewError("invalid raw material, nil material")
	}

	if len(aesRaw) != 32 && len(aesRaw) != 16 {
		return nil, errors.NewErrorf("invalid raw material, the length of the bytes must be 32 or 16, but got \"%d\"", len(aesRaw))
	}

	return &AESKey{key: aesRaw}, nil
}
