package aes

import (
	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/csp/softimpl/utils"
	"github.com/11090815/mayy/common/errors"
)

/* ------------------------------------------------------------------------------------------ */

type AESKeyGenerator struct {
	length int
}

func NewAESKeyGenerator(length int) *AESKeyGenerator {
	return &AESKeyGenerator{length: length}
}

// KeyGen 此方法的入参 KeyGenOpts 可以是 nil。
func (kg *AESKeyGenerator) KeyGen(opts csp.KeyGenOpts) (csp.Key, error) {
	lowLevelKey, err := utils.GetRandomBytes(kg.length)
	if err != nil {
		return nil, errors.NewErrorf("failed getting \"%d\" bytes for aes key generator, the error is \"%s\"", kg.length, err.Error())
	}

	return &AESKey{key: lowLevelKey, exportable: false}, nil
}
