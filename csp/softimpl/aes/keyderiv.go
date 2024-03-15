package aes

import (
	"crypto/hmac"

	"github.com/11090815/mayy/csp/interfaces"
	"github.com/11090815/mayy/csp/softimpl/config"
	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

type AESKeyDeriver struct {
	config *config.Config
}

func NewAESKeyDeriver(c *config.Config) *AESKeyDeriver {
	return &AESKeyDeriver{config: c}
}

func (kd *AESKeyDeriver) KeyDeriv(key interfaces.Key, opts interfaces.KeyDerivOpts) (interfaces.Key, error) {
	if opts == nil {
		return nil, errors.NewError("invalid opts parameter, nil opts parameter")
	}

	aesK := key.(*AESKey)

	switch o := opts.(type) {
	case *AES256KeyDerivOpts:
		mac := hmac.New(kd.config.HashFunc(), aesK.key)
		mac.Write(o.Argument())
		return &AESKey{key: mac.Sum(nil)[:kd.config.AESBytesLength()], exportable: false}, nil
	case *AESKeyDerivOpts:
		mac := hmac.New(kd.config.HashFunc(), aesK.key)
		mac.Write(o.Argument())
		return &AESKey{key: mac.Sum(nil), exportable: false}, nil
	default:
		return nil, errors.NewErrorf("the supported options contain [*AES256KeyDerivOpts, *AESKeyDerivOpts], but got \"%T\"", opts)
	}
}
