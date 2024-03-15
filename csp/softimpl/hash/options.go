package hash

import (
	"github.com/11090815/mayy/csp/interfaces"
	"github.com/11090815/mayy/errors"
)

/* ------------------------------------------------------------------------------------------ */

const (
	SHA256   = "SAH256"
	SHA384   = "SAH384"
	SHA3_256 = "SHA3_256"
	SHA3_384 = "SHA3_384"
)

/* ------------------------------------------------------------------------------------------ */

func GetHashOpt(hashFunc string) (interfaces.HashOpts, error) {
	switch hashFunc {
	case SHA256:
		return &SHA256Opts{}, nil
	case SHA384:
		return &SHA384Opts{}, nil
	case SHA3_256:
		return &SHA3_256Opts{}, nil
	case SHA3_384:
		return &SHA3_384Opts{}, nil
	default:
		return nil, errors.NewErrorf("hash function \"%s\" is not recognized", hashFunc)
	}
}

/* ------------------------------------------------------------------------------------------ */

type SHA256Opts struct{}

func (opts *SHA256Opts) Algorithm() string {
	return SHA256
}

/* ------------------------------------------------------------------------------------------ */

type SHA384Opts struct{}

func (opts *SHA384Opts) Algorithm() string {
	return SHA384
}

/* ------------------------------------------------------------------------------------------ */

type SHA3_256Opts struct{}

func (opts *SHA3_256Opts) Algorithm() string {
	return SHA3_256
}

/* ------------------------------------------------------------------------------------------ */

type SHA3_384Opts struct{}

func (opts *SHA3_384Opts) Algorithm() string {
	return SHA3_384
}
