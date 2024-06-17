package tlsca

import (
	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/common/errors"
)

type TLSCAGenerator struct{}

func NewTLSCAGenerator() *TLSCAGenerator {
	return &TLSCAGenerator{}
}

func (cg *TLSCAGenerator) GenCA(opts csp.CAGenOpts) (csp.CA, error) {
	if opts == nil {
		return nil, errors.NewError("failed generating tls CA, nil opts")
	}
	tlsCAOpts, ok := opts.(*TLSCAGenOpts)
	if !ok {
		return nil, errors.NewErrorf("failed generating tls CA, invalid opts, want *X509CAGenOpts, but got \"%T\"", opts)
	}
	return newCA(tlsCAOpts.SecurityLevel())
}
