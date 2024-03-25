package tlsca

import (
	"github.com/11090815/mayy/csp/interfaces"
	"github.com/11090815/mayy/errors"
)

type TLSCAGenerator struct{}

func NewTLSCAGenerator() *TLSCAGenerator {
	return &TLSCAGenerator{}
}

func (cg *TLSCAGenerator) CAGen(opts interfaces.CAGenOpts) (interfaces.CA, error) {
	if opts == nil {
		return nil, errors.NewError("failed generating tls CA, nil opts")
	}
	tlsCAOpts, ok := opts.(*TLSCAGenOpts)
	if !ok {
		return nil, errors.NewErrorf("failed generating tls CA, invalid opts, want *X509CAGenOpts, but got \"%T\"", opts)
	}
	return newCA(tlsCAOpts.SecurityLevel())
}
