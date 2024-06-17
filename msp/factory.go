package msp

import (
	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/common/errors"
)

func NewMSP(opts NewOpts, cryptoProvider csp.CSP) (MSP, error) {
	switch opts.(type) {
	case *CSPNewOpts:
		switch opts.GetVersion() {
		case MSPv1_0:
			return newCspMsp(MSPv1_0, cryptoProvider)
		default:
			return nil, errors.NewErrorf("invalid *CSPNewOpts, version %v is not recognized", opts.GetVersion())
		}
	default:
		return nil, errors.NewErrorf("invalid NewOpts instance, opts %T is not recognized", opts)
	}
}
