package tlsca

/* ------------------------------------------------------------------------------------------ */

const (
	TLS = "TLS"
)

type TLSCAGenOpts struct {
	Level int
}

func (opts *TLSCAGenOpts) SecurityLevel() int {
	return opts.Level
}

func (opts *TLSCAGenOpts) Algorithm() string {
	return TLS
}
