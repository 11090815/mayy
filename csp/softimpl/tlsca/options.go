package tlsca

/* ------------------------------------------------------------------------------------------ */

const (
	TLS = "TLS"
)

type TLSCAGenOpts struct {
	// Level 目前支持 256 和 384 两个安全级别。
	Level int
}

func (opts *TLSCAGenOpts) SecurityLevel() int {
	return opts.Level
}

func (opts *TLSCAGenOpts) Algorithm() string {
	return TLS
}
