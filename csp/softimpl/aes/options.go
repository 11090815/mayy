package aes

/* ------------------------------------------------------------------------------------------ */

const (
	AES = "AES"
)

/* ------------------------------------------------------------------------------------------ */

type AESCBCPKCS7ModeOpts struct {
	// IV 加密时使用的初始化向量
	IV []byte
}

/* ------------------------------------------------------------------------------------------ */

type AES256KeyDerivOpts struct {
	Temporary bool
	Arg       []byte
}

func (opts *AES256KeyDerivOpts) Algorithm() string {
	return AES
}

func (opts *AES256KeyDerivOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *AES256KeyDerivOpts) Argument() []byte {
	return opts.Arg
}

/* ------------------------------------------------------------------------------------------ */

type AESKeyDerivOpts struct {
	Temporary bool
	Arg       []byte
}

func (opts *AESKeyDerivOpts) Algorithm() string {
	return AES
}

func (opts *AESKeyDerivOpts) Ephemeral() bool {
	return opts.Temporary
}

func (opts *AESKeyDerivOpts) Argument() []byte {
	return opts.Arg
}

/* ------------------------------------------------------------------------------------------ */

type AESKeyImportOpts struct {
	Temporary bool
}

func (opts *AESKeyImportOpts) Algorithm() string {
	return AES
}

func (opts *AESKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

/* ------------------------------------------------------------------------------------------ */

type AES128KeyGenOpts struct {
	Temporary bool
}

func (opts *AES128KeyGenOpts) Algorithm() string {
	return AES
}

func (opts *AES128KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

/* ------------------------------------------------------------------------------------------ */

type AES256KeyGenOpts struct {
	Temporary bool
}

func (opts *AES256KeyGenOpts) Algorithm() string {
	return AES
}

func (opts *AES256KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}
