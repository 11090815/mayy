package ecdsa

/* ------------------------------------------------------------------------------------------ */

const (
	ECDSA       = "ECDSA"
	ECDSAP256   = "ECDSAP256"
	ECDSAP384   = "ECDSAP384"
	ECDSAReRand = "ECDSA_RERAND"
)

/* ------------------------------------------------------------------------------------------ */

type ECDSAP256KeyGenOpts struct {
	Temporary bool
}

func (opts *ECDSAP256KeyGenOpts) Algorithm() string {
	return ECDSAP256
}

// Ephemeral 如果此方法在调用时返回 true，则生成的 ECDSA 密钥不会存储到文件中。
func (opts *ECDSAP256KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAP384KeyGenOpts struct {
	Temporary bool
}

func (opts *ECDSAP384KeyGenOpts) Algorithm() string {
	return ECDSAP384
}

// Ephemeral 如果此方法在调用时返回 true，则生成的 ECDSA 密钥不会存储到文件中。
func (opts *ECDSAP384KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAGoPublicKeyImportOpts struct {
	Temporary bool
}

func (opts *ECDSAGoPublicKeyImportOpts) Algorithm() string {
	return ECDSA
}

func (opts *ECDSAGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAX509PublicKeyImportOpts struct {
	Temporary bool
}

func (opts *ECDSAX509PublicKeyImportOpts) Algorithm() string {
	return ECDSA
}

func (opts *ECDSAX509PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAPKIXPublicKeyImportOpts struct {
	Temporary bool
}

func (opts *ECDSAPKIXPublicKeyImportOpts) Algorithm() string {
	return ECDSA
}

func (opts *ECDSAPKIXPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAPrivateKeyImportOpts struct {
	Temporary bool
}

func (opts *ECDSAPrivateKeyImportOpts) Algorithm() string {
	return ECDSA
}

func (opts *ECDSAPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

/* ------------------------------------------------------------------------------------------ */

type ECDSAReRandKeyOpts struct {
	Temporary bool
	Expansion []byte
}

func (opts *ECDSAReRandKeyOpts) Algorithm() string {
	return ECDSAReRand
}

func (opts *ECDSAReRandKeyOpts) Ephemeral() bool {
	return opts.Temporary
}
