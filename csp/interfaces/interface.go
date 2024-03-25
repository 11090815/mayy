package interfaces

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"hash"
)

/* ------------------------------------------------------------------------------------------ */

type CSP interface {
	// KeyGen 根据提供的密钥生成选项，生成一个密钥。
	KeyGen(opts KeyGenOpts) (key Key, err error)

	// KeyDeriv 给定一个密钥，在此密钥的基础上派生出一个新的密钥。
	KeyDeriv(key Key, opts KeyDerivOpts) (dk Key, err error)

	// KeyImport 给定一个密钥的原始数据，根据此原始数据导入一个密钥。
	KeyImport(raw interface{}, opts KeyImportOpts) (key Key, err error)

	// Hash 给定消息，计算此消息的哈希值。
	Hash(msg []byte, opts HashOpts) ([]byte, error)

	// GetHash 根据给定的哈希选项，返回特定的哈希函数。
	GetHash(opts HashOpts) (hash.Hash, error)

	// Sign 给定密钥（私钥）、消息摘要，计算签名。
	Sign(key Key, digest []byte, opts SignerOpts) (signature []byte, err error)

	// Verify 给定密钥（公钥）、签名，验证签名的正确性。
	Verify(key Key, signature []byte, digest []byte, opts SignerOpts) (valid bool, err error)

	// Encrypt 给定加密密钥、明文，计算密文。
	Encrypt(key Key, plaintext []byte, opts EncrypterOpts) (ciphertext []byte, err error)

	// Decrypt 给定解密密钥、密文，计算明文。
	Decrypt(key Key, ciphertext []byte, opts DecrypterOpts) (plaintext []byte, err error)

	// GetKey 给定密钥的主体标识符，返回此密钥本身。
	GetKey(ski []byte) (key Key, err error)

	CAGen(opts CAGenOpts) (CA, error)
}

/* ------------------------------------------------------------------------------------------ */

type CA interface {
	// CertBytes 返回 CA 的证书的 PEM 格式编码的字节切片。
	CertBytes() []byte

	// NewIntermediateCA 创建一个中级 CA。
	NewIntermediateCA() (CA, error)

	// NewClientCertKeyPair CA 调用此方法为 client 生成一个证书和对应的密钥，证书由 CA 签署，
	// 然后证书被用来验证 client。
	NewClientCertKeyPair() (CertKeyPair, error)

	// NewServerCertKeyPair CA 为 server 生成一个证书和对应的密钥。
	NewServerCertKeyPair(hosts ...string) (CertKeyPair, error)

	// Signer 返回此证书用来给其他证书进行签名的 signer。
	Signer() crypto.Signer
}

/* ------------------------------------------------------------------------------------------ */

type CertKeyPair interface {
	// Cert 返回证书的 PEM 格式编码的字节切片。
	Cert() []byte

	// Key Cert方法返回的证书内包含证书的公钥，此方法返回的私钥与证书内的公钥相对应，
	// 返回的字节切片是私钥的 PEM 格式编码。
	Key() []byte

	// Signer 返回签名私钥，Key 方法返回的字节切片就是此签名密钥。
	Signer() crypto.Signer

	// TLSCert 将 Cert 方法返回的字节切片解析后即可得到 x509 证书，然后此方法可返回该证书。
	TLSCert() tls.Certificate

	X509Cert() *x509.Certificate
}

/* ------------------------------------------------------------------------------------------ */

// Key softimpl 包内的所有密钥都必须实现此接口。
type Key interface {
	Bytes() ([]byte, error)

	// SKI 返回密钥的主体密钥标识符。
	SKI() []byte

	// Symmetric 如果此密钥是对称密钥，则此方法返回 true，否则返回 false。
	Symmetric() bool

	// Private 如果此密钥是私钥，则此方法返回 true，否则返回 false。
	Private() bool

	// PublicKey 只有非对称密钥才能调用此方法返回公钥。
	PublicKey() (Key, error)
}

/* ------------------------------------------------------------------------------------------ */

type KeyStore interface {
	ReadOnly() bool

	GetKey(ski []byte) (Key, error)

	StoreKey(key Key) error
}

/* ------------------------------------------------------------------------------------------ */

type KeyGenOpts interface {
	// Algorithm 返回密钥生成算法的名称。
	Algorithm() string

	// Ephemeral 如果新生成的密钥不需要存储到文件中，则此算法返回 true，否则返回 false。
	Ephemeral() bool
}

/* ------------------------------------------------------------------------------------------ */

type KeyDerivOpts interface {
	// Algorithm 返回密钥派生算法的名称。
	Algorithm() string

	// Ephemeral 如果派生出来的密钥不需要存储在文件中，则此算法返回 true，否则返回 false。
	Ephemeral() bool
}

type KeyImportOpts interface {
	// Algorithm 返回密钥导入算法的名称。
	Algorithm() string

	// Ephemeral 如果导入的密钥不需要存储到文件中，则返回 true，否则返回 false。
	Ephemeral() bool
}

/* ------------------------------------------------------------------------------------------ */

type HashOpts interface {
	// Algorithm 返回哈希算法的名称。
	Algorithm() string
}

/* ------------------------------------------------------------------------------------------ */

type SignerOpts interface {
	// HashFunc 返回哈希函数的标识符 (uint)。
	HashFunc() crypto.Hash
}

/* ------------------------------------------------------------------------------------------ */

// EncrypterOpts 目前此接口内没有定义任何方法，是个空接口。
type EncrypterOpts interface {
}

/* ------------------------------------------------------------------------------------------ */

// DecrypterOpts 目前此接口内没有定义任何方法，是个空接口。
type DecrypterOpts interface {
}

/* ------------------------------------------------------------------------------------------ */

type CAGenOpts interface {
	// SecurityLevel 返回安全等级，一般是 256 或者是 384。
	SecurityLevel() int

	// Algorithm 返回生成证书的算法名称。
	Algorithm() string
}
