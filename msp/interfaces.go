package msp

import (
	"time"

	"github.com/11090815/mayy/protobuf/pmsp"
)

type MSPManager interface {
	IdentityDeserializer

	Setup(msps []MSP) error

	GetMSPs() map[string]MSP
}

type MSP interface {
	IdentityDeserializer

	Setup(config *pmsp.MSPConfig) error

	GetVersion() MSPVersion

	// GetType 目前只会返回 "csp"。
	GetType() ProviderType

	GetIdentifier() string

	GetDefaultSigningIdentity() (SigningIdentity, error)

	// GetTLSRootCerts 返回此 MSP 的根 TLS 证书。
	GetTLSRootCerts() [][]byte

	// GetTLSIntermediateCerts 返回此 MSP 的 TLS 中级证书。
	GetTLSIntermediateCerts() [][]byte

	// Validate 验证给定的身份是否合法。
	Validate(id Identity) error

	// SatisfiesPrinciple 检查给定的身份实例是否与给定的 MSPPrinciple 中提供的描述匹配。
	SatisfiesPrinciple(id Identity, principal *pmsp.MSPPrinciple) error
}

type IdentityDeserializer interface {
	DeserializeIdentity(serializedIdentity []byte) (Identity, error)

	// IsWellFormed 检查给定的序列化的身份是否能够反序列化成指定的形式。
	IsWellFormed(serializedIdentity *pmsp.SerializedIdentity) error
}

type Identity interface {
	// ExpiresAt 返回身份的过期时间。
	ExpiresAt() time.Time

	// GetIdentifier 获取身份标识。
	GetIdentifier() *IdentityIdentifier

	// GetMSPIdentifier 获取 msp 的标识符。
	GetMSPIdentifier() string

	// Validate 验证身份的正确性。
	Validate() error

	// GetOrganizationalUnits 返回与此身份关联的组织单元。
	GetOrganizationalUnits() []*OUIdentifier

	// Anonymous 返回此身份是否是匿名的。
	Anonymous() bool

	// Verify 验证给定消息和签名的正确性。
	Verify(msg []byte, signature []byte) error

	// Serialize 将身份信息序列化成字节数组。
	Serialize() ([]byte, error)

	// SatisfiesPrinciple 检查此身份实例是否与 MSPPrinciple 中提供的描述匹配。
	SatisfiesPrinciple(principal *pmsp.MSPPrinciple) error
}

type SigningIdentity interface {
	Identity

	Sign(msg []byte) ([]byte, error)

	// GetPublicVersion 返回此身份的公开部分。
	GetPublicVersion() Identity
}

type NewOpts interface {
	GetVersion() MSPVersion
}
