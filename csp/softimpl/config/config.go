package config

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/11090815/mayy/errors"
	"golang.org/x/crypto/sha3"
)

type Config struct {
	ellipticCurve elliptic.Curve
	hashFunc      func() hash.Hash
	aesBitLength  int
}

func NewConfig() *Config {
	return &Config{}
}

func (c *Config) HashFunc() func() hash.Hash {
	return c.hashFunc
}

func (c *Config) EllipticCurve() elliptic.Curve {
	return c.ellipticCurve
}

func (c *Config) AESBytesLength() int {
	return c.aesBitLength / 8
}

// SetSecurityLevel 设置哈希函数的安全级别，securityLevel 可取的值包括 256 和 384，hashFamily 可取的值
// 包括 SHA2 和 SHA3。
//
//	SHA2
//		256：sha256.New，elliptic.P256()
//		384：sha512.New384，elliptic.P384()
//
//	SHA3
//		256：sha3.New256，elliptic.P256()
//		384：sha3.New384，elliptic.P384()
func (c *Config) SetSecurityLevel(securityLevel int, hashFamily string) error {
	var err error
	switch hashFamily {
	case "SHA2":
		err = setSecurityLevelSHA2(c, securityLevel)
	case "SHA3":
		err = setSecurityLevelSHA3(c, securityLevel)
	default:
		err = errors.NewErrorf("the supported hash families contain [SHA2, SHA3], but the provided hash family is \"%s\"", hashFamily)
	}

	return err
}

/* ------------------------------------------------------------------------------------------ */

func setSecurityLevelSHA2(c *Config, level int) error {
	var err error
	switch level {
	case 256:
		c.ellipticCurve = elliptic.P256()
		c.aesBitLength = 256
		c.hashFunc = sha256.New
	case 384:
		c.ellipticCurve = elliptic.P384()
		c.aesBitLength = 256
		c.hashFunc = sha512.New384
	default:
		err = errors.NewErrorf("security level contains [256, 384], but the provided security level is \"%d\"", level)
	}
	return err
}

func setSecurityLevelSHA3(c *Config, level int) error {
	var err error
	switch level {
	case 256:
		c.ellipticCurve = elliptic.P256()
		c.aesBitLength = 256
		c.hashFunc = sha3.New256
	case 384:
		c.ellipticCurve = elliptic.P384()
		c.aesBitLength = 256
		c.hashFunc = sha3.New384
	default:
		err = errors.NewErrorf("security level contains [256, 384], but the provided security level is \"%d\"", level)
	}
	return err
}
