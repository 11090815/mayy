package tlsca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/11090815/mayy/errors"
)

type certKeyPair struct {
	cert     []byte            // x509 证书的 PEM 格式编码字节切片
	key      []byte            // ecdsa 私钥的 PEM 格式编码字节切片
	signer   crypto.Signer     // 自己的 ecdsa 私钥，不是签发证书的机构的私钥
	x509Cert *x509.Certificate // x509 证书
	tlsCert  tls.Certificate
}

func (kp *certKeyPair) Cert() []byte {
	return kp.cert
}

func (kp *certKeyPair) Key() []byte {
	return kp.key
}

func (kp *certKeyPair) Signer() crypto.Signer {
	return kp.signer
}

func (kp *certKeyPair) X509Cert() *x509.Certificate {
	return kp.x509Cert
}

func (kp *certKeyPair) TLSCert() tls.Certificate {
	return kp.tlsCert
}

func newPrivateKey(securityLevel int) (*ecdsa.PrivateKey, []byte, error) {
	var curve elliptic.Curve
	switch securityLevel {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	default:
		return nil, nil, errors.NewErrorf("invalid security level, want \"256\" or \"384\", but got \"%d\"", securityLevel)
	}
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, errors.NewErrorf("failed generating ECDSA private key, the error is \"%s\"", err.Error())
	}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, errors.NewErrorf("failed generating ECDSA private key, the error is \"%s\"", err.Error())
	}
	return privateKey, privateKeyBytes, nil
}

func newCertTemplate() (x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return x509.Certificate{}, errors.NewErrorf("failed generating serial number for X509 certificate template, the error is \"%s\"", err.Error())
	}

	return x509.Certificate{
		Subject:      pkix.Name{SerialNumber: serialNumber.String()},
		NotBefore:    time.Now().Add(time.Hour * (-24)),
		NotAfter:     time.Now().Add(24 * 365 * 10 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		SerialNumber: serialNumber,
	}, nil
}

func newCertKeyPair(securityLevel int, isCA bool, isServer bool, signer crypto.Signer, parent *x509.Certificate, hosts ...string) (*certKeyPair, error) {
	privateKey, privateKeyBytes, err := newPrivateKey(securityLevel)
	if err != nil {
		return nil, errors.NewErrorf("failed generating certificate key pair, the error is \"%s\"", err.Error())
	}

	template, err := newCertTemplate()
	if err != nil {
		return nil, errors.NewErrorf("failed generating certificate template for certificate key pair, the error is \"%s\"", err.Error())
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		// 通过判断 BasicConstraintsValid 字段的值，可以确定证书是否是一个 CA 证书，
		// 以及是否可以继续签发其他证书。这对于验证和使用证书非常重要，可以确保证书的
		// 正确性和安全性。
		template.BasicConstraintsValid = true
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	if isServer {
		// 在 TLS 通信过程中，服务器会向客户端提供一个证书，用于验证服务器的身份。客户端
		// 会检查证书中的扩展字段 x509.ExtKeyUsageServerAuth 来确定该证书的用途是用于服
		// 务器认证。
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		for _, host := range hosts {
			if ip := net.ParseIP(host); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, host)
			}
		}
	}
	publicKeyRaw := elliptic.Marshal(privateKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	ski := sha256.Sum256(publicKeyRaw)
	template.SubjectKeyId = ski[:]

	if parent == nil || signer == nil {
		// 自己给自己签署证书，一般 CA 是这么干的
		parent = &template
		signer = privateKey
	}

	publicKeyRawBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &privateKey.PublicKey, signer)
	if err != nil {
		return nil, errors.NewErrorf("failed generating certificate, the error is \"%s\"", err.Error())
	}

	certRawPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: publicKeyRawBytes})
	cert, err := x509.ParseCertificate(publicKeyRawBytes)
	if err != nil {
		return nil, errors.NewErrorf("failed generating x509 certificate, the error is \"%s\"", err.Error())
	}

	privateKeyRawPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})
	tlsCert, err := tls.X509KeyPair(certRawPEM, privateKeyRawPEM)
	if err != nil {
		return nil, errors.NewErrorf("failed generating tls certificate, the error is \"%s\"", err.Error())
	}
	return &certKeyPair{
		key:      privateKeyRawPEM,
		cert:     certRawPEM,
		signer:   privateKey,
		x509Cert: cert,
		tlsCert:  tlsCert,
	}, nil
}
