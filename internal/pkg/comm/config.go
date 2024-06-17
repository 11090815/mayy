package comm

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/11090815/mayy/common/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

const (
	DefaultMaxRecvMsgSize = 1024 * 1024 * 100 // byte
	DefaultMaxSendMsgSize = 1024 * 1024 * 100 // byte
)

var (
	DefaultKeepaliveOptions = KeepaliveOptions{
		ClientInterval:    time.Duration(1) * time.Minute,
		ClientTimeout:     time.Duration(20) * time.Second,
		ServerInterval:    time.Duration(2) * time.Hour,
		ServerTimeout:     time.Duration(20) * time.Second,
		ServerMinInterval: time.Duration(1) * time.Minute,
	}
	DefaultTLSCipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
	DefaultConnectionTimeout = 5 * time.Second
)

/* ------------------------------------------------------------------------------------------ */

type KeepaliveOptions struct {
	// ClientInterval 如果服务端在此时间段内没有发送消息给客户端，则客户端会给服务端发送一条 PING 消息，默认为 60 秒。
	ClientInterval time.Duration
	// ClientTimeout 客户端在给服务端发送了 PING 消息后，会等待一段时间，如果在此时间内服务端没有响应，
	// 则客户端会断开与服务端的连接，默认为 20 秒。
	ClientTimeout time.Duration
	// ServerInterval 如果客户端在此时间段内没有发送消息给服务端，则服务端会给客户端发送一条 PING 消息，默认为 2 小时。
	ServerInterval time.Duration
	// ServerTimeout 服务端在给客户端发送了 PING 消息后，会等待一段时间，如果在此时间内客户端没有响应，
	// 则服务端会断开与客户端的连接，默认为 20 秒。
	ServerTimeout time.Duration
	// ServerMinInterval 这是服务端设置的一个时间，如果客户端两次向服务端发送 PING 消息的时间间隔小于
	// 此时间，则客户端 ping 的太频繁了，服务端会断开与客户端之间的连接，默认为 60 秒。
	ServerMinInterval time.Duration
}

// ServerKeepaliveOptions 提取 KeepaliveOptions 结构体消息中的 ServerInterval、ServerTimeout 和 ServerMinInterval 三个
// 字段构造服务端的 keepalive 配置项。
func (ko KeepaliveOptions) ServerKeepaliveOptions() []grpc.ServerOption {
	params := keepalive.ServerParameters{
		Time:    ko.ServerInterval,
		Timeout: ko.ServerTimeout,
	}
	policy := keepalive.EnforcementPolicy{
		MinTime:             ko.ServerMinInterval,
		PermitWithoutStream: true, // 如果为假，在没有活跃的流（RPC）时客户端发送了 ping 包，服务器将回复 GOAWAY 并关闭连接。
	}
	var serverOpts = []grpc.ServerOption{
		grpc.KeepaliveParams(params),
		grpc.KeepaliveEnforcementPolicy(policy),
	}

	return serverOpts
}

// ClientKeepaliveOptions 提取 KeepaliveOptions 结构体消息中的 ClientInterval、ClientTimeout 三个字段构造客户端的 keepalive 配置项。
func (ko KeepaliveOptions) ClientKeepaliveOptions() []grpc.DialOption {
	params := keepalive.ClientParameters{
		Time:                ko.ClientInterval,
		Timeout:             ko.ClientTimeout,
		PermitWithoutStream: true, // 如果为真，即使没有活跃的流（RPC），客户端也会发送 ping。如果为假，当没有活跃的 RPC 时，Time 和 Timeout 将被忽略，并且不会发送 ping。
	}
	var clientOpts = []grpc.DialOption{
		grpc.WithKeepaliveParams(params),
	}

	return clientOpts
}

func (ko KeepaliveOptions) IsServerNil() bool {
	if ko.ServerInterval == 0 && ko.ServerTimeout == 0 && ko.ServerMinInterval == 0 {
		return true
	}
	return false
}

func (ko KeepaliveOptions) IsClientNil() bool {
	if ko.ClientInterval == 0 && ko.ClientTimeout == 0 {
		return true
	}
	return false
}

/* ------------------------------------------------------------------------------------------ */

// SecureOptions 定义了服务端和客户端的 TLS 安全参数。
type SecureOptions struct {
	// VerifyCertificate 如果该字段不为空，则会调用此字段定义的检验方法去核验证书的合法性。
	VerifyCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	// Certificate 该字段存储着 PEM 格式编码的 x509 证书，用于 TLS 通信。
	Certificate []byte
	// Key 此字段存储着 PEM 格式编码的私钥，用于 TLS 通信。
	Key []byte
	// ServerRootCAs 该字段存储着服务端的根 CA 证书，内容格式为 PEM 格式编码，客户端利用此
	// 字段核验服务端的身份。
	ServerRootCAs [][]byte
	// ClientRootCAs 该字段存储着客户端的根 CA 证书，内容格式为 PEM 格式编码，服务端利用此
	// 字段核验客户端的身份。
	ClientRootCAs [][]byte
	// UseTLS 该字段用于指示通信连接是否采用 TLS 安全协议。
	UseTLS bool
	// RequireClientCert 该字段用于指示在 TLS 通信中，客户端是否需要出示证书用于身份验证。
	RequireClientCert bool
	// CipherSuites 该字段列出了 TLS 通信所支持的密码套件。
	CipherSuites []uint16
	// TimeShift 该字段用于在客户端与服务端之间进行时间同步。
	TimeShift time.Duration
	// ServerNameOverride 用于验证返回证书中的主机名。它还包含在客户端握手中，以支持虚拟主机，除非它是一个 IP 地址。
	ServerNameOverride string
}

// TLSConfig 将 SecureOptions 消息结构体转换为 *tls.Config，用到了 SecureOptions 结构体中的以下字段：
//
//   - ServerNameOverride，string，一个字符串，用于验证返回证书中的主机名。
//
//   - VerifyCertificate，func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error，一个函数，用来检验证书的合法性。
//
//   - ServerRootCAs，[][]byte，客户端利用它核验服务端的身份。
//
//   - RequireClientCert，bool，用于指示在 TLS 通信中，客户端是否需要出示证书用于身份验证。
//
//     如果 RequireClientCert 为 true
//
//     >> Key，[]byte，客户端的私钥，与 Certificate 一同构造客户端的 TLS 证书。
//
//     >> Certificate，[]byte，客户端的 x509 证书，与 Key 一同构造客户端的 TLS 证书。
//
//   - TimeShift，time.Duration，用来保持客户端与服务端之间的时间同步。
func (so SecureOptions) TLSConfig() (*tls.Config, error) {
	if !so.UseTLS {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		MinVersion:            tls.VersionTLS12,
		ServerName:            so.ServerNameOverride,
		VerifyPeerCertificate: so.VerifyCertificate,
	}
	if len(so.ServerRootCAs) > 0 {
		tlsConfig.RootCAs = x509.NewCertPool()
		for _, certBytes := range so.ServerRootCAs {
			if !tlsConfig.RootCAs.AppendCertsFromPEM(certBytes) {
				var certStr string
				if len(certBytes) > 32 {
					certStr = hex.EncodeToString(certBytes[:32])
				} else {
					certStr = hex.EncodeToString(certBytes)
				}
				return nil, errors.NewErrorf("failed adding server root certificate \"%s\"...", certStr)
			}
		}
	}

	if so.RequireClientCert {
		cert, err := so.ClientTLSCertificate()
		if err != nil {
			return nil, errors.NewErrorf("failed loading client tls certificate, the error is \"%s\"", err.Error())
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}

	if so.TimeShift > 0 {
		tlsConfig.Time = func() time.Time {
			return time.Now().Add((-1) * so.TimeShift)
		}
	}

	return tlsConfig, nil
}

func (so SecureOptions) ClientTLSCertificate() (tls.Certificate, error) {
	if so.Key == nil || so.Certificate == nil {
		return tls.Certificate{}, errors.NewError("both key and certificate are required when using mutual TLS")
	}
	cert, err := tls.X509KeyPair(so.Certificate, so.Key)
	if err != nil {
		return tls.Certificate{}, errors.NewErrorf("failed creating tls key pair, the error is \"%s\"", err.Error())
	}
	return cert, nil
}

/* ------------------------------------------------------------------------------------------ */

type ClientConfig struct {
	// SecOpts 客户端的 TLS 安全参数。
	SecOpts SecureOptions
	// KaOpts 客户端侧的保持连接活跃性的选项参数。
	KaOpts KeepaliveOptions
	// DialTimeout 客户端与服务端建立连接的等待超时时间。
	DialTimeout time.Duration
	// AsyncConnect 以非阻塞的形式与服务端建立连接的选项。
	AsyncConnect bool
	// MaxRecvMsgSize 设置客户端可以接收的最大消息大小(以字节为单位)。如果没有设置，使用默认的 100MB。
	MaxRecvMsgSize int
	// MaxSendMsgSize 设置客户端可以发送的最大消息大小(以字节为单位)。如果没有设置，使用默认的 100MB。
	MaxSendMsgSize int
}

func (cc ClientConfig) DialOptions() ([]grpc.DialOption, error) {
	var dialOptions []grpc.DialOption
	dialOptions = append(dialOptions, cc.KaOpts.ClientKeepaliveOptions()...)

	// 如果客户端不同意以异步的方式与服务端建立连接，那么在建立连接时，就要施加阻塞选项
	if !cc.AsyncConnect {
		dialOptions = append(dialOptions,
			grpc.WithBlock(),
			grpc.FailOnNonTempDialError(true), // FailOnNonTempDialError 需要与 WithBlock 搭配使用，设置此选项后，如果拨号失败，则不会尝试重新拨号
		)
	}

	if cc.MaxRecvMsgSize != 0 {
		dialOptions = append(dialOptions, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(cc.MaxRecvMsgSize)))
	} else {
		dialOptions = append(dialOptions, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(DefaultMaxRecvMsgSize)))
	}

	if cc.MaxSendMsgSize != 0 {
		dialOptions = append(dialOptions, grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(cc.MaxSendMsgSize)))
	} else {
		dialOptions = append(dialOptions, grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(DefaultMaxSendMsgSize)))
	}

	tlsConfig, err := cc.SecOpts.TLSConfig()
	if err != nil {
		return nil, err
	}

	if tlsConfig != nil {
		transaportCredentials := &ClientCredentials{TLSConfig: tlsConfig}
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(transaportCredentials))
	} else {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	return dialOptions, nil
}

/* ------------------------------------------------------------------------------------------ */

type ServerConfig struct {
	// ConnectionTimeout 定义了建立新连接的超时时间，默认为 5 秒。
	ConnectionTimeout time.Duration
	// SecOpts 定义了 grpc 服务的安全参数。
	SecOpts SecureOptions
	// KaOpts 定义了服务端与客户端之间连接保活的参数。
	KaOpts KeepaliveOptions
	// StreamInterceptors 提供了若干个钩子来拦截流 RPC 在服务器上的执行。
	StreamInterceptors []grpc.StreamServerInterceptor
	// UnaryInterceptors 提供了若干个钩子来拦截服务器上一元 RPC 的执行。
	UnaryInterceptors []grpc.UnaryServerInterceptor
	// HealthCheckEnabled 开启对 grpc 服务的健康检查。
	HealthCheckEnabled bool
	// ServerStatsHandler 用于检测报告 grpc 服务的状态。
	ServerStatsHandler *ServerStatsHandler
	// MaxRecvMsgSize 设置服务端可以接收的最大消息大小(以字节为单位)。如果没有设置，使用默认的 100MB。
	MaxRecvMsgSize int
	// MaxSendMsgSize 设置服务端可以发送的最大消息大小(以字节为单位)。如果没有设置，使用默认的 100MB。
	MaxSendMsgSize int
}
