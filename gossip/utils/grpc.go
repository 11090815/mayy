package utils

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/csp/softimpl/tlsca"
	"github.com/11090815/mayy/internal/pkg/comm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	ca = createCAOrPanic()
)

// TLSCertificates 类型聚合了服务端和客户端的 TLS 证书。
type TLSCertificates struct {
	TLSServerCert atomic.Value
	TLSClientCert atomic.Value
}

// TODO Level 待定！
func createCAOrPanic() csp.CA {
	ca, err := tlsca.NewTLSCAGenerator().GenCA(&tlsca.TLSCAGenOpts{Level: 256})
	if err != nil {
		panic(err)
	}
	return ca
}

// CreateGRPCLayer certs 里存有 client 和 server 的 TLS 证书。client 和 server 的证书都是由 CA 生成的，secureDialOpts 是一个函数，
// 返回 client 的拨号凭证。
func CreateGRPCLayer() (port int, gRPCServer *comm.GRPCServer, certs *TLSCertificates, secureDialOpts PeerSecureDialOpts, dialOpts []grpc.DialOption) {
	serverKeyPair, err := ca.NewServerCertKeyPair("127.0.0.1", "localhost")
	if err != nil {
		panic(err)
	}
	clientKeyPair, err := ca.NewClientCertKeyPair()
	if err != nil {
		panic(err)
	}
	tlsServerCert, err := tls.X509KeyPair(serverKeyPair.Cert(), serverKeyPair.Key())
	if err != nil {
		panic(err)
	}
	tlsClientCert, err := tls.X509KeyPair(clientKeyPair.Cert(), clientKeyPair.Key())
	if err != nil {
		panic(err)
	}

	// 构建 client 的凭证。
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{tlsClientCert},
		ClientAuth:   tls.RequestClientCert,
		RootCAs:      x509.NewCertPool(),
	}
	tlsConf.RootCAs.AppendCertsFromPEM(ca.CertBytes())
	credential := credentials.NewTLS(tlsConf)
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(credential))
	secureDialOpts = func() []grpc.DialOption {
		return dialOpts
	}

	certs = &TLSCertificates{}
	certs.TLSServerCert.Store(&tlsServerCert)
	certs.TLSClientCert.Store(&tlsClientCert)

	serverConfig := comm.ServerConfig{
		ConnectionTimeout: time.Second,
		SecOpts: comm.SecureOptions{
			Key:         serverKeyPair.Key(),
			Certificate: serverKeyPair.Cert(),
			UseTLS:      true,
		},
	}
	gRPCServer, err = comm.NewGRPCServer("127.0.0.1", serverConfig)
	if err != nil {
		panic(err)
	}
	_, portStr, err := net.SplitHostPort(gRPCServer.Address())
	if err != nil {
		panic(err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		panic(err)
	}

	return port, gRPCServer, certs, secureDialOpts, dialOpts
}
