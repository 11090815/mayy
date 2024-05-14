package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/errors"
	"google.golang.org/grpc/credentials"
)

var (
	tlsClientLogger = mlog.GetLogger("comm.client.tls", mlog.DebugLevel, true)
	tlsServerLogger = mlog.GetLogger("comm.server.tls", mlog.DebugLevel, true)
)

type TLSConfig struct {
	config *tls.Config
	mutex  sync.RWMutex
}

func NewTLSConfig(config *tls.Config) *TLSConfig {
	return &TLSConfig{
		config: config,
	}
}

// Config 返回 tls.Config。
func (tc *TLSConfig) Config() tls.Config {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	if tc.config != nil {
		return *tc.config.Clone()
	}

	return tls.Config{}
}

func (tc *TLSConfig) AddClientRootCA(cert *x509.Certificate) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	tc.config.ClientCAs.AddCert(cert)
}

func (tc *TLSConfig) SetClientCAs(certPool *x509.CertPool) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.config.ClientCAs = certPool
}

/* ------------------------------------------------------------------------------------------ */

type ClientCredentials struct {
	TLSConfig *tls.Config
}

func (cc *ClientCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	l := tlsClientLogger.With("remote_address", rawConn.RemoteAddr().String())
	creds := credentials.NewTLS(cc.TLSConfig.Clone())
	start := time.Now()
	conn, auth, err := creds.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		l.Errorf("Client TLS handshake failed after %s with error: %s.", time.Since(start), err)
	} else {
		l.Debugf("Client TLS handshake completed in %s.", time.Since(start))
	}
	return conn, auth, nil
}

func (cc *ClientCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.NewError("client credentials do not implement server handshakes")
}

func (cc *ClientCredentials) Info() credentials.ProtocolInfo {
	return credentials.NewTLS(cc.TLSConfig.Clone()).Info()
}

// Clone 利用 TLS Config 创建一个 TransportCredentials。
func (cc *ClientCredentials) Clone() credentials.TransportCredentials {
	return credentials.NewTLS(cc.TLSConfig.Clone())
}

func (cc *ClientCredentials) OverrideServerName(name string) error {
	cc.TLSConfig.ServerName = name
	return nil
}

/* ------------------------------------------------------------------------------------------ */

type ServerCredentials struct {
	serverConfig *TLSConfig
}

func NewServerCredentials(config *TLSConfig) *ServerCredentials {
	// config.config.MaxVersion = tls.VersionTLS12
	return &ServerCredentials{serverConfig: config}
}

func (sc *ServerCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.NewError("server credentials do not implement client handshakes")
}

func (sc *ServerCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	tlsConfig := sc.serverConfig.Config()
	l := tlsServerLogger.With("remote_address", rawConn.RemoteAddr().String())
	start := time.Now()
	creds := credentials.NewTLS(&tlsConfig)
	conn, authInfo, err := creds.ServerHandshake(rawConn)
	if err != nil {
		l.Errorf("Server TLS handshake failed after %s with error: %s.", time.Since(start), err)
	} else {
		l.Debugf("Server TLS handshake completed in %s.", time.Since(start))
	}
	return conn, authInfo, nil
}

func (sc *ServerCredentials) Info() credentials.ProtocolInfo {
	return credentials.NewTLS(sc.serverConfig.config.Clone()).Info()
}

func (sc *ServerCredentials) Clone() credentials.TransportCredentials {
	return credentials.NewTLS(sc.serverConfig.config.Clone())
}

func (sc *ServerCredentials) OverrideServerName(string) error {
	return errors.NewError("Server does not support OverrideServerName")
}
