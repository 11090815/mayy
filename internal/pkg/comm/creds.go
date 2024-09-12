package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"time"

	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/common/mlog"
	"google.golang.org/grpc/credentials"
)

var (
	tlsClientLogger = mlog.GetLogger("comm.tls.client", mlog.DebugLevel, true)
	tlsServerLogger = mlog.GetLogger("comm.tls.server", mlog.DebugLevel, true)
	tlsCredsLogger  = mlog.GetLogger("comm.tls.creds", mlog.DebugLevel)
)

type TLSConfig struct {
	tlsConfig *tls.Config
	mutex     sync.RWMutex
}

func NewTLSConfig(config *tls.Config) *TLSConfig {
	return &TLSConfig{
		tlsConfig: config,
	}
}

// Config 返回 tls.Config。
func (tc *TLSConfig) Config() tls.Config {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	if tc.tlsConfig != nil {
		return *tc.tlsConfig.Clone()
	}

	return tls.Config{}
}

func (tc *TLSConfig) AddClientRootCA(cert *x509.Certificate) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	tc.tlsConfig.ClientCAs.AddCert(cert)
}

func (tc *TLSConfig) SetClientCAs(certPool *x509.CertPool) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.tlsConfig.ClientCAs = certPool
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
	}
	return conn, authInfo, nil
}

func (sc *ServerCredentials) Info() credentials.ProtocolInfo {
	return credentials.NewTLS(sc.serverConfig.tlsConfig.Clone()).Info()
}

func (sc *ServerCredentials) Clone() credentials.TransportCredentials {
	return credentials.NewTLS(sc.serverConfig.tlsConfig.Clone())
}

func (sc *ServerCredentials) OverrideServerName(string) error {
	return errors.NewError("Server does not support OverrideServerName")
}

/* ------------------------------------------------------------------------------------------ */

type CredentialSupport struct {
	mutex             sync.RWMutex
	appRootCAsByChain map[string][][]byte
	serverRootCAs     [][]byte
	clientCert        tls.Certificate
}

func NewCredentialSupport(rootCAs ...[]byte) *CredentialSupport {
	return &CredentialSupport{
		appRootCAsByChain: make(map[string][][]byte),
		serverRootCAs:     rootCAs,
	}
}

func (cs *CredentialSupport) SetClientCertificate(cert tls.Certificate) {
	cs.mutex.Lock()
	cs.clientCert = cert
	cs.mutex.Unlock()
}

func (cs *CredentialSupport) GetClientCertificate() tls.Certificate {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	return cs.clientCert
}

func (cs *CredentialSupport) GetPeerCredentials() credentials.TransportCredentials {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	var appRootCAs [][]byte
	appRootCAs = append(appRootCAs, cs.serverRootCAs...)
	for _, appRootCA := range cs.appRootCAsByChain {
		appRootCAs = append(appRootCAs, appRootCA...)
	}

	certPool := x509.NewCertPool()
	for _, apptRootCA := range appRootCAs {
		if !certPool.AppendCertsFromPEM(apptRootCA) {
			tlsCredsLogger.Warnf("Failed adding certificate %x to peer's client TLS trust pool.", apptRootCA)
		}
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cs.clientCert},
		RootCAs:      certPool,
	})
}

func (cs *CredentialSupport) AppRootCAsByChain() [][]byte {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	var appRootCAs [][]byte
	for _, appRootCAsByChain := range cs.appRootCAsByChain {
		appRootCAs = append(appRootCAs, appRootCAsByChain...)
	}

	return appRootCAs
}
