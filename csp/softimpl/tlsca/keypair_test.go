package tlsca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/11090815/mayy/csp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestLoadCert(t *testing.T) {
	kp, err := newCertKeyPair(384, false, false, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, kp)

	key := kp.Key()
	// key[3] = byte('w')
	tlsCertPair, err := tls.X509KeyPair(kp.Cert(), key)
	require.NoError(t, err)
	require.NotNil(t, tlsCertPair)

	block, _ := pem.Decode(kp.Cert())
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func createTLSService(t *testing.T, ca *ca, host string) *grpc.Server {
	keyPair, err := ca.NewServerCertKeyPair(host)
	require.NoError(t, err)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{keyPair.TLSCert()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    x509.NewCertPool(),
	}
	tlsConf.ClientCAs.AppendCertsFromPEM(ca.CertBytes())
	return grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConf)))
}

func TestTLSCA(t *testing.T) {
	// This test checks that the CA can create certificates
	// and corresponding keys that are signed by itself

	ca, err := newCA(256)
	require.NoError(t, err)
	require.NotNil(t, ca)

	srv := createTLSService(t, ca, "127.0.0.1")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go srv.Serve(listener)
	defer srv.Stop()
	defer listener.Close()

	probeTLS := func(kp csp.CertKeyPair) error {
		tlsCfg := &tls.Config{
			RootCAs:      x509.NewCertPool(),
			Certificates: []tls.Certificate{kp.TLSCert()},
		}
		tlsCfg.RootCAs.AppendCertsFromPEM(ca.CertBytes())
		tlsOpts := grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := grpc.DialContext(ctx, listener.Addr().String(), tlsOpts, grpc.WithBlock())
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}

	// Good path - use a cert key pair generated from the CA
	// that the TLS server started with
	kp, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)
	err = probeTLS(kp)
	require.NoError(t, err)

	// Bad path - use a cert key pair generated from a foreign CA
	foreignCA, _ := newCA(256)
	kp, err = foreignCA.NewClientCertKeyPair()
	require.NoError(t, err)
	err = probeTLS(kp)
	require.Error(t, err)
	require.Contains(t, err.Error(), "context deadline exceeded")
}
