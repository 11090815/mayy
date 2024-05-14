package comm_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/11090815/mayy/internal/pkg/comm"
	"github.com/stretchr/testify/require"
)

func TestCreds(t *testing.T) {
	caPEM, err := os.ReadFile(filepath.Join("testdata", "root1-cert.pem"))
	require.NoError(t, err)

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(caPEM) // 将根 CA 的证书放到证书池子里
	require.Truef(t, ok, "CA's certificate cannot be placed in the pool")
	serverTlsCert, err := tls.LoadX509KeyPair(filepath.Join("testdata", "root1-server-cert.pem"), filepath.Join("testdata", "root1-server-key.pem"))
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTlsCert},
		// ClientAuth: tls.RequireAndVerifyClientCert,
		// ClientCAs: certPool,
	}

	config := comm.NewTLSConfig(tlsConfig)
	serverCreds := comm.NewServerCredentials(config)
	_, _, err = serverCreds.ClientHandshake(context.Background(), "", nil)
	require.Error(t, err)

	listener, err := net.Listen("tcp", "192.168.189.128:2333")
	require.NoError(t, err)
	defer listener.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	t.Log("port:", port)
	require.NoError(t, err)
	address := net.JoinHostPort("192.168.189.128", port)

	handshake := func(wg *sync.WaitGroup) {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			t.Logf("failed accepting new connection: %s.", err)
		}
		_, _, err = serverCreds.ServerHandshake(conn)
		if err != nil {
			t.Logf("ServerHandshake failed: %s", err)
		}
	}

	// 成功的示例
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go handshake(wg)
	// clientCertificate, err := tls.LoadX509KeyPair(filepath.Join("testdata", "root1-client-cert.pem"), filepath.Join("testdata", "root1-client-key.pem"))
	// require.NoError(t, err)
	cfg := &tls.Config{RootCAs: certPool}
	_, err = tls.Dial("tcp", address, cfg)
	wg.Wait()
	require.NoError(t, err)

	// 失败的示例
	// wg = &sync.WaitGroup{}
	// wg.Add(1)
	// go handshake(wg)
	// _, err = tls.Dial("tcp", address, &tls.Config{RootCAs: certPool, MaxVersion: tls.VersionTLS10})
	// wg.Wait()
	// require.Error(t, err)
}
