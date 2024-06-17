package comm_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/common/errors"
	"github.com/11090815/mayy/internal/pkg/comm"
	"github.com/11090815/mayy/internal/pkg/comm/testpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	root1_sec1Cert        []byte
	root1_sec1Key         []byte
	root1_sec1_serverCert []byte
	root1_sec1_serverKey  []byte
	root1_sec1_clientCert []byte
	root1_sec1_clientKey  []byte
	badCert               []byte

	selfSignedCert []byte
	selfSignedKey  []byte

	testLogger  = mlog.GetLogger("test", mlog.DebugLevel, false)
	testTimeout = time.Second
)

func init() {
	root1_sec1_certFilePath := filepath.Join("testdata", "root1-sec1-cert.pem")
	root1_sec1_keyFilePath := filepath.Join("testdata", "root1-sec1-key.pem")
	root1_sec1_server_certFilePath := filepath.Join("testdata", "root1-sec1-server-cert.pem")
	root1_sec1_server_keyFilePath := filepath.Join("testdata", "root1-sec1-server-key.pem")
	root1_sec1_client_certFilePath := filepath.Join("testdata", "root1-sec1-client-cert.pem")
	root1_sec1_client_keyFilePath := filepath.Join("testdata", "root1-sec1-client-key.pem")
	selfSignedCertPath := filepath.Join("testdata", "root1-cert.pem")
	selfSignedKeyPath := filepath.Join("testdata", "root1-key.pem")

	root1_sec1Cert, _ = os.ReadFile(root1_sec1_certFilePath)
	root1_sec1Key, _ = os.ReadFile(root1_sec1_keyFilePath)
	root1_sec1_serverCert, _ = os.ReadFile(root1_sec1_server_certFilePath)
	root1_sec1_serverKey, _ = os.ReadFile(root1_sec1_server_keyFilePath)
	root1_sec1_clientCert, _ = os.ReadFile(root1_sec1_client_certFilePath)
	root1_sec1_clientKey, _ = os.ReadFile(root1_sec1_client_keyFilePath)
	selfSignedCert, _ = os.ReadFile(selfSignedCertPath)
	selfSignedKey, _ = os.ReadFile(selfSignedKeyPath)

	badCert = []byte(`-----BEGIN CERTIFICATE-----
	MIICCzCCAZKgAwIBAgIQWo+Q2aav1RQqXRIUx6Kc5DAKBggqhkjOPQQDAzAyMTAw
	LgYDVQQFEycxMjAzNzU5NTU5ODI0OTQxODAyMzI5NDg5OTI4Mjg5MjU3MTM2MzYw
	HhcNMjQwNTEzMDA0OTU3WhcNMzQwNTEyMDA0OTU3WjAyMTAwLgYDVQQFEycxMjAz
	NzU5NTU5ODI0OTQxODAyMzI5NDg5OTI4Mjg5MjU3MTM2MzYwdjAQBgcqhkjOPQIB
	BgUrgQQAIgNiAARQRWlCcF743YBfeZpBWI6hKtkJoscb8hIGL/qMw0zhiJmdhn+Y
	gRw/YlPM7Rx+jDQpj5dzdPCWxR5ZPQMPW+zbaRNPghtzEVY3QnHC85DDD9NhrFLl
	lDnAfQLvwSC11cCjbTBrMA4GA1UdDwEB/wQEAwIBpjAdBgNVHSUEFjAUBggrBgEF
	BQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zApBgNVHQ4EIgQgy2QtSNgu
	IZKBpuVYoB51QrbdvtmK/Al5aeV4Ll7RfQYwCgYIKoZIzj0EAwMDZwAwZAIwZWb4
	MSyIMHuZnlCA39Sf4jjm7O8z2I57RDY9Aa4Nexo6E6W0PocBjLWZoIJAC0ehAjA+
	h8MVVdozlhpJeuNa/sladG4k60YVip2hwc1Nb0G8On/57qD942qqpfUazSzrjtc
	-----END CERTIFICATE-----`)
}

type EmptyServiceServer struct{}

func (ess *EmptyServiceServer) EmptyCall(context.Context, *testpb.Empty) (*testpb.Empty, error) {
	testLogger.Debug("Server EmptyCall method is called.")
	return &testpb.Empty{}, nil
}

func (ess *EmptyServiceServer) EmptyStream(stream testpb.EmptyService_EmptyStreamServer) error {
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(&testpb.Empty{}); err != nil {
			return err
		}
		testLogger.Debug("Server EmptyStream is called, and send an Empty message to the other side.")
	}
}

func invokeEmptyCall(address string, dialOptions ...grpc.DialOption) (*testpb.Empty, error) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	clientConn, err := grpc.DialContext(ctx, address, dialOptions...)
	if err != nil {
		return nil, err
	}
	defer clientConn.Close()

	client := testpb.NewEmptyServiceClient(clientConn)

	return client.EmptyCall(context.Background(), new(testpb.Empty))
}

func invokeEmptyStream(address string, dialOptions ...grpc.DialOption) (*testpb.Empty, error) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	clientConn, err := grpc.DialContext(ctx, address, dialOptions...)
	if err != nil {
		return nil, err
	}
	defer clientConn.Close()

	client := testpb.NewEmptyServiceClient(clientConn)
	stream, err := client.EmptyStream(ctx)
	if err != nil {
		return nil, err
	}

	var streamErr error
	var msg *testpb.Empty
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		for {
			recv, err := stream.Recv()
			if err == io.EOF {
				wg.Done()
				return
			}
			if err != nil {
				streamErr = err
				wg.Done()
				return
			}
			msg = recv
		}
	}()

	err = stream.Send(new(testpb.Empty))
	if err != nil && err != io.EOF {
		return nil, errors.NewErrorf("stream send failed: %s", err)
	}

	stream.CloseSend()
	wg.Wait()
	return msg, streamErr
}

func TestNewGRPCServerInvalidParameters(t *testing.T) {
	// 不合法的网络监听地址
	_, err := comm.NewGRPCServer("", comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: false}})
	require.Error(t, err)
	t.Logf("error1 [%s]", err)

	_, err = comm.NewGRPCServer("localhost", comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: false}})
	require.Error(t, err)
	t.Logf("error2 [%s]", err)

	_, err = comm.NewGRPCServer("127.0.0.1", comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: false}})
	require.Error(t, err)
	t.Logf("error3 [%s]", err)

	_, err = comm.NewGRPCServer("127.0.0.1:abc", comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: false}})
	require.Error(t, err)
	t.Logf("error4 [%s]", err)

	_, err = comm.NewGRPCServer("a.b.c.d:2333", comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: false}})
	require.Error(t, err)
	t.Logf("error5 [%s]", err)

	// 不合规的 TLS 选项
	_, err = comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: true, Key: []byte{}}})
	require.Error(t, err)
	t.Logf("error6 [%s]", err)

	_, err = comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: true, Certificate: []byte{}}})
	require.Error(t, err)
	t.Logf("error7 [%s]", err)

	_, err = comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: true, Certificate: selfSignedCert, Key: []byte{}}})
	require.Error(t, err)
	t.Logf("error8 [%s]", err)

	_, err = comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: true, Certificate: []byte{}, Key: selfSignedKey}})
	require.Error(t, err)
	t.Logf("error9 [%s]", err)

	_, err = comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: true, Certificate: selfSignedCert, Key: selfSignedKey, RequireClientCert: true, ClientRootCAs: [][]byte{badCert}}})
	require.Error(t, err)
	t.Logf("error10 [%s]", err)
}

func TestNewGRPCServer(t *testing.T) {
	gServer, err := comm.NewGRPCServer("127.0.0.1:2333", comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: false}})
	require.NoError(t, err)

	testpb.RegisterEmptyServiceServer(gServer.Server(), &EmptyServiceServer{})
	go gServer.Start()
	defer gServer.Stop()

	_, err = invokeEmptyCall(gServer.Address(), []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock()}...)
	require.NoError(t, err)
}

func TestNewGRPCServerFromListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:2333")
	require.NoError(t, err)
	gServer, err := comm.NewGRPCServerFromListener(listener, comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: false}})
	require.NoError(t, err)

	testpb.RegisterEmptyServiceServer(gServer.Server(), &EmptyServiceServer{})
	go gServer.Start()
	defer gServer.Stop()

	_, err = invokeEmptyCall(gServer.Address(), []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock()}...)
	require.NoError(t, err)
}

func TestNewGRPCServerWithTLS(t *testing.T) {
	serverConfig := comm.ServerConfig{
		SecOpts: comm.SecureOptions{
			UseTLS:      true,
			Certificate: root1_sec1_serverCert,
			Key:         root1_sec1_serverKey,
		},
	}
	gServer, err := comm.NewGRPCServer("127.0.0.1:2333", serverConfig)
	require.NoError(t, err)

	tlsCert, _ := tls.X509KeyPair(root1_sec1_serverCert, root1_sec1_serverKey)
	require.Equal(t, tlsCert, gServer.GetServerCertificate())

	testpb.RegisterEmptyServiceServer(gServer.Server(), &EmptyServiceServer{})

	go gServer.Start()
	defer gServer.Stop()

	_, err = invokeEmptyCall(gServer.Address(), []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock()}...)
	require.Error(t, err)
	t.Logf("error1 [%s]", err)

	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(root1_sec1Cert)
	clientCreds := &comm.ClientCredentials{
		TLSConfig: &tls.Config{
			RootCAs: rootCAs,
		},
	}
	_, err = invokeEmptyCall(gServer.Address(), []grpc.DialOption{grpc.WithTransportCredentials(clientCreds), grpc.WithBlock()}...)
	require.NoError(t, err)
}

func TestVerifyCertificateCallback(t *testing.T) {
	verifyFunc := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		block, _ := pem.Decode(root1_sec1_clientCert)
		if !bytes.Equal(rawCerts[0], block.Bytes) {
			return errors.NewError("certificate mismatch")
		}
		return nil
	}

	probeTLS := func(endpoint string) error {
		cert, err := tls.X509KeyPair(root1_sec1_clientCert, root1_sec1_clientKey)
		if err != nil {
			return err
		}

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      x509.NewCertPool(),
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		}
		tlsCfg.RootCAs.AppendCertsFromPEM(root1_sec1Cert)

		conn, err := tls.Dial("tcp", endpoint, tlsCfg)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}

	gServer, err := comm.NewGRPCServer("127.0.0.1:2333", comm.ServerConfig{
		SecOpts: comm.SecureOptions{
			ClientRootCAs:     [][]byte{root1_sec1Cert},
			Key:               root1_sec1_serverKey,
			Certificate:       root1_sec1_serverCert,
			UseTLS:            true,
			VerifyCertificate: verifyFunc,
		},
	})
	require.NoError(t, err)

	go gServer.Start()
	defer gServer.Stop()

	require.NoError(t, probeTLS(gServer.Address()))
}

func TestWithSignedRootCertificates(t *testing.T) {
	gServer, err := comm.NewGRPCServer("127.0.0.1:2333", comm.ServerConfig{
		SecOpts: comm.SecureOptions{
			UseTLS: true,
			Certificate: root1_sec1_serverCert,
			Key: root1_sec1_serverKey,
		},
	})
	require.NoError(t, err)
	testpb.RegisterEmptyServiceServer(gServer.Server(), &EmptyServiceServer{})

	go gServer.Start()
	defer gServer.Stop()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(root1_sec1_serverCert)
	creds := credentials.NewClientTLSFromCert(certPool, "")
	_, err = invokeEmptyCall(gServer.Address(), grpc.WithTransportCredentials(creds))
	require.NoError(t, err)

	certPool = x509.NewCertPool()
	certPool.AppendCertsFromPEM(root1_sec1Cert)
	creds = credentials.NewClientTLSFromCert(certPool, "")
	_, err = invokeEmptyCall(gServer.Address(), grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
}
