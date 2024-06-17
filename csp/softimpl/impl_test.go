package softimpl_test

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/11090815/mayy/csp"
	"github.com/11090815/mayy/csp/mocks"
	"github.com/11090815/mayy/csp/softimpl"
	"github.com/11090815/mayy/csp/softimpl/aes"
	"github.com/11090815/mayy/csp/softimpl/config"
	"github.com/11090815/mayy/csp/softimpl/ecdsa"
	"github.com/11090815/mayy/csp/softimpl/hash"
	"github.com/11090815/mayy/csp/softimpl/tlsca"
	"github.com/11090815/mayy/common/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestBasic(t *testing.T) {
	impl, err := softimpl.NewSoftCSPImpl(nil)
	require.Error(t, err)
	require.Nil(t, impl)

	ks := mocks.NewMockKeyStore()
	cfg := config.NewConfig()
	cfg.SetSecurityLevel(256, "SHA3")

	impl, err = softimpl.NewSoftCSPImpl(ks)
	require.NoError(t, err)
	require.NotNil(t, impl)

	// Signer & Verifier

	ecdsaKG384 := ecdsa.NewECDSAKeyGenerator(elliptic.P384())
	sk384, err := ecdsaKG384.KeyGen(nil)
	require.NoError(t, err)
	pk384, err := sk384.PublicKey()
	require.NoError(t, err)

	ecdsaKG256 := ecdsa.NewECDSAKeyGenerator(elliptic.P384())
	sk256, err := ecdsaKG256.KeyGen(nil)
	require.NoError(t, err)
	pk256, err := sk256.PublicKey()
	require.NoError(t, err)

	ks.StoreKey(sk256)
	ks.StoreKey(sk384)
	ks.StoreKey(pk256)
	ks.StoreKey(pk384)

	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(sk256), ecdsa.NewECDSASigner())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(sk384), ecdsa.NewECDSASigner())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(sk256), ecdsa.NewECDSAPrivateKeyVerifier())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(sk384), ecdsa.NewECDSAPrivateKeyVerifier())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(pk256), ecdsa.NewECDSAPublicKeyVerifier())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(pk384), ecdsa.NewECDSAPublicKeyVerifier())

	// Encrypter & Decrypter

	aesKG128 := aes.NewAESKeyGenerator(16)
	k128, err := aesKG128.KeyGen(nil)
	require.NoError(t, err)

	aesKG256 := aes.NewAESKeyGenerator(32)
	k256, err := aesKG256.KeyGen(nil)
	require.NoError(t, err)

	ks.StoreKey(k128)
	ks.StoreKey(k256)

	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(k128), aes.NewAESCBCPKCS7Encrypter())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(k256), aes.NewAESCBCPKCS7Encrypter())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(k128), aes.NewAESCBCPKCS7Decrypter())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(k256), aes.NewAESCBCPKCS7Decrypter())

	// Key Import

	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAGoPublicKeyImportOpts{}), ecdsa.NewECDSAGoPublicKeyImporter())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAX509PublicKeyImportOpts{}), ecdsa.NewECDSAX509PublicKeyImporter(impl.(*softimpl.SoftCSPImpl)))
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAPKIXPublicKeyImportOpts{}), ecdsa.NewECDSAPKIXPublicKeyImporter())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAPrivateKeyImportOpts{}), ecdsa.NewECDSAPrivateKeyImporter())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&aes.AESKeyImportOpts{}), aes.NewAESKeyImporter())

	// Key Deriv

	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(sk256), ecdsa.NewECDSAPrivateKeyDeriver())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(sk384), ecdsa.NewECDSAPrivateKeyDeriver())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(pk256), ecdsa.NewECDSAPublicKeyDeriver())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(pk384), ecdsa.NewECDSAPublicKeyDeriver())
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(k128), aes.NewAESKeyDeriver(cfg))

	// Key Gen

	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAP256KeyGenOpts{}), ecdsa.NewECDSAKeyGenerator(elliptic.P256()))
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&ecdsa.ECDSAP384KeyGenOpts{}), ecdsa.NewECDSAKeyGenerator(elliptic.P384()))
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&aes.AES128KeyGenOpts{}), aes.NewAESKeyGenerator(16))
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&aes.AES128KeyGenOpts{}), aes.NewAESKeyGenerator(32))

	// Hash
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&hash.SHA256Opts{}), hash.NewHasher(sha256.New))
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&hash.SHA384Opts{}), hash.NewHasher(sha512.New384))
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&hash.SHA3_256Opts{}), hash.NewHasher(sha3.New256))
	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&hash.SHA3_384Opts{}), hash.NewHasher(sha3.New384))

	msg := []byte("我是潜藏在印度的卧底")
	digest, err := impl.Hash(msg, &hash.SHA3_384Opts{})
	require.NoError(t, err)

	sig, err := impl.Sign(sk256, digest, nil)
	require.NoError(t, err)
	isValid, err := impl.Verify(pk256, sig, digest, nil)
	require.NoError(t, err)
	require.True(t, isValid)

	require.Equal(t, ks.(*mocks.MockKeyStore).Num(), 4)
	dsk384, err := impl.KeyDeriv(sk384, &ecdsa.ECDSAReRandKeyOpts{Expansion: []byte{1, 2, 3}, Temporary: false})
	require.NoError(t, err)
	require.Equal(t, ks.(*mocks.MockKeyStore).Num(), 5)

	sig, err = impl.Sign(dsk384, digest, nil)
	require.NoError(t, err)

	gettedDSK384, err := ks.GetKey(dsk384.SKI())
	require.NoError(t, err)
	isValid, err = impl.Verify(gettedDSK384, sig, digest, nil)
	require.NoError(t, err)
	require.True(t, isValid)

	digest, err = impl.Hash(msg, &hash.SHA3_256Opts{})
	require.NoError(t, err)
	fmt.Printf("%x\n", digest)

	digest, err = impl.Hash(msg, &hash.SHA384Opts{})
	require.NoError(t, err)
	fmt.Printf("%x\n", digest)

	digest, err = impl.Hash(msg, &hash.SHA256Opts{})
	require.NoError(t, err)
	fmt.Printf("%x\n", digest)

	digest, err = impl.Hash(msg, &hash.SHA3_384Opts{})
	require.NoError(t, err)
	fmt.Printf("%x\n", digest)

	ciphertext, err := impl.Encrypt(k128, msg, &aes.AESCBCPKCS7ModeOpts{})
	require.NoError(t, err)
	plaintext, err := impl.Decrypt(k128, ciphertext, &aes.AESCBCPKCS7ModeOpts{})
	require.NoError(t, err)
	require.Equal(t, msg, plaintext)
}

func TestTLSCA(t *testing.T) {
	errors.SetTrace()
	ks := mocks.NewMockKeyStore()
	impl, err := softimpl.NewSoftCSPImpl(ks)
	require.NoError(t, err)

	softimpl.RegisterWidget(impl.(*softimpl.SoftCSPImpl), reflect.TypeOf(&tlsca.TLSCAGenOpts{}), tlsca.NewTLSCAGenerator())

	ca, err := impl.CAGen(&tlsca.TLSCAGenOpts{Level: 256})
	require.NoError(t, err)

	srv := createTLSService(t, ca, "127.0.0.1")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go srv.Serve(listener)
	defer srv.Stop()
	defer listener.Close()

	// 构建客户端，传入的参数为客户端的证书密钥对，基于客户端的证书和CA的证书，
	// 尝试构建与server之间的连接
	probeTLS := func(kp csp.CertKeyPair) error {
		tlsCfg := &tls.Config{
			RootCAs:      x509.NewCertPool(),
			Certificates: []tls.Certificate{kp.TLSCert()}, // 提供客户端的证书给 server 去验证客户端的身份
		}
		tlsCfg.RootCAs.AppendCertsFromPEM(ca.CertBytes()) // 利用 CA 的证书验证 server 的证书
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

	clientKP, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)
	require.NoError(t, probeTLS(clientKP))

	otherCA, _ := impl.CAGen(&tlsca.TLSCAGenOpts{Level: 384})
	fmt.Println(string(otherCA.CertBytes()))
	fmt.Println(string(ca.CertBytes()))
	otherClientKP, err := otherCA.NewClientCertKeyPair()
	require.NoError(t, err)
	require.Error(t, probeTLS(otherClientKP))
}

func createTLSService(t *testing.T, ca csp.CA, host string) *grpc.Server {
	kp, err := ca.NewServerCertKeyPair(host)
	require.NoError(t, err)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{kp.TLSCert()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    x509.NewCertPool(),
	}
	tlsConf.ClientCAs.AppendCertsFromPEM(ca.CertBytes())
	return grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConf)))
}
