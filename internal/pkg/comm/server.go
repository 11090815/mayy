package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/common/metrics"
	"github.com/11090815/mayy/errors"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/stats"
)

type GRPCServer struct {
	// address 服务端监听的地址，格式为 ip:port。
	address string
	// listener 用于监听新的连接。
	listener net.Listener
	// grpc 服务。
	server *grpc.Server
	// serverCertificate 构建 TLS 连接时，服务端用于向客户端展示的服务端证书。
	serverCertificate atomic.Value
	// mutex 保证读写的并发安全。
	mutex *sync.Mutex
	// config 服务端用来构建 grpc 服务的配置文件。
	config *TLSConfig
	// healthServer 用于检查 grpc 服务的健康状态。
	healthServer *health.Server
}

func NewGRPCServer(address string, serverConfig ServerConfig) (*GRPCServer, error) {
	if address == "" {
		return nil, errors.NewError("missing address parameter")
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, errors.NewErrorf("failed instantiating a grpc server, the error is \"%s\"", err)
	}
	return NewGRPCServerFromListener(listener, serverConfig)
}

func NewGRPCServerFromListener(listener net.Listener, serverConfig ServerConfig) (*GRPCServer, error) {
	gServer := &GRPCServer{
		address:  listener.Addr().String(),
		listener: listener,
		mutex:    &sync.Mutex{},
	}

	var serverOptions []grpc.ServerOption

	if serverConfig.SecOpts.UseTLS {
		// 服务端要求使用 TLS 建立安全连接
		if serverConfig.SecOpts.Key != nil && serverConfig.SecOpts.Certificate != nil {
			// 确定向客户端出示服务端证书的方式，并设置验证客户端证书的方法
			tlsCert, err := tls.X509KeyPair(serverConfig.SecOpts.Certificate, serverConfig.SecOpts.Key)
			if err != nil {
				listener.Close()
				return nil, err
			}
			gServer.serverCertificate.Store(tlsCert)
			getTLSCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				result := gServer.serverCertificate.Load().(tls.Certificate)
				return &result, nil
			}
			gServer.config = &TLSConfig{
				config: &tls.Config{
					ClientAuth:             tls.RequestClientCert,
					VerifyPeerCertificate:  serverConfig.SecOpts.VerifyCertificate,
					GetCertificate:         getTLSCert,
					SessionTicketsDisabled: true,
				},
			}

			// 设置加密套件
			if len(serverConfig.SecOpts.CipherSuites) == 0 {
				serverConfig.SecOpts.CipherSuites = DefaultTLSCipherSuites
			}

			// 为时间同步设置时间偏移量
			if serverConfig.SecOpts.TimeShift > 0 {
				gServer.config.config.Time = func() time.Time {
					return time.Now().Add((-1) * serverConfig.SecOpts.TimeShift)
				}
			}

			// 设置用于验证客户端证书的 CA 证书
			if serverConfig.SecOpts.RequireClientCert {
				gServer.config.config.ClientAuth = tls.RequireAndVerifyClientCert
				if len(serverConfig.SecOpts.ClientRootCAs) > 0 {
					gServer.config.config.ClientCAs = x509.NewCertPool()
					for _, clientRootCA := range serverConfig.SecOpts.ClientRootCAs {
						ok := gServer.config.config.ClientCAs.AppendCertsFromPEM(clientRootCA)
						if !ok {
							listener.Close()
							return nil, errors.NewError("failed add client root CA certificate")
						}
					}
				}
			}

			// 创建建立连接时的握手凭证
			creds := NewServerCredentials(gServer.config)
			serverOptions = append(serverOptions, grpc.Creds(creds))
		} else {
			listener.Close()
			return nil, errors.NewError("it must provide key and certificate for server when tls is enabled")
		}
	}

	if serverConfig.MaxSendMsgSize != 0 {
		serverOptions = append(serverOptions, grpc.MaxSendMsgSize(serverConfig.MaxRecvMsgSize))
	} else {
		serverOptions = append(serverOptions, grpc.MaxSendMsgSize(DefaultMaxSendMsgSize))
	}

	if serverConfig.MaxRecvMsgSize != 0 {
		serverOptions = append(serverOptions, grpc.MaxRecvMsgSize(serverConfig.MaxRecvMsgSize))
	} else {
		serverOptions = append(serverOptions, grpc.MaxRecvMsgSize(DefaultMaxRecvMsgSize))
	}

	// 设置保活选项
	serverOptions = append(serverOptions, serverConfig.KaOpts.ServerKeepaliveOptions()...)

	if serverConfig.ConnectionTimeout <= 0 {
		serverConfig.ConnectionTimeout = DefaultConnectionTimeout
	}
	serverOptions = append(serverOptions, grpc.ConnectionTimeout(serverConfig.ConnectionTimeout))

	if len(serverConfig.StreamInterceptors) > 0 {
		serverOptions = append(serverOptions, grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(serverConfig.StreamInterceptors...)))
	}

	if len(serverConfig.UnaryInterceptors) > 0 {
		serverOptions = append(serverOptions, grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(serverConfig.UnaryInterceptors...)))
	}

	if serverConfig.ServerStatsHandler != nil {
		serverOptions = append(serverOptions, grpc.StatsHandler(serverConfig.ServerStatsHandler))
	}

	gServer.server = grpc.NewServer(serverOptions...)

	if serverConfig.HealthCheckEnabled {
		gServer.healthServer = health.NewServer()
		healthpb.RegisterHealthServer(gServer.server, gServer.healthServer)
	}

	return gServer, nil
}

func (gServer *GRPCServer) SetServerCertificate(cert tls.Certificate) {
	gServer.serverCertificate.Store(cert)
}

func (gServer *GRPCServer) GetServerCertificate() tls.Certificate {
	return gServer.serverCertificate.Load().(tls.Certificate)
}

func (gServer *GRPCServer) Address() string {
	return gServer.address
}

func (gServer *GRPCServer) Listener() net.Listener {
	return gServer.listener
}

func (gServer *GRPCServer) Server() *grpc.Server {
	return gServer.server
}

func (gServer *GRPCServer) TLSEnabled() bool {
	return gServer.config != nil
}

func (gServer *GRPCServer) SetClientRootCAs(clientRootCAs [][]byte) error {
	gServer.mutex.Lock()
	defer gServer.mutex.Unlock()

	certPool := x509.NewCertPool()
	for _, clientRootCA := range clientRootCAs {
		if !certPool.AppendCertsFromPEM(clientRootCA) {
			return errors.NewError("failed appending client root CA from PEM")
		}
	}
	gServer.config.SetClientCAs(certPool)
	return nil
}

func (gServer *GRPCServer) RequireAndVerifyClientCert() bool {
	return gServer.config != nil || gServer.config.config.ClientAuth == tls.RequireAndVerifyClientCert
}

func (gServer *GRPCServer) Start() error {
	if gServer.healthServer != nil {
		for name := range gServer.server.GetServiceInfo() {
			gServer.healthServer.SetServingStatus(name, healthpb.HealthCheckResponse_SERVING)
		}
		gServer.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	}
	return gServer.server.Serve(gServer.listener)
}

func (gServer *GRPCServer) Stop() {
	gServer.server.Stop()
}

/* ------------------------------------------------------------------------------------------ */

type ServerStatsHandler struct {
	RunningConnCounter metrics.Counter
	ClosedConnCounter  metrics.Counter
}

func (ssh *ServerStatsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	l := tlsServerLogger.With("method", info.FullMethodName)
	l.Debugf("Tag RPC on method %s.", info.FullMethodName)
	return ctx
}

func (ssh *ServerStatsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {}

func (ssh *ServerStatsHandler) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	l := tlsServerLogger.With("local_address", info.LocalAddr.Network())
	l.Debugf("Tag connection %s.", info.RemoteAddr.Network())
	return ctx
}

func (ssh *ServerStatsHandler) HandleConn(ctx context.Context, s stats.ConnStats) {
	switch s.(type) {
	case *stats.ConnBegin:
		ssh.RunningConnCounter.Add(1)
	case *stats.ConnEnd:
		ssh.ClosedConnCounter.Add(1)
	}
}
