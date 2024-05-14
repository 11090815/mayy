# TLS 连接建立的过程

背景信息：

客户端与服务端的 IP 地址都是 192.168.189.128，客户端的端口号是 47352，服务端的端口号是 2333。

### 1. 第一步 —— 建立 TCP 连接

1. 客户端发送 SYN 标志位为 1 的 TCP 报文给服务端，报文中的 seq 字段由客户端选择一个随机整数确定，例如 1437936090。随后，客户端进入 SYN_SENT 阶段，等待服务端的确认。

| SYN=1 | seq=1437936090 |

2. 服务端收到客户端在上一步发送的报文后，对报文进行解析，获取其中的 seq 值，然后构造自己的 TCP 报文，让 SYN 和 ACK 标志位等于 1，接着为 seq 字段随机选一个随机值，例如 2387541446，然后让 ack 字段的值等于客户端发送来的报文的 seq 值加一，即 1437936091。随后，服务端进入 SYNC_RCVD 阶段，等待客户端的回应。

| SYN=1 | ACK=1 | seq=2387541446 | ack=1437936091 |

3. 客户端收到服务端发来的报文后，解析报文，获得其中的 seq 值，然后构造 TCP 报文，让 ACK 标志位等于 1，接着让 seq 等于自己在第 1 步为 seq 选择的随机数加一，即 1437936091，然后让 ack 等于服务端发送来的报文的 seq 值加一，即 2387541447。当然在这一步，客户端需要检查服务端发送来的报文中的 ack 是否等于 1437936091。然后，服务端需要检查客户端发送来的报文中的 seq 是否等于 1437936091，且 ack 是否等于 2387541447。

| ACK=1 | seq=1437936091 | ack=2387541447 |

### 2. 第二步 —— TLS 握手过程

1. 客户端发送 PSH 和 ACK 标志位为 1 的 TCP 报文给服务端，其中 seq=1437936091，ack=2387541447，然后在报文的数据帧部分，构造一个 ClientHello 消息，一个 ClientHello 消息包含以下内容（不仅限于以下内容）：

Random：f54e7407513d3addfb03d8223eb922ca8eb555414239d5d0f0b416455b741e7a 【用于协商对称密钥】
CipherSuites：Cipher Suites (19 suites)                                  【用于告诉服务端，客户端所支持的加密算法】
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
    Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
    Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
    Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
    Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
    Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
    Cipher Suite: TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)
    Cipher Suite: TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)
    Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
    Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
    Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)

服务端收到消息后，会回复一个 ACK 标志位为 1 的 TCP 报文给客户端，其中 seq=2387541447，ack=1437936330。

2. 服务端发送 PSH 和 ACK 标志位为 1 的 TCP 报文给客户端，其中 seq=2387541447，ack=1437936330，然后在报文的数据帧部分，构造一个 ServerHello 消息，ServerHello 消息包含但不限于以下内容：

Random：85bf0a8b8d87b3d09daaec637f2a0b389f9677c97c10ff6f85799afca4bb80be 【用于协商对称密钥】
CipherSuites：TLS_AES_128_GCM_SHA256 (0x1301)                            【用于告诉客户端，服务端所选用的加密算法】

3. 客户端发送 PSH 和 ACK 标志位为 1 的 TCP 报文给服务端，该报文包含一个 Change Cipher Spec 消息，表示客户端接下来要切换为另一种加密方案来传输数据，即使用对称加密来传输数据。