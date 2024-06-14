package comm

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/11090815/mayy/gossip/protoext"
	"github.com/11090815/mayy/gossip/utils"
)

type Comm interface {
	// GetPKIid 返回创建此 Comm 的节点的 ID。
	GetPKIid() utils.PKIidType

	Send(msg *protoext.SignedGossipMessage, peers ...*RemotePeer)

	// SendWithAck 发送消息给一群 peer 节点，并等待从这些节点处收回至少 minAck 个反馈，或者直到 timeout 超时时间超时。
	SendWithAck(msg *protoext.SignedGossipMessage, timeout time.Duration, minAck int, peers ...*RemotePeer) AggregatedSendResult

	// Probe 给一个 peer 节点发送一条消息，如果对方回应了则返回 nil，否则返回 error。
	Probe(peer *RemotePeer) error

	// Handshake 与一个 peer 节点进行握手，如果握手成功，则返回此 peer 节点的身份证书信息，否则返回 nil 和 error。
	Handshake(peer *RemotePeer) (utils.PeerIdentityType, error)

	// Accept 接收 Comm 的创建者感兴趣的消息，并将这些消息放于一个 read-only 通道中，然后返回此通道。
	Accept(utils.MessageAcceptor) <-chan protoext.ReceivedMessage

	// PreseumedDead 将可能已经离线的 peer 节点的 ID 放入到一个 read-only 通道里，然后返回此通道。
	PresumedDead() <-chan utils.PKIidType

	// IdentitySwitch 将身份发生改变的 peer 节点的 ID 放入到一个 read-only 通道里，然后返回此通道。
	IdentitySwitch() <-chan utils.PKIidType

	// CloseConn 关闭与某个特定 peer 节点之间的网络连接。
	CloseConn(peer *RemotePeer)

	Stop()
}

/* ------------------------------------------------------------------------------------------ */

type RemotePeer struct {
	Endpoint string
	PKIID    utils.PKIidType
}

func (rp *RemotePeer) String() string {
	return fmt.Sprintf("{RemotePeer | Endpoint: %s; PKI-ID: %s}", rp.Endpoint, rp.PKIID.String())
}

/* ------------------------------------------------------------------------------------------ */

type SendResult struct {
	result string
	RemotePeer
}

func (sr SendResult) Error() string {
	return sr.result
}

/* ------------------------------------------------------------------------------------------ */

type AggregatedSendResult []SendResult

// AckCount 返回响应成功的消息数。
func (asr AggregatedSendResult) AckCount() int {
	count := 0
	for _, ack := range asr {
		if ack.result == "" {
			count++
		}
	}
	return count
}

// NackCount 返回响应失败的消息数。
func (asr AggregatedSendResult) NackCount() int {
	return len(asr) - asr.AckCount()
}

func (asr AggregatedSendResult) String() string {
	errMap := make(map[string]int)
	for _, ack := range asr {
		if ack.result == "" {
			continue
		}
		errMap[ack.result]++
	}

	ackCount := asr.AckCount()
	output := map[string]any{}
	if ackCount > 0 {
		output["successes"] = ackCount
	}
	if ackCount < len(asr) {
		output["failures"] = errMap
	}
	bz, _ := json.Marshal(output)
	return string(bz)
}
