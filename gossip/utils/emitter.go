package utils

// BatchingEmitter 用于 gossip 推送/转发 阶段。消息被添加到 BatchingEmitter 中，它们被周期性地分批转发 T 次，
// 然后被丢弃。如果 BatchingEmitter 存储的消息计数达到一定容量，也会触发消息分派。
type BatchingEmitter interface {
	Add(any)
	Size() int
	Stop()
}

// EmittedGossipMessage 封装了签名的 gossip 消息，并在消息转发时使用路由过滤器
type EmittedGossipMessage struct {
	*SignedGossipMessage
	filter func(id PKIidType) bool
}

func (egm *EmittedGossipMessage) Filter(pkiID PKIidType) bool {
	return egm.filter(pkiID)
}

func NewEmittedGossipMessage(sgm *SignedGossipMessage, filter func(PKIidType) bool) *EmittedGossipMessage {
	return &EmittedGossipMessage{
		SignedGossipMessage: sgm,
		filter:              filter,
	}
}
