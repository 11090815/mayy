package utils

import (
	"encoding/hex"
	"reflect"

	"google.golang.org/grpc"
)

type ChannelID []byte

func (id ChannelID) String() string {
	return hex.EncodeToString(id)
}

/* ------------------------------------------------------------------------------------------ */

// Payload 用来存储一个一个区块。
type Payload struct {
	ChannelID ChannelID
	Data      []byte
	Hash      string
	SeqNum    uint64 // SeqNum 是区块的序号。
}

/* ------------------------------------------------------------------------------------------ */

type InfluenceResult int

const (
	MessageNoAction InfluenceResult = iota
	// MessageInvalidates 表示当前消息让另一个消息无效。
	MessageInvalidates
	// MessageInvalidated 表示另一个消息让当前消息无效。
	MessageInvalidated
)

// MessageReplacingPolicy 是一个函数类型，此类函数用于比较两个消息之间是如何影响的：
//  1. 如果返回的结果是 MessageNoAction，则表明两个消息之间互不影响；
//  2. 如果返回的结果是 MessageInvalidates，则表示当前消息让另一个消息无效了；
//  3. 如果返回的结果是 MessageInvalidated，则表示另一个消息让当前消息无效了。
type MessageReplacingPolicy func(this, that any) InfluenceResult

/* ------------------------------------------------------------------------------------------ */

// MessageAcceptor 是一个谓词，用于确定创建 MessageAcceptor 的订阅者对哪些消息感兴趣。
type MessageAcceptor func(any) bool

/* ------------------------------------------------------------------------------------------ */

// PeerSecureDialOpts 返回 gRPC 拨号的安全选项。
type PeerSecureDialOpts func() []grpc.DialOption

// PeerSuspector 检测 peer 的身份证书或者其上的 CA 证书是否被撤销。
type PeerSuspector func(identity PeerIdentityType) bool

/* ------------------------------------------------------------------------------------------ */

// Equals 判断 a 和 b 是否相同。
type Equals func(a, b any) bool

/* ------------------------------------------------------------------------------------------ */

// IndexInSlice 给定一个数组 array 和一个可能存在于 array 中的一个元素 o，
// 返回 o 在 array 中的索引位置。
func IndexInSlice(array any, o any, equals Equals) int {
	arr := reflect.ValueOf(array)
	for i := 0; i < arr.Len(); i++ {
		if equals(arr.Index(i).Interface(), o) {
			return i
		}
	}
	return -1
}
