package utils

import (
	"reflect"
	"sync"
	"time"

	"github.com/11090815/mayy/csp/factory"
	"github.com/11090815/mayy/csp/softimpl/hash"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

type ChannelID []byte

func (id ChannelID) String() string {
	if len(id) == 0 {
		return "<nil>"
	}
	return string(id)
}

func StringToChannelID(idStr string) ChannelID {
	if idStr == "<nil>" {
		return ChannelID{}
	}
	return []byte(idStr)
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

type JoinChannelMessage interface {
	SequenceNumber() uint64
	Orgs() []OrgIdentityType
	AnchorPeersOf(OrgIdentityType) []AnchorPeer
}

/* ------------------------------------------------------------------------------------------ */

type AnchorPeer struct {
	Host string
	Port int
}

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

func Contains(a string, b []string) bool {
	for _, c := range b {
		if a == c {
			return true
		}
	}
	return false
}

// GetRandomIndices 随机获取区间 [0:highestIndex] 内 indiceCount 个整数。
func GetRandomIndices(indiceCount, highestIndex int) []int {
	if highestIndex+1 < indiceCount {
		return nil
	}
	return random.Perm(highestIndex + 1)[:indiceCount]
}

func BytesToStrings(bzs [][]byte) []string {
	strs := make([]string, len(bzs))
	for i, bz := range bzs {
		strs[i] = string(bz)
	}
	return strs
}

func StringsToBytes(strs []string) [][]byte {
	bzs := make([][]byte, len(strs))
	for i, str := range strs {
		bzs[i] = []byte(str)
	}
	return bzs
}

func GenerateMAC(pkiID PKIidType, channelID ChannelID) []byte {
	var bz []byte
	bz = append(bz, pkiID...)
	bz = append(bz, channelID...)
	csp, err := factory.GetCSP()
	if err != nil {
		panic(err)
	}
	hash, err := csp.Hash(bz, &hash.SHA256Opts{})
	if err != nil {
		panic(err)
	}
	return hash
}

/* ------------------------------------------------------------------------------------------ */

var viperLock sync.RWMutex

func GetIntOrDefault(key string, defVal int) int {
	viperLock.RLock()
	defer viperLock.RUnlock()
	if val := viper.GetInt(key); val != 0 {
		return val
	}
	return defVal
}

func GetDurationOrDefault(key string, defVal time.Duration) time.Duration {
	viperLock.RLock()
	defer viperLock.RUnlock()
	if val := viper.GetDuration(key); val != 0 {
		return val
	}
	return defVal
}

func GetBool(key string) bool {
	viperLock.RLock()
	defer viperLock.RUnlock()
	return viper.GetBool(key)
}

func GetString(key string) string {
	viperLock.RLock()
	defer viperLock.RUnlock()
	return viper.GetString(key)
}

func GetStringSliceOrDefault(key string, defVal []string) []string {
	viperLock.RLock()
	defer viperLock.RUnlock()
	if val := viper.GetStringSlice(key); val != nil {
		return val
	}
	return defVal
}
