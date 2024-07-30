package algo

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/utils"
)

/*
	1. 启动者向一组远程对等节点发送带有特定 NONCE 的 Hello 消息；
	2. 每个远程对等节点响应其消息的摘要并返回该 NONCE；
	3. 启动者检查接收到的 NONCE 的有效性，聚合摘要，并创建一个包含要从每个远程对等节点接收的特定项目 ID 的请求，然后将每个请求发送给对应的对等节点；
	4. 每个对等节点返回包含被请求的项目（如果它仍然拥有这些项目）和 NONCE 的响应。

	发起者                                                        其他 peer
	  o     ------------------ Hello <NONCE> ------------------>      o
	 /|\    <----------- Digest <[3,5,8,...], NONCE> -----------     /|\
	  |     --------------- Request <[3,8], NONCE> ------------>      |
	 / \    <-------- Response <[item3,item8], NONCE> ----------     / \
*/

/*
一开始，启动者向一组远程 peer 节点发送 hello 消息（针对不同的 peer 节点，启动者会在 hello 消息中放置不同的 nonce），接着启动者会设置一个等待 digest 消息的超时时间，这个
超时时间一到，启动者就会处理在超时时间内收到的 digests，然后构造 request 消息，向其他 peer 节点发送 request 消息，默认情况下，等待 digest 消息的超时时间是 1 秒。

收到 hello 消息的 peer 节点，会将 nonce 值暂存在本地，然后设置等待 request 消息的超时时间，这个超时时间一过，peer 节点就会将暂存在本地的 nonce 给删除掉，一旦删除掉，后续，
启动者如果再基于该 nonce 向 peer 节点发送 request 消息，则会被 peer 节点忽视。默认情况下，peer 节点设置的等待 request 消息的超时时间是 1.5 秒。接着 peer 节点会将存储在
本地状态机中的值逐一取出，在这里我们把这些值看成是 digest，hello 消息中不仅包含 nonce，其实还包含一个 context，一般情况下，context 代表发送 hello 消息的发送者地址（或姓名），
即启动者的地址（或姓名），peer 节点利用摘要过滤器 DigestFilter，逐一过滤存储在本地状态机中的 digest。注意观察摘要过滤器的定义，我们可以发现，摘要过滤器它是一个返回值是函数的
函数，我们将 DigestFilter 视为母函数，DigestFilter 的返回值视为子函数，母函数的入参是 interface{}，参数名就叫 context，因此，我们不难猜出母函数返回的子函数应当与 hello 消
息中包含的 context 相关，也就是与启动者相关，而子函数的入参是摘要值，所以摘要过滤器会将哪些摘要值过滤出来可能取决于启动者的身份。

收到 digest 消息的启动者，会将 digest 逐一存储到本地，并建立 digest 与发送者之间的联系，即启动者需要知道每个 digest 是由哪些 peer 节点发送的，之所以是 “哪些”，是因为不同的
peer 节点可能会发送相同的 digest。当等待 digest 的超时时间一过，则启动者会根据在超时时间内收到的 digest 构建一个 request 消息，并且此时启动者将不会再接收新的 digest 消息。、
request 构造规则可以通过举一个例子来说明：例如有两个 peer 节点：p1 和 p2，p1 给启动者发送的 digests 是 [1 2 3]，p2 给启动者发送的 digests 是 [2 4 3]，那么启动者收到的
digests 经过去重处理后是 [1 2 3 4]，digest 与发送者之间的联系如下：

	1 => {p1}
	2 => {p1, p2}
	3 => {p1, p2}
	4 => {p2}

启动者会随机构造 2 个 request 消息，它首先遍历 [1 2 3 4]，首先是 1 这个 digest，它仅由 p1 发送，所以启动者构造 req1{[1], p1}；接着遍历到 2，它由 p1 和 p2 发送，启动者从 p1
和p2 中随机选一个，例如选到 p1，那么启动者更新 req1{[1, 2], p1}；接着遍历到 3，它由 p1 和 p2 发送，启动者从 p1 和 p2 中随机选一个，例如选到 p2，那么启动者构造 req2{[3], p1}；
最后遍历到 4，它仅由 p2 发送，因此，启动者更新 req2{[3, 4], p2}。启动者分别将 req1 和 req2 发送给 p1 和 p2，并进入等待 response 消息的超时时间内，一旦超时时间一过，则启动者会
结束本次 pull 进程。

收到 request 消息的 peer 节点，会解析 request 消息，得到其中的 digests，然后逐一提取其中的 digest，并判断本地状态机中是否有存储该 digest，其次还会根据摘要过滤器 DigestFilter
判断此 digest 能不能发送给启动者，如果本地状态机存有该 digest 且过滤器判断结果是可以发送，那么 peer 节点就会构造 response 消息，将能发送的 digest（item）发送给启动者。

收到 response 消息的启动者，会将 response 消息中的 items 存储到本地状态机中。

从上面的过程可以看出，DigestWaitTime 必须小于 RequestWaitTime，如果 DigestWaitTime 大于或等于 RequestWaitTime，那么 peer 节点会率先因为超时（RequestWaitTime）将暂存
在本地的 nonce 删除掉。之后启动者才因为超时（DigestWaitTime）向 peer 节点发送 request 消息，这样的话就已经迟了，peer 节点会因为在本地找不到 request 消息中的 nonce 而忽
视掉启动者发送来的 request。而 ResponseWaitTime 的大小则与 DigestWaitTime 和 RequestWaitTime 无关，它主要取决于网络质量的好坏。
*/
const (
	DefaultDigestWaitTime   = 1000 * time.Millisecond
	DefaultRequestWaitTime  = 1500 * time.Millisecond
	DefaultResponseWaitTime = 2000 * time.Millisecond
)

// DigestFilter 根据 context 上下文信息返回一个 digest 过滤器。
type DigestFilter func(context any) func(digestItem string) bool

type PullAdapter interface {
	SelectPeers() []string

	Hello(dest string, nonce uint64)

	SendDigest(digests []string, nonce uint64, context any)

	SendReq(dest string, items []string, nonce uint64)

	SendRes(items []string, nonce uint64, context any)
}

type PullEngine interface {
	OnHello(nonce uint64, context any)

	OnDigests(digests []string, nonce uint64, context any)

	OnReq(items []string, nonce uint64, context any)

	OnRes(items []string, nonce uint64)

	Add(items ...string)

	Remove(items ...string)

	Stop()
}

type pullEngineImpl struct {
	adapter            PullAdapter
	stopFlag           int32 // 1 表示停止
	state              *utils.Set
	item2owners        map[string][]string
	peers2nonces       map[string]uint64
	nonces2peers       map[uint64]string
	acceptingDigests   int32 // 1 表示正在等待接收 digests，0 表示忽略到来的 digests
	acceptingResponses int32 // 1 表示正在等待接收 responses
	mutex              *sync.Mutex
	outgoingNonces     *utils.Set
	incomingNonces     *utils.Set
	digFilter          DigestFilter
	logger             mlog.Logger
	digestWaitTime     time.Duration
	requestWaitTime    time.Duration
	responseWaitTime   time.Duration
}

type Config struct {
	// DigestWaitTime 给所有 peer 节点发送过 hello 消息后，默认等待 DigestWaitTime 这段时间，就去处理其他 peer 节点返回来的 digests。
	DigestWaitTime time.Duration
	// RequestWaitTime 给其他节点发送过 digests 消息后，会等待 RequestWaitTime 时间，在此时间内，接收其他节点的 request 消息，超过此时间后，就不再接收 request 消息。
	RequestWaitTime time.Duration
	// ResponseWaitTime 发送完 request 消息后，等待 ResponseWaitTime 时间，在此时间内，接收其他节点发送来的 response 消息，超过此时间，则忽略后面到来的 response 消息。
	ResponseWaitTime time.Duration
}

func NewPullEngineWithFilter(adapter PullAdapter, sleepTime time.Duration, dFilter DigestFilter, config Config, logger mlog.Logger) PullEngine {
	engine := &pullEngineImpl{
		adapter:            adapter,
		stopFlag:           0,
		state:              utils.NewSet(),
		item2owners:        make(map[string][]string),
		peers2nonces:       make(map[string]uint64),
		nonces2peers:       make(map[uint64]string),
		acceptingDigests:   0,
		acceptingResponses: 0,
		mutex:              &sync.Mutex{},
		outgoingNonces:     utils.NewSet(),
		incomingNonces:     utils.NewSet(),
		digFilter:          dFilter,
		digestWaitTime:     config.DigestWaitTime,
		requestWaitTime:    config.RequestWaitTime,
		responseWaitTime:   config.ResponseWaitTime,
		logger:             logger,
	}

	go func() {
		for !engine.isStopped() {
			time.Sleep(sleepTime)
			if engine.isStopped() {
				return
			}
			engine.initiatePull()
		}
	}()

	return engine
}

func NewPullEngine(adapter PullAdapter, sleepTime time.Duration, config Config, logger mlog.Logger) PullEngine {
	var dFilter DigestFilter = func(context any) func(digestItem string) bool {
		return func(digestItem string) bool {
			return true
		}
	}

	return NewPullEngineWithFilter(adapter, sleepTime, dFilter, config, logger)
}

// OnHello initiator 给其他 peer 节点发送 hello 消息后，其他节点凭借 OnHello 方法处理到来的 hello 消息。
func (pe *pullEngineImpl) OnHello(nonce uint64, context any) {
	pe.incomingNonces.Add(nonce)
	time.AfterFunc(pe.requestWaitTime, func() {
		pe.incomingNonces.Remove(nonce)
	})

	slice := pe.state.ToArray()
	var digests []string
	filter := pe.digFilter(context)
	for _, item := range slice {
		digest := item.(string)
		if !filter(digest) {
			continue
		}
		digests = append(digests, digest)
	}
	if len(digests) == 0 {
		return
	}
	pe.adapter.SendDigest(digests, nonce, context)
}

// OnDigests initiator 发送完 hello 消息给其他 peer 节点后，其他 peer 节点就会立马发送 digests 给 initiator。
func (pe *pullEngineImpl) OnDigests(digests []string, nonce uint64, context any) {
	if !pe.isAcceptingDigests() || !pe.outgoingNonces.Exists(nonce) {
		// 如果 initiator 现在正在处理已经收到的 digests 的话，或者没有给发送 digests 的 peer 节点发送过 hello 消息的话，
		// 那么对于到来的 digests 则会直接忽略掉。
		return
	}

	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	for _, digest := range digests {
		if pe.state.Exists(digest) {
			continue
		}
		// 将所有拥有此 digest 的 peer 节点放一起
		if _, exists := pe.item2owners[digest]; !exists {
			pe.item2owners[digest] = make([]string, 0)
		}
		pe.item2owners[digest] = append(pe.item2owners[digest], pe.nonces2peers[nonce])
	}
}

// OnReq initiator 在收到其他 peer 节点发送来的 digests 后，会向其他节点发送 request 消息，
// OnReq 方法就是用来处理收到的 request 消息。
func (pe *pullEngineImpl) OnReq(items []string, nonce uint64, context any) {
	if !pe.incomingNonces.Exists(nonce) {
		return
	}
	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	filter := pe.digFilter(context)
	var items2send []string
	for _, item := range items {
		if pe.state.Exists(item) && filter(item) {
			items2send = append(items2send, item)
		}
	}

	if len(items2send) == 0 {
		return
	}

	go pe.adapter.SendRes(items2send, nonce, context)
}

func (pe *pullEngineImpl) OnRes(items []string, nonce uint64) {
	if !pe.outgoingNonces.Exists(nonce) || !pe.isAcceptingResponses() {
		return
	}
	pe.Add(items...)
}

func (pe *pullEngineImpl) Add(items ...string) {
	for _, item := range items {
		pe.state.Add(item)
	}
}

func (pe *pullEngineImpl) Remove(items ...string) {
	for _, item := range items {
		pe.state.Remove(item)
	}
}

func (pe *pullEngineImpl) Stop() {
	atomic.StoreInt32(&pe.stopFlag, 1)
}

/* ------------------------------------------------------------------------------------------ */

func (pe *pullEngineImpl) isStopped() bool {
	return atomic.LoadInt32(&pe.stopFlag) == int32(1)
}

// acceptResponses 让自己进入能够接收 responses 的状态里。
func (pe *pullEngineImpl) acceptResponse() {
	atomic.StoreInt32(&pe.acceptingResponses, 1)
}

func (pe *pullEngineImpl) isAcceptingResponses() bool {
	return atomic.LoadInt32(&pe.acceptingResponses) == int32(1)
}

func (pe *pullEngineImpl) ignoreResponses() {
	atomic.StoreInt32(&pe.acceptingResponses, 0)
}

// acceptDigests 让自己进入能够接收 digests 的状态里。
func (pe *pullEngineImpl) acceptDigests() {
	atomic.StoreInt32(&pe.acceptingDigests, 1)
}

func (pe *pullEngineImpl) isAcceptingDigests() bool {
	return atomic.LoadInt32(&pe.acceptingDigests) == int32(1)
}

func (pe *pullEngineImpl) ignoreDigests() {
	atomic.StoreInt32(&pe.acceptingDigests, 0)
}

func (pe *pullEngineImpl) newNonce() uint64 {
	n := uint64(0)
	for {
		n = utils.RandomUint64()
		if !pe.outgoingNonces.Exists(n) {
			// 绝不发送已经用过的 nonce
			return n
		}
	}
}

func (pe *pullEngineImpl) initiatePull() {
	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	pe.acceptDigests() // 进入接收 digests 的状态
	for _, peer := range pe.adapter.SelectPeers() {
		nonce := pe.newNonce() // 针对不同的 peer 节点生成不同的 nonce
		pe.outgoingNonces.Add(nonce)
		pe.nonces2peers[nonce] = peer // 标记一下此 nonce 发送给了哪个 peer 节点
		pe.peers2nonces[peer] = nonce // 标记一下目前给此 peer 节点发送的 nonce
		pe.adapter.Hello(peer, nonce)
	}

	// 给所有 peer 节点发送过 hello 消息后，默认等待 1 秒钟就去处理其他 peer 节点返回来的 digests
	time.AfterFunc(pe.digestWaitTime, pe.processIncomingDigests)
}

func (pe *pullEngineImpl) processIncomingDigests() {
	// 在处理已经到来的 digests 的时候，那么会忽略掉后续到来的 digests
	pe.ignoreDigests()

	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	requestMapping := make(map[string][]string) // peer => items
	// 遍历一遍自己所收到的所有 items，确保每个 item 都有一个与之对应的发送者
	for item, sources := range pe.item2owners {
		// 从发送 item 给自己的 peer 节点中随机选择一个 peer
		source := sources[utils.RandomIntn(len(sources))]
		if _, exists := requestMapping[source]; !exists {
			requestMapping[source] = make([]string, 0)
		}
		requestMapping[source] = append(requestMapping[source], item)
	}

	// 进入到接收 responses 的状态
	pe.acceptResponse()

	for dest, seqsToReq := range requestMapping {
		pe.adapter.SendReq(dest, seqsToReq, pe.peers2nonces[dest])
	}

	// 给相关 peer 节点发送过关于 items 的 request 消息后，默认等待 2 秒钟就不接收 response 消息了，
	// 也就是说，initiator 在发送完 request 消息后，peer 节点默认只有 2 秒钟时间发送 response 消息。
	time.AfterFunc(pe.responseWaitTime, pe.prepareNextPull)
}

func (pe *pullEngineImpl) prepareNextPull() {
	// 忽略接下来到来的 responses 消息
	pe.ignoreResponses()

	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	pe.outgoingNonces.Clear()
	pe.item2owners = make(map[string][]string)
	pe.peers2nonces = make(map[string]uint64)
	pe.nonces2peers = make(map[uint64]string)
}
