package election

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
	"github.com/stretchr/testify/mock"
)

const (
	testTimeout                       = 5 * time.Second
	testPollInterval                  = time.Millisecond * 300
	testStartupGracePeriod            = time.Millisecond * 500
	testMembershipSampleInterval      = time.Millisecond * 100
	testLeaderAliveThreshold          = time.Millisecond * 100
	testLeaderElectionDuration        = time.Millisecond * 500
	testLeadershipDeclarationInterval = testLeaderAliveThreshold / 2
)

type peer struct {
	mockedMethods map[string]struct{}
	mock.Mock
	id                 utils.PKIidType
	peers              map[string]*peer
	sharedLock         *sync.RWMutex
	msgChan            chan *leaderElecMsg
	leaderFromCallback bool
	callbackInvoked    bool
	lock               *sync.RWMutex
	LeaderElectionService
}

func (p *peer) On(methodName string, args ...any) *mock.Call {
	p.sharedLock.Lock()
	defer p.sharedLock.Unlock()
	p.mockedMethods[methodName] = struct{}{}
	return p.Mock.On(methodName, args...)
}

func (p *peer) Gossip(m *leaderElecMsg) {
	p.sharedLock.Lock()
	defer p.sharedLock.Unlock()

	if _, isMocked := p.mockedMethods["Gossip"]; isMocked {
		p.Called(m)
		return
	}

	for _, node := range p.peers {
		if bytes.Equal(node.id, p.id) {
			continue
		}
		node.msgChan <- m
	}
}

func (p *peer) Accept() <-chan *leaderElecMsg {
	p.sharedLock.Lock()
	defer p.sharedLock.Unlock()

	if _, isMocked := p.mockedMethods["Accept"]; isMocked {
		args := p.Mock.Called()
		return args.Get(0).(<-chan *leaderElecMsg)
	}
	return p.msgChan
}

func (p *peer) CreateMessage(isDeclaration bool) *leaderElecMsg {
	leadershipMsg := &pgossip.LeadershipMessage{
		PkiId:         p.id,
		IsDeclaration: isDeclaration,
	}

	return &leaderElecMsg{LeadershipMessage: leadershipMsg}
}

func (p *peer) Peers() []*utils.NetworkMember {
	p.sharedLock.Lock()
	defer p.sharedLock.Unlock()
	if _, isMocked := p.mockedMethods["Peers"]; isMocked {
		args := p.Mock.Called()
		return args.Get(0).([]*utils.NetworkMember)
	}

	var peers []*utils.NetworkMember
	for _, node := range p.peers {
		peers = append(peers, &utils.NetworkMember{PKIid: node.id})
	}
	return peers
}

func (p *peer) ReportMetrics(isLeader bool) {
	p.Mock.Called(isLeader)
}

func (p *peer) leaderCallback(isLeader bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.leaderFromCallback = isLeader
	p.callbackInvoked = true
}

/* ------------------------------------------------------------------------------------------ */

func createPeerWithCostumeMetrics(num int, peerMap map[string]*peer, sharedLock *sync.RWMutex, f func(mock.Arguments)) *peer {
	id := utils.PKIidType(fmt.Sprintf("peer%d", num))
	p := &peer{
		mockedMethods:      make(map[string]struct{}),
		id:                 id,
		peers:              peerMap,
		sharedLock:         sharedLock,
		msgChan:            make(chan *leaderElecMsg),
		leaderFromCallback: false,
		callbackInvoked:    false,
		lock:               &sync.RWMutex{},
	}
	p.On("ReportMetrics", mock.Anything).Run(f)
	config := ElectionConfig{
		StartupGracePeriod:       testStartupGracePeriod,
		MembershipSampleInterval: testMembershipSampleInterval,
		LeaderAliveThreshold:     testLeaderAliveThreshold,
		LeaderElectionDuration:   testLeaderElectionDuration,
	}
	p.LeaderElectionService = NewLeaderElectionService(p, id, p.leaderCallback, config, utils.GetLogger(utils.ElectionLogger, fmt.Sprintf("peer%d", num), mlog.DebugLevel, true, true))
	sharedLock.Lock()
	peerMap[id.String()] = p
	sharedLock.Unlock()

	return p
}
