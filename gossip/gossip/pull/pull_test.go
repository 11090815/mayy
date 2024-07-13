package pull

import (
	"bytes"
	"time"

	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/gossip/gossip/comm"
	"github.com/11090815/mayy/gossip/utils"
	"github.com/11090815/mayy/protobuf/pgossip"
)

var (
	pullInterval    = 500 * time.Millisecond
	timeoutInterval = 20 * time.Second
)

type pullMsg struct {
	respondChan chan *pullMsg
	msg         *utils.SignedGossipMessage
}

func (msg *pullMsg) GetSourceEnvelope() *pgossip.Envelope {
	return msg.msg.Envelope
}

func (msg *pullMsg) Respond(m *pgossip.GossipMessage) {
	sgm, _ := utils.NoopSign(m)
	msg.respondChan <- &pullMsg{
		msg:         sgm,
		respondChan: msg.respondChan,
	}
}

func (msg *pullMsg) GetSignedGossipMessage() *utils.SignedGossipMessage {
	return msg.msg
}

func (msg *pullMsg) GetConnectionInfo() *utils.ConnectionInfo {
	return nil
}

func (msg *pullMsg) Ack(error) {}

type pullInstance struct {
	self          utils.NetworkMember
	mediator      PullMediator
	items         *utils.Set
	msgChan       chan *pullMsg
	peer2PullInst map[string]*pullInstance // endpoint => *pullInstance
	stopChan      chan struct{}
	pullAdapter   *PullAdapter
	config        PullConfig
}

func (p *pullInstance) Send(msg *utils.SignedGossipMessage, peers ...*comm.RemotePeer) {
	for _, peer := range peers {
		m := &pullMsg{
			msg:         msg,
			respondChan: p.msgChan,
		}
		p.peer2PullInst[peer.Endpoint].msgChan <- m
	}
}

func (p *pullInstance) GetMembership() utils.Members {
	members := []utils.NetworkMember{}
	for _, peer := range p.peer2PullInst {
		if bytes.Equal(peer.self.PKIid, p.self.PKIid) {
			continue
		}
		members = append(members, peer.self)
	}
	return members
}

func (p *pullInstance) start() {
	p.mediator = NewPullMediator(p.config, p.pullAdapter, utils.GetLogger(utils.PullLogger, p.self.Endpoint, mlog.DebugLevel, true, true))
	go func() {
		select {
		case <-p.stopChan:
			return
		case msg := <-p.msgChan:
			p.mediator.HandleMessage(msg)
		}
	}()
}
