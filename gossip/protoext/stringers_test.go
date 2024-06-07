package protoext

import (
	"testing"

	"github.com/11090815/mayy/protobuf/pgossip"
)

func TestHello(t *testing.T) {
	hello := &pgossip.GossipHello{Nonce: 234, Metadata: []byte("hello")}
	t.Log(hello.String())
}
