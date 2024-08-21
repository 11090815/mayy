package gossip

import (
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/11090815/mayy/csp/factory"
	"github.com/11090815/mayy/gossip/discovery"
)

var (
	timeout = time.Second * 180
	r       *rand.Rand
	aliveTimeInterval = 1000 * time.Millisecond
	discoveryConfig = discovery.Config{
		AliveTimeInterval: aliveTimeInterval,
		AliveExpirationTimeout: 10 * aliveTimeInterval,
	}
)

func TestMain(m *testing.M) {
	r = rand.New(rand.NewSource(time.Now().UnixNano()))
	factory.InitCSPFactoryWithOpts(&factory.FactoryOpts{
		Kind:          "sw",
		KeyStorePath:  "./keys",
		SecurityLevel: 384,
		HashFamily:    "SHA2",
		ReadOnly:      true,
	})
	os.Exit(m.Run())
}
