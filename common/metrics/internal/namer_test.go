package internal

import (
	"testing"

	"github.com/11090815/mayy/common/metrics"
	"github.com/stretchr/testify/require"
)

func TestCounterNamer(t *testing.T) {
	opts := metrics.CounterOpts{
		Namespace: "blockchain",
		Subsystem: "gossip",
		Name: "validation_block",
		StatsdFormat: "%{#fqname}%{channel}%{system}",
		LabelNames: []string{},
	}

	// panic
	namer := NewCounterNamer(opts)
	require.Panics(t, func() {
		namer.Format("channel", "0x123", "system", "linux")
	})

	// non panic
	opts = metrics.CounterOpts{
		Namespace: "blockchain",
		Subsystem: "gossip",
		Name: "validation_block",
		StatsdFormat: "%{#fqname}%{channel}%{system}",
		LabelNames: []string{"channel", "system"},
	}
	namer = NewCounterNamer(opts)
	format := namer.Format("channel", "0x123", "system", "linux")
	require.Equal(t, "blockchain.gossip.validation_block0x123linux", format)

	// replace .
	opts = metrics.CounterOpts{
		Namespace: "blockchain",
		Subsystem: "gossip",
		Name: "validation_block",
		StatsdFormat: "%{#fqname}%{channel}%{system}",
		LabelNames: []string{"channel", "system"},
	}
	namer = NewCounterNamer(opts)
	format = namer.Format("channel", "0x.123", "system", "l.i.n.u.x")
	require.Equal(t, "blockchain.gossip.validation_block0x_123l_i_n_u_x", format)

	// replace :
	opts = metrics.CounterOpts{
		Namespace: "blockchain",
		Subsystem: "gossip",
		Name: "validation_block",
		StatsdFormat: "%{#fqname}%{channel}%{system}",
		LabelNames: []string{"channel", "system"},
	}
	namer = NewCounterNamer(opts)
	format = namer.Format("channel", "0x.123", "system", "l:i:n:u:x")
	require.Equal(t, "blockchain.gossip.validation_block0x_123l_i_n_u_x", format)

	// replace |
	opts = metrics.CounterOpts{
		Namespace: "blockchain",
		Subsystem: "gossip",
		Name: "validation_block",
		StatsdFormat: "%{#fqname}%{channel}%{system}",
		LabelNames: []string{"channel", "system"},
	}
	namer = NewCounterNamer(opts)
	format = namer.Format("channel", "0x.123", "system", "l|i|n:u:x")
	require.Equal(t, "blockchain.gossip.validation_block0x_123l_i_n_u_x", format)

	// replace \s
	opts = metrics.CounterOpts{
		Namespace: "blockchain",
		Subsystem: "gossip",
		Name: "validation_block",
		StatsdFormat: "%{#fqname}%{channel}%{system}",
		LabelNames: []string{"channel", "system"},
	}
	namer = NewCounterNamer(opts)
	format = namer.Format("channel", "0x.123", "system", "l i  n:u:x")
	require.Equal(t, "blockchain.gossip.validation_block0x_123l_i__n_u_x", format)
}
