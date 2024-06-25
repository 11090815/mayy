package metrics

import "github.com/11090815/mayy/common/metrics"

type GossipMetrics struct {
	CommMetrics *CommMetrics
}

func NewGossipMetrics(p metrics.Provider) *GossipMetrics {
	return &GossipMetrics{
		CommMetrics: newCommMetrics(p),
	}
}

/* ------------------------------------------------------------------------------------------ */

type CommMetrics struct {
	SentMessages     metrics.Counter
	BufferOverflow   metrics.Counter
	ReceivedMessages metrics.Counter
}

var (
	SentMessagesOpts = metrics.CounterOpts{
		Namespace:    "gossip",
		Subsystem:    "comm",
		Name:         "messages_sent",
		Help:         "Number of messages sent",
		StatsdFormat: "%{#fqname}",
	}

	BufferOverflowOpts = metrics.CounterOpts{
		Namespace:    "gossip",
		Subsystem:    "comm",
		Name:         "overflow_count",
		Help:         "Number of outgoing queue buffer overflows",
		StatsdFormat: "%{fqname}",
	}

	ReceivedMessagesOpts = metrics.CounterOpts{
		Namespace:    "gossip",
		Subsystem:    "comm",
		Name:         "messages_received",
		Help:         "Number of messages received",
		StatsdFormat: "%{fqname}",
	}
)

func newCommMetrics(p metrics.Provider) *CommMetrics {
	return &CommMetrics{
		SentMessages:     p.NewCounter(SentMessagesOpts),
		BufferOverflow:   p.NewCounter(BufferOverflowOpts),
		ReceivedMessages: p.NewCounter(ReceivedMessagesOpts),
	}
}

/* ------------------------------------------------------------------------------------------ */

type PrivdataMetrics struct {
	ValidationDuration             metrics.Histogram
	ListMissingPrivateDataDuration metrics.Histogram
	FetchDuration                  metrics.Histogram
	CommitPrivateDataDuration      metrics.Histogram
	PurgeDuration                  metrics.Histogram
	SendDuration                   metrics.Histogram
	ReconciliationDuration         metrics.Histogram
	PullDuration                   metrics.Histogram
	RetrieveDuration               metrics.Histogram
}

var (
	ValidationDurationOpts = metrics.HistogramOpts{
		Namespace:    "gossip",
		Subsystem:    "privdata",
		Name:         "validation_duration",
		Help:         "Time it takes to validate a block (in seconds)",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}
)
