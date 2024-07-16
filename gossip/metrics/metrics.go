package metrics

import "github.com/11090815/mayy/common/metrics"

type GossipMetrics struct {
	CommMetrics       *CommMetrics
	ElectionMetrics   *ElectionMetrics
	MembershipMetrics *MembershipMetrics
}

func NewGossipMetrics(p metrics.Provider) *GossipMetrics {
	return &GossipMetrics{
		CommMetrics:       newCommMetrics(p),
		ElectionMetrics:   newElectionMetrics(p),
		MembershipMetrics: newMembershipMetrics(p),
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

type ElectionMetrics struct {
	Declaration metrics.Gauge
}

var LeaderDeclarationOpts = metrics.GaugeOpts{
	Namespace:    "gossip",
	Subsystem:    "leader_election",
	Name:         "leader",
	Help:         "Peer is leader (1) or follower (0)",
	LabelNames:   []string{"channel"},
	StatsdFormat: "%{#fqname}.%{channel}",
}

func newElectionMetrics(p metrics.Provider) *ElectionMetrics {
	return &ElectionMetrics{
		Declaration: p.NewGauge(LeaderDeclarationOpts),
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

type MembershipMetrics struct {
	Total metrics.Gauge
}

var TotalOpts = metrics.GaugeOpts{
	Namespace:    "gossip",
	Subsystem:    "membership",
	Name:         "total_peers_known",
	Help:         "Total known peers",
	LabelNames:   []string{"channel"},
	StatsdFormat: "%{#fqname}.%{channel}",
}

func newMembershipMetrics(p metrics.Provider) *MembershipMetrics {
	return &MembershipMetrics{
		Total: p.NewGauge(TotalOpts),
	}
}
