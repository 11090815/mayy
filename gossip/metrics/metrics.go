package metrics

import "github.com/11090815/mayy/common/metrics"

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
