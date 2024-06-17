package prometheus

import (
	"github.com/11090815/mayy/common/metrics"
	kitmetrics "github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/prometheus"
	prom "github.com/prometheus/client_golang/prometheus"
)

type Provider struct{}

/* ------------------------------------------------------------------------------------------ */

type Counter struct {
	kitmetrics.Counter
}

func (p *Provider) NewCounter(opts metrics.CounterOpts) metrics.Counter {
	return &Counter{
		Counter: prometheus.NewCounterFrom(
			prom.CounterOpts{
				Namespace: opts.Namespace,
				Subsystem: opts.Subsystem,
				Name:      opts.Name,
				Help:      opts.Help,
			},
			opts.LabelNames,
		),
	}
}

func (c *Counter) With(labelsValues ...string) metrics.Counter {
	return &Counter{Counter: c.Counter.With(labelsValues...)}
}

/* ------------------------------------------------------------------------------------------ */

type Gauge struct {
	kitmetrics.Gauge
}

func (p *Provider) NewGauge(opts metrics.GaugeOpts) metrics.Gauge {
	return &Gauge{
		Gauge: prometheus.NewGaugeFrom(
			prom.GaugeOpts{
				Namespace: opts.Namespace,
				Subsystem: opts.Subsystem,
				Name:      opts.Name,
				Help:      opts.Help,
			},
			opts.LabelNames,
		),
	}
}

func (g *Gauge) With(labelsValues ...string) metrics.Gauge {
	return &Gauge{Gauge: g.Gauge.With(labelsValues...)}
}

/* ------------------------------------------------------------------------------------------ */

type Histogram struct {
	kitmetrics.Histogram
}

func (p *Provider) NewHistogram(opts metrics.HistogramOpts) metrics.Histogram {
	return &Histogram{
		Histogram: prometheus.NewHistogramFrom(
			prom.HistogramOpts{
				Namespace: opts.Namespace,
				Subsystem: opts.Subsystem,
				Name:      opts.Name,
				Help:      opts.Help,
				Buckets:   opts.Buckets,
			},
			opts.LabelNames,
		),
	}
}

func (h *Histogram) With(labelsValues ...string) metrics.Histogram {
	return &Histogram{Histogram: h.Histogram.With(labelsValues...)}
}
