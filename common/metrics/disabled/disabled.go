package disabled

import "github.com/11090815/mayy/common/metrics"

type Provider struct{}

func (p *Provider) NewCounter(metrics.CounterOpts) metrics.Counter {
	return &Counter{}
}

func (p *Provider) NewGauge(metrics.GaugeOpts) metrics.Gauge {
	return &Gauge{}
}

func (p *Provider) NewHistogram(metrics.HistogramOpts) metrics.Histogram {
	return &Histogram{}
}

type Counter struct{}

func (c *Counter) Add(delta float64) {}
func (c *Counter) With(labelValues ...string) metrics.Counter {
	return c
}

type Gauge struct{}

func (g *Gauge) Add(delta float64) {}
func (g *Gauge) Set(val float64)   {}
func (g *Gauge) With(labelValues ...string) metrics.Gauge {
	return g
}

type Histogram struct{}

func (h *Histogram) Observe(value float64) {}
func (h *Histogram) With(labelValues ...string) metrics.Histogram {
	return h
}
