package statsd

import (
	"github.com/11090815/mayy/common/metrics"
	"github.com/11090815/mayy/common/metrics/internal"
	"github.com/go-kit/kit/metrics/statsd"
)

const defaultNameFormat = "%{#fqname}"

type Provider struct {
	Statsd *statsd.Statsd
}

/* ------------------------------------------------------------------------------------------ */

type Counter struct {
	Counter        *statsd.Counter
	namer          *internal.Namer
	statsdProvider *statsd.Statsd
}

func (p *Provider) NewCounter(opts metrics.CounterOpts) metrics.Counter {
	if opts.StatsdFormat == "" {
		opts.StatsdFormat = defaultNameFormat
	}
	counter := &Counter{
		statsdProvider: p.Statsd,
		namer:          internal.NewCounterNamer(opts),
	}

	if len(opts.LabelNames) == 0 {
		counter.Counter = p.Statsd.NewCounter(counter.namer.Format(), 1.0)
	}

	return counter
}

func (c *Counter) Add(delta float64) {
	if c.Counter == nil {
		panic("label values must be provided by calling With()")
	}
	c.Counter.Add(delta)
}

func (c *Counter) With(labelsValues ...string) metrics.Counter {
	name := c.namer.Format(labelsValues...)
	return &Counter{Counter: c.statsdProvider.NewCounter(name, 1.0)}
}

/* ------------------------------------------------------------------------------------------ */

type Gauge struct {
	Gauge          *statsd.Gauge
	namer          *internal.Namer
	statsdProvider *statsd.Statsd
}

func (p *Provider) NewGauge(opts metrics.GaugeOpts) metrics.Gauge {
	if opts.StatsdFormat == "" {
		opts.StatsdFormat = defaultNameFormat
	}
	gauge := &Gauge{
		statsdProvider: p.Statsd,
		namer:          internal.NewGaugeNamer(opts),
	}

	if len(opts.LabelNames) == 0 {
		gauge.Gauge = p.Statsd.NewGauge(gauge.namer.Format())
	}

	return gauge
}

func (g *Gauge) Add(delta float64) {
	if g.Gauge == nil {
		panic("label values must be provided by calling With()")
	}
	g.Gauge.Add(delta)
}

func (g *Gauge) Set(value float64) {
	if g.Gauge == nil {
		panic("label values must be provided by calling With()")
	}
	g.Gauge.Set(value)
}

func (g *Gauge) With(labelsValues ...string) metrics.Gauge {
	name := g.namer.Format(labelsValues...)
	return &Gauge{Gauge: g.statsdProvider.NewGauge(name)}
}

/* ------------------------------------------------------------------------------------------ */

type Histogram struct {
	Timing         *statsd.Timing
	namer          *internal.Namer
	statsdProvider *statsd.Statsd
}

func (p *Provider) NewHistogram(opts metrics.HistogramOpts) metrics.Histogram {
	if opts.StatsdFormat == "" {
		opts.StatsdFormat = defaultNameFormat
	}
	histogram := &Histogram{
		namer: internal.NewHistogramNamer(opts),
		statsdProvider: p.Statsd,
	}

	if len(opts.LabelNames) == 0 {
		histogram.Timing = p.Statsd.NewTiming(histogram.namer.Format(), 1.0)
	}

	return histogram
}

func (h *Histogram) Observe(value float64) {
	if h.Timing == nil {
		panic("label values must be provided by calling With()")
	}
	h.Timing.Observe(value)
}

func (h *Histogram) With(labelsValues ...string) metrics.Histogram {
	name := h.namer.Format(labelsValues...)
	return &Histogram{Timing: h.statsdProvider.NewTiming(name, 1)}
}
