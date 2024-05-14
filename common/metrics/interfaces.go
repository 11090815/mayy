package metrics

type Provider interface {
	NewCounter(CounterOpts) Counter
}

/* ------------------------------------------------------------------------------------------ */

type Counter interface {
	With(labelValues ...string) Counter
	Add(delta float64)
}

/* ------------------------------------------------------------------------------------------ */

type Gauge interface {
	With(labelValues ...string) Gauge
	Add(delta float64)
	Set(value float64)
}

/* ------------------------------------------------------------------------------------------ */

type Histogram interface {
	With(labelValues ...string) Histogram
	Observe(value float64)
}
