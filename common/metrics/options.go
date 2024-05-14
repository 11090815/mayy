package metrics

type CounterOpts struct {
	Namespace    string
	Subsystem    string
	Name         string
	Help         string
	LabelNames   []string
	LabelHelp    map[string]string
	StatsdFormat string
}

/* ------------------------------------------------------------------------------------------ */

type GaugeOpts struct {
	Namespace    string
	Subsystem    string
	Name         string
	Help         string
	LabelNames   []string
	LabelHelp    map[string]string
	StatsdFormat string
}

/* ------------------------------------------------------------------------------------------ */

type HistogramOpts struct {
	Namespace    string
	Subsystem    string
	Name         string
	Help         string
	Buckets      []float64
	LabelNames   []string
	LabelHelp    map[string]string
	StatsdFormat string
}
