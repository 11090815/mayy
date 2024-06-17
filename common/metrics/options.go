package metrics

type CounterOpts struct {
	Namespace string
	Subsystem string
	Name      string
	Help      string
	// LabelNames 之后调用 With 方法传入的 labels2values 参数中，labels 必须存在于 LabelNames 中，不然会 panic。
	LabelNames   []string
	LabelHelp    map[string]string
	StatsdFormat string
}

/* ------------------------------------------------------------------------------------------ */

type GaugeOpts struct {
	Namespace string
	Subsystem string
	Name      string
	Help      string
	// LabelNames 之后调用 With 方法传入的 labels2values 参数中，labels 必须存在于 LabelNames 中，不然会 panic。
	LabelNames   []string
	LabelHelp    map[string]string
	StatsdFormat string
}

/* ------------------------------------------------------------------------------------------ */

type HistogramOpts struct {
	Namespace string
	Subsystem string
	Name      string
	Help      string
	Buckets   []float64
	// LabelNames 之后调用 With 方法传入的 labels2values 参数中，labels 必须存在于 LabelNames 中，不然会 panic。
	LabelNames   []string
	LabelHelp    map[string]string
	StatsdFormat string
}
