package internal

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/11090815/mayy/common/metrics"
)

var (
	formatRegexp            = regexp.MustCompile(`%{([#?[:alnum:]_]+)}`)
	invalidLabelValueRegexp = regexp.MustCompile(`[.|:\s]`)
)

type Namer struct {
	namespace  string
	subsystem  string
	name       string
	nameFormat string
	labelNames map[string]struct{}
}

func NewCounterNamer(opts metrics.CounterOpts) *Namer {
	return &Namer{
		namespace:  opts.Namespace,
		subsystem:  opts.Subsystem,
		name:       opts.Name,
		nameFormat: opts.StatsdFormat,
		labelNames: sliceToSet(opts.LabelNames),
	}
}

func NewGaugeNamer(opts metrics.GaugeOpts) *Namer {
	return &Namer{
		namespace:  opts.Namespace,
		subsystem:  opts.Subsystem,
		name:       opts.Name,
		nameFormat: opts.StatsdFormat,
		labelNames: sliceToSet(opts.LabelNames),
	}
}

func NewHistogramNamer(opts metrics.HistogramOpts) *Namer {
	return &Namer{
		namespace:  opts.Namespace,
		subsystem:  opts.Subsystem,
		name:       opts.Name,
		nameFormat: opts.StatsdFormat,
		labelNames: sliceToSet(opts.LabelNames),
	}
}

func (n *Namer) FullyQualifiedName() string {
	if n.namespace != "" && n.subsystem != "" {
		return strings.Join([]string{n.namespace, n.subsystem, n.name}, ".")
	} else if n.namespace != "" {
		return strings.Join([]string{n.namespace, n.name}, ".")
	} else if n.subsystem != "" {
		return strings.Join([]string{n.subsystem, n.name}, ".")
	} else {
		return n.name
	}
}

func (n *Namer) Format(labelValues ...string) string {
	labels2values := n.labelsToMap(labelValues)

	cursor := 0
	var segments []string

	matches := formatRegexp.FindAllStringSubmatchIndex(n.nameFormat, -1)
	for _, match := range matches {
		start, end := match[0], match[1]
		labelStart, labelEnd := match[2], match[3]

		if start > cursor {
			segments = append(segments, n.nameFormat[cursor:start])
		}

		key := n.nameFormat[labelStart:labelEnd]
		var value string
		switch key {
		case "#namespace":
			value = n.namespace
		case "#subsystem":
			value = n.subsystem
		case "#name":
			value = n.name
		case "#fqname":
			value = n.FullyQualifiedName()
		default:
			var ok bool
			value, ok = labels2values[key]
			if !ok {
				panic(fmt.Sprintf("invalid label in name format: %s", key))
			}
			value = invalidLabelValueRegexp.ReplaceAllString(value, "_")
		}
		segments = append(segments, value)
		cursor = end
	}

	if cursor != len(n.nameFormat) {
		segments = append(segments, n.nameFormat[cursor:])
	}
	return strings.Join(segments, "")
}

/* ------------------------------------------------------------------------------------------ */

func (n *Namer) validateLabel(label string) {
	if _, ok := n.labelNames[label]; !ok {
		panic(fmt.Sprintf("invalid label name: %s", label))
	}
}

func (n *Namer) labelsToMap(labelValues []string) map[string]string {
	kvs := make(map[string]string)
	for i := 0; i < len(labelValues); i += 2 {
		label := labelValues[i]
		n.validateLabel(label)
		if i == len(labelValues)-1 {
			kvs[label] = "unknown"
		} else {
			kvs[label] = labelValues[i+1]
		}
	}
	return kvs
}

func sliceToSet(slice []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, item := range slice {
		set[item] = struct{}{}
	}
	return set
}
