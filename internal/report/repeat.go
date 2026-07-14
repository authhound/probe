package report

import (
	"fmt"
	"strings"

	"github.com/authhound/probe/internal/check"
)

// This file renders repeat mode (`radius test --count N`): the per-iteration
// progress line for the text sink, and the additive `repeat` block for the
// JSON document. Everything here is additive within schema major "1" — the
// top-level results/summary keep their shape (one object per check; in repeat
// mode those are the aggregate verdicts).

// repeatDoc is the JSON `repeat` block, present only when --count was used.
type repeatDoc struct {
	Count               int            `json:"count"`
	Completed           int            `json:"completed"`
	IntervalMs          int64          `json:"interval_ms"`
	RequestedIntervalMs int64          `json:"requested_interval_ms"`
	IntervalStretched   bool           `json:"interval_stretched"`
	Iterations          []iterationDoc `json:"iterations"`
	Aggregate           []aggregateDoc `json:"aggregate"`
}

type iterationDoc struct {
	Results []check.Result `json:"results"`
}

type aggregateDoc struct {
	Check     string      `json:"check"`
	Attempts  int         `json:"attempts"`
	Successes int         `json:"successes"`
	Failures  int         `json:"failures"`
	Timeouts  int         `json:"timeouts"`
	Skipped   int         `json:"skipped"`
	LatencyMs *latencyDoc `json:"latency_ms,omitempty"`
}

// latencyDoc is nearest-rank percentiles over answered runs, in milliseconds.
type latencyDoc struct {
	Min    int64 `json:"min"`
	Median int64 `json:"median"`
	P95    int64 `json:"p95"`
	Max    int64 `json:"max"`
}

// SetRepeat attaches the repeat block to the JSON document. count is the
// requested iteration count (completed may be lower after an interrupt).
func (s *JSONSink) SetRepeat(count int, run check.RepeatRun, stats []check.CheckStats) {
	doc := &repeatDoc{
		Count:               count,
		Completed:           len(run.Iterations),
		IntervalMs:          run.Interval.Milliseconds(),
		RequestedIntervalMs: run.RequestedInterval.Milliseconds(),
		IntervalStretched:   run.Stretched,
		Iterations:          []iterationDoc{},
		Aggregate:           []aggregateDoc{},
	}
	for _, iter := range run.Iterations {
		doc.Iterations = append(doc.Iterations, iterationDoc{Results: iter})
	}
	for _, st := range stats {
		a := aggregateDoc{
			Check:     st.Check,
			Attempts:  st.Attempts,
			Successes: st.Successes,
			Failures:  st.Failures,
			Timeouts:  st.Timeouts,
			Skipped:   st.Skipped,
		}
		if st.Successes > 0 && st.LatMax > 0 {
			a.LatencyMs = &latencyDoc{
				Min:    st.LatMin.Milliseconds(),
				Median: st.LatMedian.Milliseconds(),
				P95:    st.LatP95.Milliseconds(),
				Max:    st.LatMax.Milliseconds(),
			}
		}
		doc.Aggregate = append(doc.Aggregate, a)
	}
	s.repeat = doc
}

// IterationLine renders one repeat iteration as a single compact progress
// line. Skipped checks are omitted (they are identical every iteration and
// would drown the signal); lost requests are called out.
func IterationLine(iteration, total int, results []check.Result) string {
	var parts []string
	for _, r := range results {
		if r.Status == check.StatusSkip && r.Fields[check.TimeoutField] != "true" {
			continue
		}
		p := fmt.Sprintf("%s %s", r.Check, strings.ToUpper(string(r.Status)))
		if r.Fields[check.TimeoutField] == "true" {
			p = r.Check + " LOST (no reply)"
		} else if rtt, ok := r.Fields["rtt_ms"]; ok {
			p += " " + rtt + "ms"
		}
		parts = append(parts, p)
	}
	if parts == nil {
		parts = []string{"all checks skipped"}
	}
	width := len(fmt.Sprint(total))
	return fmt.Sprintf("run %*d/%d  %s", width, iteration, total, strings.Join(parts, " · "))
}
