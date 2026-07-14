package check

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Repeat mode (`radius test --count N`) runs the same plan N times to expose
// intermittent failures a single-shot PASS can't see. It is a diagnosis loop a
// human babysits: strictly sequential, hard-capped at RepeatCountMax runs, no
// scheduling, no persistence — continuous monitoring stays out of this binary.

const (
	RepeatCountMin = 2
	RepeatCountMax = 50

	// repeatIntervalFloor is the hard minimum pause between iterations. It is
	// derived from the runner's per-exchange ceiling (minInterval) so the two
	// can never drift apart: the runner already enforces minInterval between
	// exchanges inside an iteration, so any between-iteration pause >= minInterval
	// keeps the sustained request rate under the ceiling; 4x adds margin. Like
	// minInterval itself, this is deliberately not configurable by flag, env,
	// or config.
	repeatIntervalFloor = 4 * minInterval
)

// RepeatOptions configures a repeated run.
type RepeatOptions struct {
	Count    int           // iterations, RepeatCountMin..RepeatCountMax
	Interval time.Duration // requested pause between iterations; floored to the safety minimum
	// OnIteration, if set, is called after each completed iteration with its
	// 1-based index and results — progress reporting for a human watching.
	OnIteration func(iteration int, results []Result)
}

// RepeatRun is the outcome of a repeated run. Iterations holds only fully
// completed iterations; a run cut short by ctx cancellation aggregates what
// finished.
type RepeatRun struct {
	Iterations        [][]Result
	RequestedInterval time.Duration
	Interval          time.Duration // interval actually used (>= safety floor)
	Stretched         bool          // requested interval was below the floor
}

// EffectiveInterval returns the between-iteration interval a repeat run will
// actually use, and whether the requested one had to be stretched to satisfy
// the safety floor.
func EffectiveInterval(requested time.Duration) (effective time.Duration, stretched bool) {
	if requested < repeatIntervalFloor {
		return repeatIntervalFloor, true
	}
	return requested, false
}

// RunRepeated executes plan Count times, pausing the effective interval between
// iterations. The Runner's own per-exchange ceiling still applies inside every
// iteration; the floor here only governs the gap between iterations.
func RunRepeated(ctx context.Context, r *Runner, plan Plan, opts RepeatOptions) (RepeatRun, error) {
	if opts.Count < RepeatCountMin || opts.Count > RepeatCountMax {
		return RepeatRun{}, fmt.Errorf("count must be between %d and %d", RepeatCountMin, RepeatCountMax)
	}
	interval, stretched := EffectiveInterval(opts.Interval)
	run := RepeatRun{RequestedInterval: opts.Interval, Interval: interval, Stretched: stretched}
	for i := 0; i < opts.Count; i++ {
		if i > 0 {
			select {
			case <-time.After(interval):
			case <-ctx.Done():
				return run, nil
			}
		}
		results := r.Run(ctx, plan)
		if ctx.Err() != nil && len(results) < len(plan.Checks) {
			// Cancelled mid-iteration: a partial iteration would skew the
			// per-check tallies, so drop it and report what completed.
			return run, nil
		}
		run.Iterations = append(run.Iterations, results)
		if opts.OnIteration != nil {
			opts.OnIteration(i+1, results)
		}
	}
	return run, nil
}

// CheckStats aggregates one check's results across all iterations.
//
// A "success" is any iteration the server answered and processed (pass, warn,
// or info). A timeout is a lost request — no reply at all — counted separately
// from processed rejections because they point at different culprits: loss
// means path/overload, a consistent reject means configuration.
type CheckStats struct {
	Check     string
	Attempts  int // iterations where the check actually sent (not skipped)
	Successes int // pass / warn / info
	Failures  int // fail or lost
	Timeouts  int // subset of Failures: no reply at all
	Skipped   int
	Warns     int

	// Latency over answered iterations (nearest-rank percentiles). Zero when
	// nothing was answered.
	LatMin, LatMedian, LatP95, LatMax time.Duration
}

// Iterations returns how many iterations this check appeared in.
func (s CheckStats) Iterations() int { return s.Attempts + s.Skipped }

// AggregateRepeat computes per-check statistics across the run's iterations,
// in the plan's check order.
func AggregateRepeat(run RepeatRun) []CheckStats {
	if len(run.Iterations) == 0 {
		return nil
	}
	byCheck := map[string]*CheckStats{}
	var order []string
	for _, r := range run.Iterations[0] {
		byCheck[r.Check] = &CheckStats{Check: r.Check}
		order = append(order, r.Check)
	}
	latencies := map[string][]time.Duration{}
	for _, iter := range run.Iterations {
		for _, r := range iter {
			s, ok := byCheck[r.Check]
			if !ok { // defensive: a check name not in iteration 1
				s = &CheckStats{Check: r.Check}
				byCheck[r.Check] = s
				order = append(order, r.Check)
			}
			switch {
			case r.Fields[TimeoutField] == "true":
				// A lost request is a failed attempt regardless of the status
				// the check chose for single-run readability (pap reports
				// timeout as SKIP to say "fix reachability first").
				s.Attempts++
				s.Failures++
				s.Timeouts++
			case r.Status == StatusSkip:
				s.Skipped++
			case r.Status == StatusFail:
				s.Attempts++
				s.Failures++
			default: // pass / warn / info: the server answered and processed it
				s.Attempts++
				s.Successes++
				if r.Status == StatusWarn {
					s.Warns++
				}
				if r.Duration > 0 {
					latencies[r.Check] = append(latencies[r.Check], r.Duration)
				}
			}
		}
	}
	var out []CheckStats
	for _, name := range order {
		s := byCheck[name]
		if lat := latencies[name]; len(lat) > 0 {
			sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
			s.LatMin = lat[0]
			s.LatMax = lat[len(lat)-1]
			s.LatMedian = percentile(lat, 0.5)
			s.LatP95 = percentile(lat, 0.95)
		}
		out = append(out, *s)
	}
	return out
}

// percentile is the nearest-rank percentile of an ascending-sorted slice.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// Verdict renders the aggregate as one Result per check, so repeat mode flows
// through the same sinks, tallies, and exit-code logic as a single run. The
// summary names flakiness explicitly: partial loss reads as a path/server
// problem, a 0% success rate as a configuration problem.
func (s CheckStats) Verdict() Result {
	n := s.Iterations()
	r := Result{Check: s.Check, Fields: map[string]string{
		"attempts":  strconv.Itoa(s.Attempts),
		"successes": strconv.Itoa(s.Successes),
		"timeouts":  strconv.Itoa(s.Timeouts),
	}}
	if s.Attempts > 0 {
		r.Fields["success_rate"] = fmt.Sprintf("%d/%d", s.Successes, s.Attempts)
	}
	if s.Successes > 0 && s.LatMax > 0 {
		r.Fields["latency_min_ms"] = ms(s.LatMin)
		r.Fields["latency_median_ms"] = ms(s.LatMedian)
		r.Fields["latency_p95_ms"] = ms(s.LatP95)
		r.Fields["latency_max_ms"] = ms(s.LatMax)
		r.Detail = fmt.Sprintf("Latency over %d answered runs: min %sms, median %sms, p95 %sms, max %sms.",
			s.Successes, ms(s.LatMin), ms(s.LatMedian), ms(s.LatP95), ms(s.LatMax))
	}

	switch {
	case s.Attempts == 0:
		r.Status = StatusSkip
		r.Summary = fmt.Sprintf("%s: skipped in all %d runs", s.Check, n)
	case s.Failures == 0:
		r.Status = StatusPass
		if s.Warns > 0 {
			r.Status = StatusWarn
		}
		r.Summary = fmt.Sprintf("%s: %d/%d succeeded — stable", s.Check, s.Successes, s.Attempts)
		if s.Warns > 0 {
			r.Summary += fmt.Sprintf(" (%d with warnings)", s.Warns)
		}
	case s.Successes == 0 && s.Timeouts == s.Attempts:
		r.Status = StatusFail
		r.Summary = fmt.Sprintf("%s: all %d requests lost — nothing answered; the server is down or unreachable, this probe isn't registered as a client, or the secret is wrong (silent drop) — not intermittent",
			s.Check, s.Attempts)
	case s.Successes == 0:
		r.Status = StatusFail
		r.Summary = fmt.Sprintf("%s: 0/%d succeeded — failed every run; a consistent failure points to configuration (secret, credentials, policy), not flakiness",
			s.Check, s.Attempts)
	default:
		r.Status = StatusFail
		r.Summary = fmt.Sprintf("%s: %d/%d succeeded, %s — consistent with an unstable path or an overloaded/failing server, not a config error",
			s.Check, s.Successes, s.Attempts, lossPhrase(s))
	}
	return r
}

// lossPhrase describes the failed fraction of a flaky check: lost requests
// (timeouts) and processed-but-failed runs are named separately.
func lossPhrase(s CheckStats) string {
	var parts []string
	if s.Timeouts > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d requests lost", s.Timeouts, s.Attempts))
	}
	if other := s.Failures - s.Timeouts; other > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d failed after an answer", other, s.Attempts))
	}
	return strings.Join(parts, " and ")
}

func ms(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }
