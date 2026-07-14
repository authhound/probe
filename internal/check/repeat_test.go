package check

import (
	"context"
	"strings"
	"testing"
	"time"
)

// stubCheck returns a scripted sequence of results, one per iteration, so
// repeat behavior can be tested without a network.
type stubCheck struct {
	name    string
	results []Result
	calls   int
}

func (c *stubCheck) Name() string { return c.name }
func (c *stubCheck) Run(ctx context.Context, t Target) Result {
	r := c.results[c.calls%len(c.results)]
	c.calls++
	r.Check = c.name
	return r
}

func TestEffectiveIntervalStretchesToFloor(t *testing.T) {
	// The floor is derived from the hard-coded rate ceiling and must win over
	// any smaller request — this is the "cannot be bypassed" guarantee.
	eff, stretched := EffectiveInterval(50 * time.Millisecond)
	if !stretched || eff != repeatIntervalFloor {
		t.Errorf("50ms: got (%s, %v), want (%s, true)", eff, stretched, repeatIntervalFloor)
	}
	eff, stretched = EffectiveInterval(0)
	if !stretched || eff != repeatIntervalFloor {
		t.Errorf("0: got (%s, %v), want (%s, true)", eff, stretched, repeatIntervalFloor)
	}
	eff, stretched = EffectiveInterval(2 * time.Second)
	if stretched || eff != 2*time.Second {
		t.Errorf("2s: got (%s, %v), want (2s, false)", eff, stretched)
	}
	if repeatIntervalFloor < minInterval {
		t.Errorf("floor %s below the per-exchange ceiling %s", repeatIntervalFloor, minInterval)
	}
}

func TestRunRepeatedEnforcesFloor(t *testing.T) {
	// Two iterations with a requested interval far below the floor must still
	// be separated by at least the floor.
	ok := Result{Status: StatusPass, Summary: "ok"}
	plan := Plan{Checks: []Check{&stubCheck{name: "c", results: []Result{ok}}}}
	start := time.Now()
	run, err := RunRepeated(context.Background(), &Runner{}, plan, RepeatOptions{
		Count: 2, Interval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !run.Stretched || run.Interval != repeatIntervalFloor {
		t.Errorf("got interval %s stretched=%v, want %s stretched=true", run.Interval, run.Stretched, repeatIntervalFloor)
	}
	if elapsed := time.Since(start); elapsed < repeatIntervalFloor {
		t.Errorf("iterations only %s apart, want >= %s", elapsed, repeatIntervalFloor)
	}
	if len(run.Iterations) != 2 {
		t.Errorf("got %d iterations, want 2", len(run.Iterations))
	}
}

func TestRunRepeatedCountBounds(t *testing.T) {
	plan := Plan{Checks: []Check{&stubCheck{name: "c", results: []Result{{Status: StatusPass}}}}}
	for _, n := range []int{-1, 0, 1, RepeatCountMax + 1} {
		if _, err := RunRepeated(context.Background(), &Runner{}, plan, RepeatOptions{Count: n, Interval: time.Second}); err == nil {
			t.Errorf("count %d: expected an error", n)
		}
	}
}

func TestRunRepeatedCancelKeepsCompletedIterations(t *testing.T) {
	ok := Result{Status: StatusPass, Summary: "ok"}
	plan := Plan{Checks: []Check{&stubCheck{name: "c", results: []Result{ok}}}}
	ctx, cancel := context.WithCancel(context.Background())
	run, err := RunRepeated(ctx, &Runner{}, plan, RepeatOptions{
		Count: 10, Interval: time.Second,
		OnIteration: func(i int, _ []Result) {
			if i == 2 {
				cancel()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Iterations) != 2 {
		t.Errorf("got %d completed iterations after cancel, want 2", len(run.Iterations))
	}
}

// mkIter builds one iteration's results for aggregate tests.
func mkIter(rs ...Result) []Result { return rs }

func res(check string, st Status, d time.Duration, timeout bool) Result {
	r := Result{Check: check, Status: st, Duration: d}
	if timeout {
		r = markTimeout(r)
	}
	return r
}

func TestAggregateRepeatCountsAndLatency(t *testing.T) {
	// 10 iterations of one check: 8 answered with known latencies, 2 lost.
	// Latencies 10..80ms -> min 10, median (ceil(4)=4th) 40, p95 (ceil(7.6)=8th) 80, max 80.
	var iters [][]Result
	for i := 1; i <= 8; i++ {
		iters = append(iters, mkIter(res("peap-mschapv2", StatusPass, time.Duration(i)*10*time.Millisecond, false)))
	}
	// One lost as FAIL, one lost as SKIP (pap reports timeouts as skip) — both
	// must count as lost attempts, not skips.
	iters = append(iters,
		mkIter(res("peap-mschapv2", StatusFail, 5*time.Second, true)),
		mkIter(res("peap-mschapv2", StatusSkip, 5*time.Second, true)),
	)

	stats := AggregateRepeat(RepeatRun{Iterations: iters})
	if len(stats) != 1 {
		t.Fatalf("got %d stats, want 1", len(stats))
	}
	s := stats[0]
	if s.Attempts != 10 || s.Successes != 8 || s.Failures != 2 || s.Timeouts != 2 || s.Skipped != 0 {
		t.Errorf("counts: attempts=%d successes=%d failures=%d timeouts=%d skipped=%d",
			s.Attempts, s.Successes, s.Failures, s.Timeouts, s.Skipped)
	}
	if s.LatMin != 10*time.Millisecond || s.LatMedian != 40*time.Millisecond ||
		s.LatP95 != 80*time.Millisecond || s.LatMax != 80*time.Millisecond {
		t.Errorf("latency: min=%s median=%s p95=%s max=%s", s.LatMin, s.LatMedian, s.LatP95, s.LatMax)
	}

	v := s.Verdict()
	if v.Status != StatusFail {
		t.Errorf("flaky verdict status: got %s, want fail", v.Status)
	}
	for _, want := range []string{"8/10 succeeded", "2/10 requests lost", "unstable path", "not a config error"} {
		if !strings.Contains(v.Summary, want) {
			t.Errorf("flaky verdict missing %q: %s", want, v.Summary)
		}
	}
	if v.Fields["success_rate"] != "8/10" || v.Fields["timeouts"] != "2" {
		t.Errorf("verdict fields: %v", v.Fields)
	}
}

func TestAggregateVerdictWording(t *testing.T) {
	pass := res("c", StatusPass, time.Millisecond, false)
	fail := res("c", StatusFail, time.Millisecond, false)
	skip := res("c", StatusSkip, 0, false)
	warn := res("c", StatusWarn, time.Millisecond, false)

	cases := []struct {
		name    string
		iters   [][]Result
		status  Status
		summary string
	}{
		{"all pass", [][]Result{mkIter(pass), mkIter(pass)}, StatusPass, "2/2 succeeded — stable"},
		{"all fail", [][]Result{mkIter(fail), mkIter(fail)}, StatusFail, "points to configuration"},
		{"all skip", [][]Result{mkIter(skip), mkIter(skip)}, StatusSkip, "skipped in all 2 runs"},
		{"warns stay warn", [][]Result{mkIter(warn), mkIter(warn)}, StatusWarn, "stable"},
		{"reject flaky", [][]Result{mkIter(pass), mkIter(fail)}, StatusFail, "1/2 failed after an answer"},
	}
	for _, tc := range cases {
		stats := AggregateRepeat(RepeatRun{Iterations: tc.iters})
		v := stats[0].Verdict()
		if v.Status != tc.status || !strings.Contains(v.Summary, tc.summary) {
			t.Errorf("%s: got status=%s summary=%q, want status=%s containing %q",
				tc.name, v.Status, v.Summary, tc.status, tc.summary)
		}
	}
}
