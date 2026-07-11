package check

import (
	"context"
	"time"
)

// minInterval is a hard-coded floor between successive RADIUS exchanges. It
// exists so the probe can never be turned into a load generator against a
// production RADIUS server — not by a config file, not by a cloud instruction.
// This ceiling is deliberately not configurable (doc rule: hard-coded safety
// ceilings the config cannot override). One "your tool DoS'd my RADIUS server"
// thread would be fatal to the product.
const minInterval = 250 * time.Millisecond

// Runner executes a plan's checks in order, enforcing the rate ceiling, and
// emits each Result to the sink as it completes. The same Runner serves both
// the local one-shot mode and (later) the scheduled cloud mode.
type Runner struct {
	Sink ResultSink
}

func (r *Runner) Run(ctx context.Context, plan Plan) []Result {
	var results []Result
	var last time.Time
	for _, c := range plan.Checks {
		if elapsed := time.Since(last); !last.IsZero() && elapsed < minInterval {
			select {
			case <-time.After(minInterval - elapsed):
			case <-ctx.Done():
				return results
			}
		}
		start := time.Now()
		res := c.Run(ctx, plan.Target)
		if res.Duration == 0 {
			res.Duration = time.Since(start)
		}
		last = time.Now()
		results = append(results, res)
		if r.Sink != nil {
			r.Sink.Emit(res)
		}
	}
	return results
}
