package report

import (
	"strings"

	"github.com/authhound/probe/internal/check"
)

// ComparisonBlock renders the multi-server comparison for the terminal: the
// headline verdict (word-wrapped to match the rest of the output) followed by
// any per-check divergences between the servers that responded.
func ComparisonBlock(c check.Comparison) string {
	var b strings.Builder
	b.WriteString("Comparison across servers:\n")
	b.WriteString("  " + wrap(c.Verdict, 70, "  ") + "\n")
	for _, d := range c.Divergent {
		b.WriteString("  - " + d + "\n")
	}
	return b.String()
}
