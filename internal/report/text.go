// Package report renders check results for a human terminal. It is the v1
// ResultSink; the premium build adds a CloudSink alongside it.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/authhound/probe/internal/check"
)

type TextSink struct {
	w      io.Writer
	color  bool
	counts map[check.Status]int
}

func NewTextSink(w io.Writer, color bool) *TextSink {
	return &TextSink{w: w, color: color, counts: map[check.Status]int{}}
}

func (s *TextSink) icon(st check.Status) string {
	glyph := map[check.Status]string{
		check.StatusPass: "PASS", check.StatusFail: "FAIL", check.StatusWarn: "WARN",
		check.StatusInfo: "INFO", check.StatusSkip: "SKIP",
	}[st]
	if !s.color {
		return glyph
	}
	code := map[check.Status]string{
		check.StatusPass: "32", check.StatusFail: "31", check.StatusWarn: "33",
		check.StatusInfo: "36", check.StatusSkip: "90",
	}[st]
	return fmt.Sprintf("\x1b[%sm%s\x1b[0m", code, glyph)
}

func (s *TextSink) Emit(r check.Result) {
	s.counts[r.Status]++
	fmt.Fprintf(s.w, "%s  %s\n", s.icon(r.Status), r.Summary)
	if rtt, ok := r.Fields["rtt_ms"]; ok {
		fmt.Fprintf(s.w, "        %sms round-trip\n", rtt)
	}
	if r.Detail != "" {
		fmt.Fprintf(s.w, "        %s\n", wrap(r.Detail, 72, "        "))
	}
	if r.Authorization != nil {
		s.renderAuthorization(r.Authorization)
	}
	if r.Hint != "" {
		// Hints are pre-formatted, paste-ready snippets: print line-by-line
		// with indent, never re-wrapped (wrap() would mangle the formatting).
		fmt.Fprintln(s.w)
		for _, line := range strings.Split(r.Hint, "\n") {
			fmt.Fprintf(s.w, "        %s\n", line)
		}
	}
}

// renderAuthorization prints the Access-Accept authorization block: the
// attributes the server returned (the VLAN/policy answer) and the outcome of any
// --expect-vlan/--expect-attr assertions.
func (s *TextSink) renderAuthorization(a *check.Authorization) {
	if len(a.Attributes) > 0 {
		fmt.Fprintf(s.w, "        Authorization returned by the server:\n")
		for _, at := range a.Attributes {
			if at.Vendor != 0 {
				fmt.Fprintf(s.w, "          %s = %s  [vendor %d]\n", at.Name, at.Value, at.Vendor)
			} else {
				fmt.Fprintf(s.w, "          %s = %s\n", at.Name, at.Value)
			}
		}
	}
	for _, ar := range a.Assertions {
		switch {
		case ar.Indeterminate:
			fmt.Fprintf(s.w, "          assert %s=%s: could not verify (Access-Accept not read)\n", ar.Label, ar.Expected)
		case ar.Pass:
			fmt.Fprintf(s.w, "          assert %s=%s: OK\n", ar.Label, ar.Expected)
		case ar.Actual == "":
			fmt.Fprintf(s.w, "          assert %s=%s: MISMATCH (not returned)\n", ar.Label, ar.Expected)
		default:
			fmt.Fprintf(s.w, "          assert %s=%s: MISMATCH (got %s)\n", ar.Label, ar.Expected, ar.Actual)
		}
	}
}

// Close prints the verdict line and returns nil (kept for the ResultSink
// contract; a CloudSink's Close would flush/upload).
func (s *TextSink) Close() error {
	fmt.Fprintln(s.w)
	fmt.Fprintf(s.w, "Verdict: %d passed, %d failed, %d warnings",
		s.counts[check.StatusPass], s.counts[check.StatusFail], s.counts[check.StatusWarn])
	if skip := s.counts[check.StatusSkip]; skip > 0 {
		fmt.Fprintf(s.w, ", %d skipped", skip)
	}
	fmt.Fprintln(s.w)
	return nil
}

// Failed reports whether any check failed, for the process exit code.
func (s *TextSink) Failed() bool { return s.counts[check.StatusFail] > 0 }

// Warned reports whether any check warned, for --strict exit handling.
func (s *TextSink) Warned() bool { return s.counts[check.StatusWarn] > 0 }

func wrap(str string, width int, indent string) string {
	var out, line string
	for _, w := range splitWords(str) {
		if line == "" {
			line = w
		} else if len(line)+1+len(w) <= width {
			line += " " + w
		} else {
			out += line + "\n" + indent
			line = w
		}
	}
	return out + line
}

func splitWords(s string) []string {
	var words []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' {
			if cur != "" {
				words = append(words, cur)
				cur = ""
			}
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		words = append(words, cur)
	}
	return words
}
