package report

import (
	"encoding/json"
	"io"

	"github.com/authhound/probe/internal/check"
)

// SchemaVersion identifies the --json document shape. It is a major version:
// within a major, changes are strictly additive (new fields may appear; existing
// fields never change type, meaning, or disappear), so scripts pinned to a major
// keep working. A breaking change bumps this and is documented in
// docs/json-schema.md. The golden-file test (json_test.go) fails CI if the shape
// changes without this bump.
const SchemaVersion = "1"

// JSONSink collects results and emits a single JSON document on Close, for MSP
// scripting and (later) the premium result-upload path. The shape is documented
// in docs/json-schema.md and pinned by a golden-file test: a top-level
// schema_version, the per-check results, and a summary tally.
type JSONSink struct {
	w       io.Writer
	results []check.Result
	counts  map[check.Status]int
	repeat  *repeatDoc // non-nil only in repeat mode (--count); see SetRepeat
}

func NewJSONSink(w io.Writer) *JSONSink {
	return &JSONSink{w: w, counts: map[check.Status]int{}}
}

func (s *JSONSink) Emit(r check.Result) {
	s.results = append(s.results, r)
	s.counts[r.Status]++
}

// summaryCounts is the per-status tally. It is a fixed struct (not a map) so
// every count is always present in the JSON — including the zeros — which is
// what lets RMM scripts address .summary.warn without first checking it exists.
type summaryCounts struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Warn int `json:"warn"`
	Info int `json:"info"`
	Skip int `json:"skip"`
}

func (s *JSONSink) Close() error {
	doc := struct {
		SchemaVersion string         `json:"schema_version"`
		Results       []check.Result `json:"results"`
		Summary       summaryCounts  `json:"summary"`
		Repeat        *repeatDoc     `json:"repeat,omitempty"` // additive: only with --count
	}{
		SchemaVersion: SchemaVersion,
		Results:       s.results,
		Repeat:        s.repeat,
		Summary: summaryCounts{
			Pass: s.counts[check.StatusPass],
			Fail: s.counts[check.StatusFail],
			Warn: s.counts[check.StatusWarn],
			Info: s.counts[check.StatusInfo],
			Skip: s.counts[check.StatusSkip],
		},
	}
	enc := json.NewEncoder(s.w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func (s *JSONSink) Failed() bool { return s.counts[check.StatusFail] > 0 }

// Warned reports whether any check warned, for --strict exit handling.
func (s *JSONSink) Warned() bool { return s.counts[check.StatusWarn] > 0 }
