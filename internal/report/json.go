package report

import (
	"encoding/json"
	"io"

	"github.com/authhound/probe/internal/check"
)

// JSONSink collects results and emits a single JSON document on Close, for MSP
// scripting and (later) the premium result-upload path. The shape matches the
// check.Result struct plus a summary tally.
type JSONSink struct {
	w       io.Writer
	results []check.Result
	counts  map[check.Status]int
}

func NewJSONSink(w io.Writer) *JSONSink {
	return &JSONSink{w: w, counts: map[check.Status]int{}}
}

func (s *JSONSink) Emit(r check.Result) {
	s.results = append(s.results, r)
	s.counts[r.Status]++
}

func (s *JSONSink) Close() error {
	doc := struct {
		Results []check.Result       `json:"results"`
		Summary map[check.Status]int `json:"summary"`
	}{Results: s.results, Summary: s.counts}
	enc := json.NewEncoder(s.w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func (s *JSONSink) Failed() bool { return s.counts[check.StatusFail] > 0 }

// Warned reports whether any check warned, for --strict exit handling.
func (s *JSONSink) Warned() bool { return s.counts[check.StatusWarn] > 0 }
