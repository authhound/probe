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
	w          io.Writer
	results    []check.Result
	counts     map[check.Status]int
	repeat     *repeatDoc        // non-nil only in repeat mode (--count); see SetRepeat
	servers    []serverDoc       // non-nil only when comparing >1 --server; see SetServers
	comparison *check.Comparison // the cross-server verdict, paired with servers
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

// serverDoc is one server's block in a multi-server comparison. Top-level
// `results`/`summary` stay present (the combined tally across all servers, so
// `.summary.fail` still drives scripts); `servers[]` groups them per server.
type serverDoc struct {
	Server  string         `json:"server"`
	Results []check.Result `json:"results"`
	Summary summaryCounts  `json:"summary"`
}

// SetServers attaches the per-server grouping and cross-server verdict for a
// multi-server run. It is additive: single-server documents omit both fields and
// are byte-for-byte unchanged.
func (s *JSONSink) SetServers(runs []check.ServerRun, cmp check.Comparison) {
	for _, r := range runs {
		s.servers = append(s.servers, serverDoc{
			Server:  r.Server,
			Results: r.Results,
			Summary: tally(r.Results),
		})
	}
	s.comparison = &cmp
}

// tally counts a result set into the fixed summary struct (all statuses present,
// including zeros).
func tally(results []check.Result) summaryCounts {
	var c summaryCounts
	for _, r := range results {
		switch r.Status {
		case check.StatusPass:
			c.Pass++
		case check.StatusFail:
			c.Fail++
		case check.StatusWarn:
			c.Warn++
		case check.StatusInfo:
			c.Info++
		case check.StatusSkip:
			c.Skip++
		}
	}
	return c
}

func (s *JSONSink) Close() error {
	doc := struct {
		SchemaVersion string            `json:"schema_version"`
		Results       []check.Result    `json:"results"`
		Summary       summaryCounts     `json:"summary"`
		Repeat        *repeatDoc        `json:"repeat,omitempty"`     // additive: only with --count
		Servers       []serverDoc       `json:"servers,omitempty"`    // additive: only when comparing >1 --server
		Comparison    *check.Comparison `json:"comparison,omitempty"` // additive: paired with servers
	}{
		SchemaVersion: SchemaVersion,
		Results:       s.results,
		Repeat:        s.repeat,
		Servers:       s.servers,
		Comparison:    s.comparison,
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
