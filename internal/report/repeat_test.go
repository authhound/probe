package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/authhound/probe/internal/check"
)

// repeatRun is a fixed two-iteration run (one flaky check) whose JSON render is
// pinned by testdata/schema-v1-repeat.golden.json — the shape guard for the
// additive `repeat` block. Regenerate with:
// `go test ./internal/report -run Golden -update`.
func repeatRun() (check.RepeatRun, []check.CheckStats) {
	ok := check.Result{
		Check: "pap-auth", Status: check.StatusPass,
		Summary:  "PAP authentication accepted for alice",
		Duration: 4_000_000,
	}
	lost := check.Result{
		Check: "pap-auth", Status: check.StatusFail,
		Summary:  "No reply from 127.0.0.1:1812 within 5s",
		Fields:   map[string]string{check.TimeoutField: "true"},
		Duration: 5_000_000_000,
	}
	run := check.RepeatRun{
		Iterations:        [][]check.Result{{ok}, {lost}},
		RequestedInterval: 500 * time.Millisecond,
		Interval:          time.Second,
		Stretched:         true,
	}
	return run, check.AggregateRepeat(run)
}

func TestJSONRepeatGolden(t *testing.T) {
	run, stats := repeatRun()
	var buf bytes.Buffer
	sink := NewJSONSink(&buf)
	for _, st := range stats {
		sink.Emit(st.Verdict())
	}
	sink.SetRepeat(2, run, stats)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := buf.Bytes()

	golden := filepath.Join("testdata", "schema-v1-repeat.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		t.Logf("updated %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("repeat --json shape changed vs %s.\n"+
			"If intentional and additive, regenerate with:\n"+
			"    go test ./internal/report -run Golden -update\n"+
			"Otherwise bump report.SchemaVersion and document it in docs/json-schema.md."+
			"\n\n--- got ---\n%s\n--- want ---\n%s", golden, got, want)
	}
}

// TestJSONWithoutRepeatOmitsBlock pins that single runs are byte-identical to
// before this feature existed: no `repeat` key unless --count was used.
func TestJSONWithoutRepeatOmitsBlock(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONSink(&buf)
	sink.Emit(check.Result{Check: "reachability", Status: check.StatusPass, Summary: "ok"})
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte(`"repeat"`)) {
		t.Errorf("single-run JSON must not contain a repeat block:\n%s", buf.String())
	}
}

func TestIterationLine(t *testing.T) {
	results := []check.Result{
		{Check: "reachability", Status: check.StatusPass, Fields: map[string]string{"rtt_ms": "2"}},
		{Check: "shared-secret", Status: check.StatusPass},
		{Check: "pap-auth", Status: check.StatusSkip, Fields: map[string]string{check.TimeoutField: "true"}},
		{Check: "eap-tls", Status: check.StatusSkip, Summary: "No client certificate given"},
	}
	line := IterationLine(3, 10, results)
	for _, want := range []string{"run  3/10", "reachability PASS 2ms", "shared-secret PASS", "pap-auth LOST (no reply)"} {
		if !strings.Contains(line, want) {
			t.Errorf("line missing %q: %s", want, line)
		}
	}
	// Plain skips stay off the line; a timed-out check (whatever its status) is on it.
	if strings.Contains(line, "eap-tls") {
		t.Errorf("skipped check should not appear: %s", line)
	}
}
