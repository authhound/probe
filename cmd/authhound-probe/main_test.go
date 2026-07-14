package main

import (
	"testing"

	"github.com/authhound/probe/internal/check"
)

// fakeSink is a resultSink whose tallies we set directly, to drive exitCode.
type fakeSink struct {
	failed bool
	warned bool
}

func (fakeSink) Emit(check.Result) {}
func (fakeSink) Close() error      { return nil }
func (s fakeSink) Failed() bool    { return s.failed }
func (s fakeSink) Warned() bool    { return s.warned }

func TestExitCode(t *testing.T) {
	cases := []struct {
		name   string
		sink   fakeSink
		strict bool
		want   int
	}{
		{"clean run", fakeSink{}, false, 0},
		{"failure always exits 1", fakeSink{failed: true}, false, 1},
		{"warning is not a failure by default", fakeSink{warned: true}, false, 0},
		{"warning fails under --strict", fakeSink{warned: true}, true, 1},
		{"strict with a clean run still 0", fakeSink{}, true, 0},
		{"failure still 1 under --strict", fakeSink{failed: true}, true, 1},
	}
	for _, c := range cases {
		if got := exitCode(c.sink, c.strict); got != c.want {
			t.Errorf("%s: exitCode = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestCountFlagValidation pins the --count contract: out-of-range counts and a
// stray --interval are usage errors (exit 2) caught before any credential
// prompting or network I/O.
func TestCountFlagValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"count too high", []string{"--server", "192.0.2.1", "--count", "51"}},
		{"count zero", []string{"--server", "192.0.2.1", "--count", "0"}},
		{"count negative", []string{"--server", "192.0.2.1", "--count", "-3"}},
		{"interval without count", []string{"--server", "192.0.2.1", "--interval", "5s"}},
	}
	for _, c := range cases {
		if got := cmdRadiusTest(c.args); got != 2 {
			t.Errorf("%s: exit = %d, want 2", c.name, got)
		}
	}
}

func TestResolveVersion(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	// When GoReleaser stamps a tag into `version`, that wins verbatim.
	version = "1.2.3"
	if got := resolveVersion(); got != "1.2.3" {
		t.Errorf("stamped version: got %q, want %q", got, "1.2.3")
	}

	// When unstamped ("dev"), resolveVersion falls back to build info. Under
	// `go test` the main module version is "(devel)", which is filtered out, so
	// it degrades to "dev" rather than leaking "(devel)" into --version output.
	version = "dev"
	if got := resolveVersion(); got == "(devel)" || got == "" {
		t.Errorf("dev fallback returned %q, want a clean version string", got)
	}
}
