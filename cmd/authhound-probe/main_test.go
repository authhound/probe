package main

import (
	"strings"
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

func TestParseServers(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"single bare host gets default port", "radius.corp.com", []string{"radius.corp.com:1812"}},
		{"single host:port kept", "10.0.0.1:1645", []string{"10.0.0.1:1645"}},
		{"comma list, mixed", "a,b:1812,c:1645", []string{"a:1812", "b:1812", "c:1645"}},
		{"whitespace and trailing comma dropped", " a , b , ", []string{"a:1812", "b:1812"}},
		{"duplicates de-duped, order kept", "a,a:1812,b", []string{"a:1812", "b:1812"}},
	}
	for _, c := range cases {
		got, err := parseServers(c.in)
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if _, err := parseServers("  , , "); err == nil {
		t.Error("empty server list should error")
	}
}

func TestResolveBindAddr(t *testing.T) {
	if a, err := resolveBindAddr(""); err != nil || a != nil {
		t.Errorf("empty bind: got (%v, %v), want (nil, nil)", a, err)
	}
	a, err := resolveBindAddr("127.0.0.1")
	if err != nil {
		t.Fatalf("bare IP: unexpected error %v", err)
	}
	if a.IP.String() != "127.0.0.1" || a.Port != 0 {
		t.Errorf("bare IP: got %v, want 127.0.0.1:0", a)
	}
	if a, err := resolveBindAddr("127.0.0.1:5000"); err != nil || a.Port != 5000 {
		t.Errorf("IP:port: got (%v, %v), want port 5000", a, err)
	}
	// A hostname is rejected — bind is about which interface leaves, not DNS.
	if _, err := resolveBindAddr("jumpbox.corp.com"); err == nil {
		t.Error("hostname bind should error")
	}
	if _, err := resolveBindAddr("not an ip"); err == nil {
		t.Error("garbage bind should error")
	}
}

func TestMultiServerRejectsCount(t *testing.T) {
	// --count against multiple servers is a usage error.
	if got := cmdRadiusTest([]string{"--server", "192.0.2.1,192.0.2.2", "--secret", "x", "--count", "3"}); got != 2 {
		t.Errorf("multi-server + --count: exit = %d, want 2", got)
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
