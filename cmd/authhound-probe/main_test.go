package main

import "testing"

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
