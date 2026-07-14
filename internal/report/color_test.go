package report

import (
	"os"
	"testing"
)

// UseColor's decision is a conjunction; these cases pin the parts that don't
// depend on a real TTY. A pipe (os.Pipe) is never a terminal, so it lets us
// assert the "not a terminal -> no colour" and precedence rules deterministically
// without allocating a console.
func TestUseColorNonTTY(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	// A pipe isn't a terminal: colour off regardless of the flag.
	if UseColor(w, false) {
		t.Error("UseColor(pipe, noColor=false) = true, want false (not a terminal)")
	}

	// --no-color short-circuits before the TTY check.
	if UseColor(w, true) {
		t.Error("UseColor(_, noColor=true) = true, want false")
	}

	// nil file is treated as no-colour, never panics.
	if UseColor(nil, false) {
		t.Error("UseColor(nil, _) = true, want false")
	}
}

// NO_COLOR (https://no-color.org) disables colour for ANY value, including empty,
// and takes precedence over everything except the explicit flag ordering above.
func TestUseColorNoColorEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	if UseColor(os.Stdout, false) {
		t.Error("UseColor with NO_COLOR set (empty) = true, want false")
	}
	t.Setenv("NO_COLOR", "1")
	if UseColor(os.Stdout, false) {
		t.Error("UseColor with NO_COLOR=1 = true, want false")
	}
}
