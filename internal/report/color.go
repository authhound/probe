package report

import (
	"os"

	"golang.org/x/term"
)

// UseColor decides whether ANSI colour should be emitted to f (normally
// os.Stdout). Colour is on only when ALL of these hold:
//
//   - the caller didn't pass --no-color (noColorFlag is false),
//   - the NO_COLOR environment variable is unset (https://no-color.org — any
//     value, even empty, disables colour by that convention),
//   - f is a real terminal (not a pipe or a file — so `... > out.txt` and
//     `... | tee` never capture escape codes), and
//   - on Windows, virtual-terminal processing could actually be enabled on the
//     console (legacy conhost builds that can't render VT get plain text
//     instead of raw \x1b[..m garbage).
//
// This is the single source of truth for the colour decision; both subcommands
// call it so behaviour is identical.
func UseColor(f *os.File, noColorFlag bool) bool {
	if noColorFlag {
		return false
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if f == nil || !term.IsTerminal(int(f.Fd())) {
		return false
	}
	// On Windows this turns on VT processing and reports whether it stuck; on
	// every other OS it's a no-op that returns true.
	return enableVirtualTerminal(f)
}
