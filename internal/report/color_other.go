//go:build !windows

package report

import "os"

// enableVirtualTerminal is a no-op off Windows: Linux and macOS terminals
// render ANSI natively, so if f is a TTY (already checked by the caller) colour
// works. Returns true so UseColor's final decision is "yes, colour".
func enableVirtualTerminal(*os.File) bool { return true }
