//go:build windows

package report

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVirtualTerminal turns on ANSI escape processing for the console behind
// f and reports whether it is now active.
//
// Windows Terminal and modern conhost (Windows 10 1511+ / Server 2016+) can
// render ANSI, but only after ENABLE_VIRTUAL_TERMINAL_PROCESSING is set on the
// output handle — otherwise the escapes print as literal "←[32m" text. Older
// conhost builds reject the flag; there we return false so UseColor falls back
// to plain PASS/FAIL words rather than emitting garbage. PowerShell 5.1 and 7+
// both run inside one of these consoles, so this covers them too.
func enableVirtualTerminal(f *os.File) bool {
	handle := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false // not a real console (e.g. redirected) — no colour
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true // already on
	}
	if err := windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return false // legacy conhost that can't do VT — degrade to plain text
	}
	return true
}
