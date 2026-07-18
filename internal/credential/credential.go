// Package credential resolves a single secret value (the RADIUS shared secret or
// a user's password) from whichever safe source the operator chose, without ever
// requiring it on the command line.
//
// The whole point is to keep credentials out of shell history and `ps` output on
// the shared jump boxes this tool runs on. A value can come from, in precedence
// order:
//
//  1. an explicit flag: --secret-stdin, --secret-file, or the plain --secret VALUE
//  2. an environment variable (AUTHHOUND_RADIUS_SECRET / AUTHHOUND_RADIUS_PASSWORD)
//  3. an interactive no-echo prompt (when stdin is a terminal)
//
// The plain inline forms (--secret VALUE, --pap user:pass) still work for lab use
// but earn a one-line warning on a TTY, because they leak into history and ps.
//
// Nothing here logs, echoes, or returns the value except to the caller that asked
// for it; resolution errors never include the value itself.
package credential

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"
)

// Spec describes one credential to resolve and where it may come from. A caller
// fills in only the sources the operator actually provided.
type Spec struct {
	// Name is a human label used in the prompt and in error messages, never the
	// value. e.g. "shared secret" or "password for alice".
	Name string

	// Inline is the value supplied directly on the command line (the --secret
	// argument, or the ":pass" half of --pap user:pass). InlineSet distinguishes
	// an explicitly-empty value from an omitted one.
	Inline    string
	InlineSet bool

	// File is a --secret-file / --password-file path; empty if not given.
	File string

	// Stdin is true for --secret-stdin: read one line from standard input.
	Stdin bool

	// EnvVar is the environment variable consulted as a fallback; empty to skip.
	EnvVar string

	// Required makes a value with no source and no way to prompt an error. For
	// optional credentials (an auth method that simply wasn't requested) leave it
	// false and Resolve returns "".
	Required bool

	// Exclusive rejects giving more than one explicit flag source at once. Used
	// for the shared secret, whose --secret / --secret-file / --secret-stdin forms
	// are mutually exclusive; passwords leave it false so --password-file can act
	// as a fallback for a bare "user".
	Exclusive bool
}

// Prompter carries the terminal-facing dependencies so tests can drive resolution
// without a real TTY. The zero value is not usable; call Default.
type Prompter struct {
	Stderr       io.Writer
	Stdin        io.Reader
	IsTTY        func() bool
	ReadPassword func(prompt string) (string, error)
}

// Default returns a Prompter wired to the real process: prompts and warnings go
// to stderr, --secret-stdin reads os.Stdin, and prompts read without echo from
// the controlling terminal (works in Windows Terminal / PowerShell via x/term).
func Default() Prompter {
	return Prompter{
		Stderr: os.Stderr,
		Stdin:  os.Stdin,
		IsTTY:  func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		ReadPassword: func(prompt string) (string, error) {
			fmt.Fprint(os.Stderr, prompt)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return string(b), err
		},
	}
}

// Resolve returns the credential value for spec, applying the documented
// precedence. It emits a one-line WARN to stderr when the value came from an
// inline command-line form on a TTY. The value is never logged or echoed.
func (p Prompter) Resolve(spec Spec) (string, error) {
	if spec.Exclusive {
		n := 0
		if spec.InlineSet {
			n++
		}
		if spec.File != "" {
			n++
		}
		if spec.Stdin {
			n++
		}
		if n > 1 {
			return "", fmt.Errorf("choose only one of --%[1]s, --%[1]s-file, or --%[1]s-stdin", flagBase(spec.Name))
		}
	}

	switch {
	case spec.Stdin:
		return readStdin(p.Stdin)
	case spec.File != "":
		return readFile(spec.File)
	case spec.InlineSet:
		if p.IsTTY != nil && p.IsTTY() {
			fmt.Fprintf(p.Stderr, "WARN  %s given on the command line is visible in shell history and to `ps`; prefer %s or an interactive prompt.\n",
				spec.Name, saferForms(spec))
		}
		return spec.Inline, nil
	}

	if spec.EnvVar != "" {
		if v, ok := os.LookupEnv(spec.EnvVar); ok {
			return v, nil
		}
	}

	if p.IsTTY != nil && p.IsTTY() {
		return p.ReadPassword(fmt.Sprintf("Enter %s: ", spec.Name))
	}

	if spec.Required {
		hint := "provide it interactively (run in a terminal)"
		if spec.EnvVar != "" {
			hint = fmt.Sprintf("set %s, use --%[2]s-file, or provide it interactively (run in a terminal)", spec.EnvVar, flagBase(spec.Name))
		}
		return "", fmt.Errorf("no %s provided: %s", spec.Name, hint)
	}
	return "", nil
}

func readStdin(r io.Reader) (string, error) {
	if r == nil {
		return "", errors.New("no stdin available to read the credential from")
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("reading credential from stdin: %w", err)
	}
	return trimOneNewline(string(b)), nil
}

func readFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("refusing to read %s: it is readable by other users on this host (mode %#o); run: chmod 600 %s",
			path, info.Mode().Perm(), path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return trimOneNewline(string(b)), nil
}

// trimOneNewline removes exactly one trailing line ending (\n or \r\n) — no more,
// so a credential that legitimately ends in whitespace survives a here-doc.
func trimOneNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
		if strings.HasSuffix(s, "\r") {
			s = s[:len(s)-1]
		}
	}
	return s
}

// flagBase maps a Spec name to the flag stem used in help text. Only the shared
// secret is Exclusive and thus reaches this for the multi-source error.
func flagBase(name string) string {
	if strings.Contains(name, "secret") {
		return "secret"
	}
	return "password"
}

func saferForms(spec Spec) string {
	if spec.EnvVar != "" {
		return "$" + spec.EnvVar + ", --" + flagBase(spec.Name) + "-file,"
	}
	return "--" + flagBase(spec.Name) + "-file"
}
