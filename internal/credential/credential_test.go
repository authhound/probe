package credential

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// newPrompter builds a Prompter with the terminal side mocked. tty controls
// whether an interactive prompt is considered possible; promptReturn is what the
// mocked no-echo read yields. The last prompt string is recorded in *lastPrompt.
func newPrompter(tty bool, stdin string, promptReturn string, lastPrompt *string) (Prompter, *bytes.Buffer) {
	stderr := &bytes.Buffer{}
	return Prompter{
		Stderr: stderr,
		Stdin:  strings.NewReader(stdin),
		IsTTY:  func() bool { return tty },
		ReadPassword: func(prompt string) (string, error) {
			if lastPrompt != nil {
				*lastPrompt = prompt
			}
			return promptReturn, nil
		},
	}, stderr
}

func TestResolveInlineNoTTY(t *testing.T) {
	p, stderr := newPrompter(false, "", "", nil)
	got, err := p.Resolve(Spec{Name: "shared secret", Inline: "s3cret", InlineSet: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cret" {
		t.Fatalf("got %q", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no warning off a TTY, got %q", stderr.String())
	}
}

func TestResolveInlineOnTTYWarns(t *testing.T) {
	p, stderr := newPrompter(true, "", "", nil)
	got, err := p.Resolve(Spec{Name: "shared secret", Inline: "s3cret", InlineSet: true, EnvVar: "AUTHHOUND_RADIUS_SECRET"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cret" {
		t.Fatalf("got %q", got)
	}
	warn := stderr.String()
	if !strings.HasPrefix(warn, "WARN") {
		t.Fatalf("expected a WARN line, got %q", warn)
	}
	if strings.Contains(warn, "s3cret") {
		t.Fatalf("the warning leaked the secret: %q", warn)
	}
}

func TestResolveFileTrimsOneNewline(t *testing.T) {
	cases := map[string]string{
		"plain":       "hunter2",
		"one-lf":      "hunter2\n",
		"one-crlf":    "hunter2\r\n",
		"trailing-sp": "hunter2 \n", // only the newline is stripped
		"two-lf":      "hunter2\n\n",
	}
	want := map[string]string{
		"plain": "hunter2", "one-lf": "hunter2", "one-crlf": "hunter2",
		"trailing-sp": "hunter2 ", "two-lf": "hunter2\n",
	}
	for name, content := range cases {
		path := filepath.Join(t.TempDir(), "sec")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		p, _ := newPrompter(false, "", "", nil)
		got, err := p.Resolve(Spec{Name: "shared secret", File: path})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != want[name] {
			t.Fatalf("%s: got %q want %q", name, got, want[name])
		}
	}
}

func TestResolveFileRefusesWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission model only")
	}
	path := filepath.Join(t.TempDir(), "sec")
	if err := os.WriteFile(path, []byte("hunter2"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, _ := newPrompter(false, "", "", nil)
	_, err := p.Resolve(Spec{Name: "shared secret", File: path})
	if err == nil {
		t.Fatal("expected refusal for a world-readable file")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("error should suggest chmod 600, got %q", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaked the secret: %q", err)
	}
}

func TestResolveEnvFallback(t *testing.T) {
	t.Setenv("AUTHHOUND_RADIUS_SECRET", "from-env")
	p, _ := newPrompter(false, "", "", nil)
	got, err := p.Resolve(Spec{Name: "shared secret", EnvVar: "AUTHHOUND_RADIUS_SECRET", Required: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-env" {
		t.Fatalf("got %q", got)
	}
}

func TestResolvePrecedenceFileBeatsEnv(t *testing.T) {
	t.Setenv("AUTHHOUND_RADIUS_SECRET", "from-env")
	path := filepath.Join(t.TempDir(), "sec")
	if err := os.WriteFile(path, []byte("from-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, _ := newPrompter(false, "", "", nil)
	got, err := p.Resolve(Spec{Name: "shared secret", File: path, EnvVar: "AUTHHOUND_RADIUS_SECRET"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-file" {
		t.Fatalf("file should win over env, got %q", got)
	}
}

func TestResolveStdinTrims(t *testing.T) {
	p, _ := newPrompter(false, "piped-secret\n", "", nil)
	got, err := p.Resolve(Spec{Name: "shared secret", Stdin: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != "piped-secret" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveExclusiveConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sec")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, _ := newPrompter(false, "", "", nil)
	_, err := p.Resolve(Spec{Name: "shared secret", Inline: "y", InlineSet: true, File: path, Exclusive: true})
	if err == nil {
		t.Fatal("expected a conflict error when two explicit sources are given")
	}
	if !strings.Contains(err.Error(), "only one") {
		t.Fatalf("got %q", err)
	}
}

func TestResolvePromptWhenNoSource(t *testing.T) {
	var prompt string
	p, _ := newPrompter(true, "", "typed-pw", &prompt)
	got, err := p.Resolve(Spec{Name: "password for alice", EnvVar: "AUTHHOUND_RADIUS_PASSWORD", Required: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != "typed-pw" {
		t.Fatalf("got %q", got)
	}
	if !strings.Contains(prompt, "password for alice") {
		t.Fatalf("prompt should name the credential, got %q", prompt)
	}
}

func TestResolveRequiredNoTTYErrors(t *testing.T) {
	p, _ := newPrompter(false, "", "", nil)
	_, err := p.Resolve(Spec{Name: "shared secret", EnvVar: "AUTHHOUND_RADIUS_SECRET", Required: true})
	if err == nil {
		t.Fatal("expected an error when required and no source and no TTY")
	}
	if !strings.Contains(err.Error(), "AUTHHOUND_RADIUS_SECRET") {
		t.Fatalf("error should point at the env var, got %q", err)
	}
}

func TestResolveOptionalMissingIsEmpty(t *testing.T) {
	p, _ := newPrompter(false, "", "", nil)
	got, err := p.Resolve(Spec{Name: "password for alice", EnvVar: "AUTHHOUND_RADIUS_PASSWORD"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("optional missing credential should be empty, got %q", got)
	}
}
