package check

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestBlastRADIUSSignedReplyPasses(t *testing.T) {
	addr := startFakeServer(t, &fakeServer{secret: "s3cret", signMsgAuth: true})
	r := (BlastRADIUS{}).Run(context.Background(), target(addr, "s3cret"))
	if r.Status != StatusPass {
		t.Fatalf("signed reply: got %s (%s), want pass", r.Status, r.Summary)
	}
	if r.Fields[BlastRADIUSField] != "signed" {
		t.Errorf("field: got %q, want signed", r.Fields[BlastRADIUSField])
	}
}

func TestBlastRADIUSUnsignedReplyWarns(t *testing.T) {
	// Default fakeServer does not sign replies — the unhardened case.
	addr := startFakeServer(t, &fakeServer{secret: "s3cret"})
	r := (BlastRADIUS{}).Run(context.Background(), target(addr, "s3cret"))
	if r.Status != StatusWarn {
		t.Fatalf("unsigned reply: got %s (%s), want warn", r.Status, r.Summary)
	}
	if r.Fields[BlastRADIUSField] != "unsigned" {
		t.Errorf("field: got %q, want unsigned", r.Fields[BlastRADIUSField])
	}
	// The exposed case must carry the paste-ready remediation.
	for _, want := range []string{"require_message_authenticator", "radsec test", "CVE-2024-3596"} {
		if !strings.Contains(r.Hint, want) {
			t.Errorf("hint missing %q; hint:\n%s", want, r.Hint)
		}
	}
	// Never leak the secret.
	for _, out := range []string{r.Summary, r.Detail, r.Hint} {
		if strings.Contains(out, "s3cret") {
			t.Errorf("secret leaked into result: %q", out)
		}
	}
}

func TestBlastRADIUSTimeoutSkips(t *testing.T) {
	addr := startFakeServer(t, &fakeServer{secret: "s3cret", silent: true})
	tgt := target(addr, "s3cret")
	tgt.Timeout = 300 * time.Millisecond
	r := (BlastRADIUS{}).Run(context.Background(), tgt)
	if r.Status != StatusSkip {
		t.Fatalf("timeout: got %s (%s), want skip", r.Status, r.Summary)
	}
	if r.Fields[TimeoutField] != "true" {
		t.Errorf("timeout result not marked as a timeout")
	}
}

func TestBlastRADIUSSecretMismatchWarns(t *testing.T) {
	// Server signs a Message-Authenticator, but with a different secret than the
	// probe uses: present but does not validate -> WARN pointing at the secret.
	addr := startFakeServer(t, &fakeServer{secret: "s3cret", wrongSecret: "other", signMsgAuth: true})
	r := (BlastRADIUS{}).Run(context.Background(), target(addr, "s3cret"))
	if r.Status != StatusWarn {
		t.Fatalf("mismatch: got %s (%s), want warn", r.Status, r.Summary)
	}
	if !strings.Contains(strings.ToLower(r.Summary), "shared secret") {
		t.Errorf("summary should point at the shared secret, got %q", r.Summary)
	}
}
