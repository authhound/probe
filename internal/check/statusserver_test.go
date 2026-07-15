package check

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestStatusServerReply: a server that answers the Status-Server query is
// reported PASS, marked supported, with no auth attempt consumed.
func TestStatusServerReply(t *testing.T) {
	addr := startFakeServer(t, &fakeServer{secret: "s3cret"})
	r := (StatusServer{}).Run(context.Background(), target(addr, "s3cret"))
	if r.Status != StatusPass {
		t.Fatalf("status-server reply: got %s (%s), want pass", r.Status, r.Summary)
	}
	if r.Fields["supported"] != "true" {
		t.Errorf("supported field: got %q, want true", r.Fields["supported"])
	}
	if strings.Contains(r.Summary+r.Detail, "s3cret") {
		t.Error("secret leaked into status-server output")
	}
}

// TestStatusServerNoSupport: silence (server without Status-Server enabled, or
// an unregistered probe) must be INFO — never FAIL — and defer to reachability.
func TestStatusServerNoSupport(t *testing.T) {
	addr := startFakeServer(t, &fakeServer{secret: "s3cret", silent: true})
	tgt := target(addr, "s3cret")
	tgt.Timeout = 300 * time.Millisecond
	r := (StatusServer{}).Run(context.Background(), tgt)
	if r.Status != StatusInfo {
		t.Fatalf("no Status-Server support: got %s, want info (never fail)", r.Status)
	}
	if r.Fields["supported"] != "false" {
		t.Errorf("supported field: got %q, want false", r.Fields["supported"])
	}
	if r.Fields[TimeoutField] != "true" {
		t.Errorf("timeout field: got %q, want true", r.Fields[TimeoutField])
	}
	if !strings.Contains(r.Detail, "status_server = yes") {
		t.Error("detail should mention enabling status_server = yes")
	}
}

// TestBindLocalAddrHonored: a Target with LocalAddr set still reaches the server,
// and on timeout the reported source IP reflects the bind (so the WS-3
// registration hint stays correct under --bind).
func TestBindLocalAddrHonored(t *testing.T) {
	laddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}

	// Reaches a live server when bound to the loopback source.
	addr := startFakeServer(t, &fakeServer{secret: "s3cret", goodUser: "alice", goodPass: "pw"})
	tgt := target(addr, "s3cret")
	tgt.LocalAddr = laddr
	if r := (Reachability{}).Run(context.Background(), tgt); r.Status != StatusPass {
		t.Fatalf("bound reachability: got %s (%s), want pass", r.Status, r.Summary)
	}

	// On timeout, the detected source IP is the bound address.
	silent := startFakeServer(t, &fakeServer{secret: "s3cret", silent: true})
	stgt := target(silent, "s3cret")
	stgt.Timeout = 300 * time.Millisecond
	stgt.LocalAddr = laddr
	r := (Reachability{}).Run(context.Background(), stgt)
	if r.Status != StatusFail {
		t.Fatalf("bound timeout: got %s, want fail", r.Status)
	}
	if r.Fields["source_ip"] != "127.0.0.1" {
		t.Errorf("source_ip under --bind: got %q, want 127.0.0.1", r.Fields["source_ip"])
	}
}
