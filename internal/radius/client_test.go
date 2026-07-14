package radius

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestExchangeTimeoutCarriesLocalIP verifies that a timed-out Exchange returns
// a *TimeoutError that (a) still matches ErrTimeout for existing callers and
// (b) carries the socket's real local source IP for the registration hint.
func TestExchangeTimeoutCarriesLocalIP(t *testing.T) {
	// A bound-but-never-answering UDP socket: everything sent here times out.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	p, err := NewAccessRequest(1)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = Exchange(pc.LocalAddr().String(), "s3cret", p, 200*time.Millisecond)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout match, got %v", err)
	}
	var te *TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("want *TimeoutError, got %T", err)
	}
	if te.LocalIP != "127.0.0.1" {
		t.Errorf("LocalIP: got %q, want 127.0.0.1", te.LocalIP)
	}
}
