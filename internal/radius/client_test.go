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
	_, _, _, err = Exchange(pc.LocalAddr().String(), "s3cret", p, 200*time.Millisecond, nil)
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

// TestExchangeRetransmits verifies that a datagram lost on the way is re-sent
// (same socket, same Identifier) and the eventual reply is accepted, with the
// retransmit counted — a single drop must not read as "server down".
func TestExchangeRetransmits(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// Drop the first datagram, answer the second with a minimal Access-Reject.
	go func() {
		buf := make([]byte, 4096)
		seen := 0
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			seen++
			if seen < 2 || n < 20 {
				continue
			}
			reply := make([]byte, 20)
			reply[0], reply[1] = 3, buf[1]
			reply[3] = 20
			_, _ = pc.WriteTo(reply, addr)
		}
	}()

	p, err := NewAccessRequest(7)
	if err != nil {
		t.Fatal(err)
	}
	res, err := ExchangeR(pc.LocalAddr().String(), "s3cret", p, 2500*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("expected a reply after retransmit, got %v", err)
	}
	if res.Retransmits != 1 {
		t.Errorf("retransmits: got %d, want 1", res.Retransmits)
	}
	if res.Reply == nil || res.Reply.Identifier != 7 {
		t.Errorf("reply not matched to the request")
	}
}

// TestRetransmitScheduleFitsTimeout pins the schedule: no retries when the
// timeout cannot fit one; otherwise two re-sends inside the deadline.
func TestRetransmitScheduleFitsTimeout(t *testing.T) {
	if s := retransmitSchedule(time.Second); s != nil {
		t.Errorf("1s: want no retransmits, got %v", s)
	}
	// 2s: one retry, and only after FreeRADIUS's 1s reject_delay window.
	if s := retransmitSchedule(2 * time.Second); len(s) != 1 || s[0] != 1500*time.Millisecond {
		t.Errorf("2s: got %v, want [1.5s]", s)
	}
	s := retransmitSchedule(5 * time.Second)
	if len(s) != 2 || s[0] != 2*time.Second || s[1] != 3500*time.Millisecond {
		t.Errorf("5s: got %v, want [2s 3.5s]", s)
	}
}

// TestResultTLVOnlyEchoesStatus: the PEAP Result-TLV acknowledgement must carry
// a Result TLV and nothing else, whatever the server packed next to it (Windows
// NPS adds a Crypto-Binding TLV; echoing it back is invalid).
func TestResultTLVOnlyEchoesStatus(t *testing.T) {
	server := []byte{0x80, 0x03, 0x00, 0x02, 0x00, 0x01, // Result TLV: success
		0x80, 0x0c, 0x00, 0x38} // start of a Crypto-Binding TLV (type 12)
	server = append(server, make([]byte, 56)...)
	got := resultTLV(server)
	want := []byte{0x80, 0x03, 0x00, 0x02, 0x00, 0x01}
	if string(got) != string(want) {
		t.Errorf("ack = %x, want %x", got, want)
	}
	if f := resultTLV([]byte{0x80, 0x03, 0x00, 0x02, 0x00, 0x02}); f[5] != 2 {
		t.Errorf("failure status not preserved: %x", f)
	}
}
