package radius

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// ExchangeResult is what one Access-Request round trip produced.
type ExchangeResult struct {
	Reply       *Packet
	Raw         []byte        // exact bytes received (for Response-Authenticator verification)
	RTT         time.Duration // first send -> reply (or -> deadline on timeout)
	Retransmits int           // how many times the datagram had to be re-sent before a reply
}

// retransmitSchedule returns the offsets from the first send at which the same
// datagram is re-sent when nothing has arrived yet (RFC 5080 §2.2.1: a NAS
// retransmits the identical packet, same Identifier and Request Authenticator).
// One lost datagram therefore no longer reads as "server down".
//
// No retransmit fires before 1.5 s: FreeRADIUS delays every Access-Reject by
// reject_delay (1 s by default), and a retransmit inside that window is a
// duplicate the server discards while the real reply is still on its way — it
// would be reported as loss that never happened. Offsets are 40% and 70% of
// the timeout (never below that floor), and only when they leave at least
// 300 ms before the deadline for the reply; a timeout too short to fit a
// retry gets none.
func retransmitSchedule(timeout time.Duration) []time.Duration {
	const earliest = 1500 * time.Millisecond
	const margin = 300 * time.Millisecond
	var out []time.Duration
	for _, off := range []time.Duration{timeout * 4 / 10, timeout * 7 / 10} {
		if off < earliest {
			off = earliest
		}
		if off > timeout-margin {
			break
		}
		if len(out) > 0 && off <= out[len(out)-1] {
			continue
		}
		out = append(out, off)
	}
	return out
}

// Exchange sends one Access-Request and waits for a reply. It returns the
// decoded reply, the raw reply bytes (for Response-Authenticator verification),
// and the round-trip time. A Message-Authenticator is always included, which
// is both good hygiene and required by servers hardened against BlastRADIUS
// (CVE-2024-3596). See ExchangeR for the retransmit count.
func Exchange(addr string, secret string, p *Packet, timeout time.Duration, localAddr net.Addr) (reply *Packet, raw []byte, rtt time.Duration, err error) {
	res, err := ExchangeR(addr, secret, p, timeout, localAddr)
	if res == nil {
		return nil, nil, 0, err
	}
	return res.Reply, res.Raw, res.RTT, err
}

// ExchangeR is Exchange with the full result, including how many retransmits
// were needed. The datagram is re-sent on the retransmitSchedule from the same
// socket (same source port, Identifier and Request Authenticator), so the
// server's duplicate detection works exactly as it does for a real NAS.
//
// localAddr, when non-nil, is the source address the UDP socket binds to
// (the --bind flag) — the way to pin the outgoing interface on a multi-homed
// host. The chosen source IP is what the RADIUS server sees, and it is exactly
// what TimeoutError.LocalIP reports back so the registration hint stays correct.
func ExchangeR(addr string, secret string, p *Packet, timeout time.Duration, localAddr net.Addr) (*ExchangeResult, error) {
	wire, err := p.encode(secret)
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{LocalAddr: localAddr}
	conn, err := dialer.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	res := &ExchangeResult{}
	start := time.Now()
	deadline := start.Add(timeout)
	sched := retransmitSchedule(timeout)

	if _, err := conn.Write(wire); err != nil {
		return res, err
	}

	buf := make([]byte, 4096)
	for {
		next := deadline
		if len(sched) > 0 {
			if t := start.Add(sched[0]); t.Before(next) {
				next = t
			}
		}
		if err := conn.SetReadDeadline(next); err != nil {
			return res, err
		}
		n, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if len(sched) > 0 && time.Now().Before(deadline) {
					sched = sched[1:]
					if _, werr := conn.Write(wire); werr != nil {
						return res, werr
					}
					res.Retransmits++
					continue
				}
				res.RTT = time.Since(start)
				return res, &TimeoutError{LocalIP: localIP(conn)}
			}
			return res, err
		}
		res.RTT = time.Since(start)
		raw := make([]byte, n)
		copy(raw, buf[:n])
		reply, err := decode(raw)
		if err != nil {
			res.Raw = raw
			return res, fmt.Errorf("decode reply: %w", err)
		}
		if reply.Identifier != p.Identifier {
			// A stale or stray datagram on our port: not our reply, keep waiting.
			continue
		}
		res.Raw, res.Reply = raw, reply
		return res, nil
	}
}

// ErrTimeout means no reply arrived before the deadline — the server is
// unreachable, not listening, or (very commonly) does not have this probe
// whitelisted as a RADIUS client, in which case it silently drops the request.
var ErrTimeout = errors.New("no reply before timeout")

// TimeoutError is the concrete error Exchange returns on timeout. It carries
// the local source IP the OS chose for the (already-dialed) socket, so callers
// can tell the admin exactly which address to register as a RADIUS client.
// errors.Is(err, ErrTimeout) matches it, so existing checks need no change.
type TimeoutError struct{ LocalIP string }

func (e *TimeoutError) Error() string        { return ErrTimeout.Error() }
func (e *TimeoutError) Is(target error) bool { return target == ErrTimeout }

// localIP extracts the socket's local address, without the ephemeral port.
func localIP(conn net.Conn) string {
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
		return ua.IP.String()
	}
	return ""
}
