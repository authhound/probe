package radius

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// Exchange sends one Access-Request and waits for a reply. It returns the
// decoded reply, the raw reply bytes (for Response-Authenticator verification),
// and the round-trip time. A Message-Authenticator is always included, which
// is both good hygiene and required by servers hardened against BlastRADIUS
// (CVE-2024-3596).
func Exchange(addr string, secret string, p *Packet, timeout time.Duration) (reply *Packet, raw []byte, rtt time.Duration, err error) {
	wire, err := p.encode(secret)
	if err != nil {
		return nil, nil, 0, err
	}

	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, nil, 0, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, 0, err
	}

	start := time.Now()
	if _, err := conn.Write(wire); err != nil {
		return nil, nil, 0, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	rtt = time.Since(start)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil, nil, rtt, ErrTimeout
		}
		return nil, nil, rtt, err
	}

	raw = make([]byte, n)
	copy(raw, buf[:n])
	reply, err = decode(raw)
	if err != nil {
		return nil, raw, rtt, fmt.Errorf("decode reply: %w", err)
	}
	if reply.Identifier != p.Identifier {
		return reply, raw, rtt, errors.New("reply identifier mismatch")
	}
	return reply, raw, rtt, nil
}

// ErrTimeout means no reply arrived before the deadline — the server is
// unreachable, not listening, or (very commonly) does not have this probe
// whitelisted as a RADIUS client, in which case it silently drops the request.
var ErrTimeout = errors.New("no reply before timeout")
