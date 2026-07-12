package radius

import (
	"errors"
	"time"
)

// WireSize returns the encoded byte length of the packet. When withMsgAuth is
// true it includes the 18-byte Message-Authenticator that Exchange always adds.
func (p *Packet) WireSize(withMsgAuth bool) int {
	n := 20 // header
	for _, a := range p.Attributes {
		n += 2 + len(a.Value)
	}
	if withMsgAuth {
		n += 18
	}
	return n
}

// padToWithProxyState appends Proxy-State attributes until the encoded packet
// (including the Message-Authenticator) reaches at least target bytes. Proxy-State
// is echoed unchanged by the server (RFC 2865), so a padded request produces a
// padded reply — exercising the path MTU in *both* directions.
func (p *Packet) padToWithProxyState(target int) {
	for {
		cur := p.WireSize(true)
		if cur >= target {
			return
		}
		valSize := target - cur - 2
		if valSize > 253 {
			valSize = 253
		}
		if valSize < 1 {
			valSize = 1
		}
		p.Add(AttrProxyState, make([]byte, valSize))
	}
}

// MTUReachable sends an Access-Request padded to ~target bytes and reports
// whether a reply came back — i.e. whether the network path carries RADIUS
// packets of that size in both directions. Any reply (even Access-Reject)
// counts; a timeout means the packet (or its reply) was dropped.
func MTUReachable(addr, secret string, target int, attrs []Attribute, timeout time.Duration) (ok bool, replied bool, err error) {
	p, err := NewAccessRequest(1)
	if err != nil {
		return false, false, err
	}
	p.AddString(AttrUserName, "authhound-probe")
	for _, a := range attrs {
		p.Add(a.Type, a.Value)
	}
	p.padToWithProxyState(target)

	_, _, _, err = Exchange(addr, secret, p, timeout)
	if err == nil {
		return true, true, nil
	}
	if errors.Is(err, ErrTimeout) {
		return false, false, nil // dropped — a size failure, not a hard error
	}
	return false, false, err // connection refused, etc. — real error
}
