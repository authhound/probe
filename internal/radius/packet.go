// Package radius implements just enough of RFC 2865/3579 for an outside-in
// diagnostic client: build an Access-Request, hide a PAP password, add a
// Message-Authenticator, and verify the Response Authenticator on the reply.
//
// The probe acts as a NAS (network access server) talking to a RADIUS server,
// so it only ever *sends* Access-Requests and *reads* the replies.
package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

type Code byte

const (
	AccessRequest   Code = 1
	AccessAccept    Code = 2
	AccessReject    Code = 3
	AccessChallenge Code = 11
	StatusServer    Code = 12 // RFC 5997 liveness query; reply is an Access-Accept
)

func (c Code) String() string {
	switch c {
	case AccessRequest:
		return "Access-Request"
	case AccessAccept:
		return "Access-Accept"
	case AccessReject:
		return "Access-Reject"
	case AccessChallenge:
		return "Access-Challenge"
	case StatusServer:
		return "Status-Server"
	default:
		return fmt.Sprintf("Code(%d)", byte(c))
	}
}

// Attribute types used by the probe (RFC 2865 / 3579).
type AttrType byte

const (
	AttrUserName             AttrType = 1
	AttrUserPassword         AttrType = 2
	AttrNASIPAddress         AttrType = 4
	AttrNASPort              AttrType = 5
	AttrReplyMessage         AttrType = 18
	AttrState                AttrType = 24
	AttrProxyState           AttrType = 33 // echoed unchanged by the server (RFC 2865)
	AttrCalledStationID      AttrType = 30
	AttrCallingStationID     AttrType = 31
	AttrNASIdentifier        AttrType = 32
	AttrNASPortType          AttrType = 61
	AttrEAPMessage           AttrType = 79
	AttrMessageAuthenticator AttrType = 80
)

// NAS-Port-Type values (RFC 2865). Wireless-802.11 is what real APs send;
// including it makes the probe's request match the same network policies a
// real 802.1X client would.
const (
	NASPortEthernet      = 15
	NASPortWireless80211 = 19
	NASPortVirtual       = 5
)

type Attribute struct {
	Type  AttrType
	Value []byte
}

type Packet struct {
	Code          Code
	Identifier    byte
	Authenticator [16]byte
	Attributes    []Attribute

	// msgAuthOffset records where the Message-Authenticator value sits during
	// encode, so the zero placeholder can be overwritten with the real HMAC.
	// Not part of the wire format.
	msgAuthOffset int
}

func newAuthenticator() ([16]byte, error) {
	var a [16]byte
	_, err := rand.Read(a[:])
	return a, err
}

// NewAccessRequest creates an Access-Request with a fresh request authenticator.
func NewAccessRequest(id byte) (*Packet, error) {
	auth, err := newAuthenticator()
	if err != nil {
		return nil, err
	}
	return &Packet{Code: AccessRequest, Identifier: id, Authenticator: auth}, nil
}

// NewStatusServer creates a Status-Server (RFC 5997) liveness query with a fresh
// authenticator. It carries no User-Name or password — it is a pure "are you
// alive?" ping that a server answers with an Access-Accept without ever
// consuming an authentication attempt. Exchange always appends the
// Message-Authenticator that RFC 5997 requires.
func NewStatusServer(id byte) (*Packet, error) {
	auth, err := newAuthenticator()
	if err != nil {
		return nil, err
	}
	return &Packet{Code: StatusServer, Identifier: id, Authenticator: auth}, nil
}

func (p *Packet) Add(t AttrType, v []byte) {
	p.Attributes = append(p.Attributes, Attribute{Type: t, Value: v})
}

func (p *Packet) AddString(t AttrType, v string) {
	p.Add(t, []byte(v))
}

// Get returns the first attribute of type t, or nil.
func (p *Packet) Get(t AttrType) []byte {
	for _, a := range p.Attributes {
		if a.Type == t {
			return a.Value
		}
	}
	return nil
}

// GetAllString returns the concatenated string values of every attribute of
// type t (used for Reply-Message, which servers may split across attributes).
func (p *Packet) GetAllString(t AttrType) string {
	var out []byte
	for _, a := range p.Attributes {
		if a.Type == t {
			out = append(out, a.Value...)
		}
	}
	return string(out)
}

// AddEAP splits an EAP packet across as many EAP-Message attributes as needed
// (each attribute value is capped at 253 bytes). RFC 3579: a receiver
// concatenates them in order to reconstruct the EAP packet.
func (p *Packet) AddEAP(eap []byte) {
	for len(eap) > 0 {
		n := 253
		if len(eap) < n {
			n = len(eap)
		}
		p.Add(AttrEAPMessage, eap[:n])
		eap = eap[n:]
	}
}

// ConcatEAP reassembles the EAP packet from all EAP-Message attributes, in
// order.
func (p *Packet) ConcatEAP() []byte {
	var out []byte
	for _, a := range p.Attributes {
		if a.Type == AttrEAPMessage {
			out = append(out, a.Value...)
		}
	}
	return out
}

// SetUserPassword hides the password per RFC 2865 §5.2 and adds it as
// User-Password. Must be called after the authenticator is set.
func (p *Packet) SetUserPassword(password, secret string) {
	pw := []byte(password)
	// Pad to a multiple of 16.
	if len(pw)%16 != 0 || len(pw) == 0 {
		pad := 16 - (len(pw) % 16)
		if len(pw) == 0 {
			pad = 16
		}
		pw = append(pw, make([]byte, pad)...)
	}
	out := make([]byte, len(pw))
	prev := p.Authenticator[:]
	for i := 0; i < len(pw); i += 16 {
		h := md5.New()
		h.Write([]byte(secret))
		h.Write(prev)
		b := h.Sum(nil)
		for j := 0; j < 16; j++ {
			out[i+j] = pw[i+j] ^ b[j]
		}
		prev = out[i : i+16]
	}
	p.Add(AttrUserPassword, out)
}

// encode serializes the packet. If msgAuthSecret is non-empty, a
// Message-Authenticator (RFC 3579) is computed over the packet and appended.
func (p *Packet) encode(msgAuthSecret string) ([]byte, error) {
	attrs, withMsgAuth, err := p.encodeAttributes(msgAuthSecret != "")
	if err != nil {
		return nil, err
	}
	length := 20 + len(attrs)
	if length > 4096 {
		return nil, errors.New("radius: packet too large")
	}
	buf := make([]byte, 20+len(attrs))
	buf[0] = byte(p.Code)
	buf[1] = p.Identifier
	binary.BigEndian.PutUint16(buf[2:4], uint16(length))
	copy(buf[4:20], p.Authenticator[:])
	copy(buf[20:], attrs)

	if withMsgAuth {
		// The Message-Authenticator was encoded as 16 zero bytes; HMAC-MD5 the
		// whole packet keyed by the secret, then write it back in place.
		mac := hmac.New(md5.New, []byte(msgAuthSecret))
		mac.Write(buf)
		sum := mac.Sum(nil)
		copy(buf[p.msgAuthOffset:p.msgAuthOffset+16], sum)
	}
	return buf, nil
}

func (p *Packet) encodeAttributes(withMsgAuth bool) ([]byte, bool, error) {
	var out []byte
	for _, a := range p.Attributes {
		if len(a.Value) > 253 {
			return nil, false, fmt.Errorf("radius: attribute %d too long", a.Type)
		}
		out = append(out, byte(a.Type), byte(2+len(a.Value)))
		out = append(out, a.Value...)
	}
	if withMsgAuth {
		p.msgAuthOffset = 20 + len(out) + 2 // 20 header + attrs + type/len
		out = append(out, byte(AttrMessageAuthenticator), 18)
		out = append(out, make([]byte, 16)...)
	}
	return out, withMsgAuth, nil
}

// decode parses a reply packet. It does NOT verify anything; callers use
// VerifyResponse for that.
func decode(b []byte) (*Packet, error) {
	if len(b) < 20 {
		return nil, errors.New("radius: short packet")
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < 20 || length > len(b) {
		return nil, errors.New("radius: bad length")
	}
	p := &Packet{Code: Code(b[0]), Identifier: b[1]}
	copy(p.Authenticator[:], b[4:20])
	pos := 20
	for pos < length {
		if pos+2 > length {
			return nil, errors.New("radius: truncated attribute")
		}
		t := AttrType(b[pos])
		alen := int(b[pos+1])
		if alen < 2 || pos+alen > length {
			return nil, errors.New("radius: bad attribute length")
		}
		val := make([]byte, alen-2)
		copy(val, b[pos+2:pos+alen])
		p.Attributes = append(p.Attributes, Attribute{Type: t, Value: val})
		pos += alen
	}
	return p, nil
}

// VerifyResponse checks the Response Authenticator of a reply against the
// request authenticator and shared secret (RFC 2865 §3). A correct result
// proves the server holds the same shared secret we do. `raw` is the exact
// bytes received; `reqAuth` is the authenticator we sent.
func VerifyResponse(raw []byte, reqAuth [16]byte, secret string) bool {
	if len(raw) < 20 {
		return false
	}
	var got [16]byte
	copy(got[:], raw[4:20])
	// Recompute: MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
	h := md5.New()
	h.Write(raw[0:4])
	h.Write(reqAuth[:])
	h.Write(raw[20:])
	h.Write([]byte(secret))
	want := h.Sum(nil)
	return hmac.Equal(got[:], want)
}
