package radius

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// EAPSession drives an EAP conversation over RADIUS: it acts as the NAS,
// sending Access-Requests carrying EAP-Message attributes and reading the
// Access-Challenge replies, tracking the RADIUS State attribute and EAP
// identifiers across round trips.
//
// It is used to establish the outer TLS tunnel of PEAP/EAP-TLS so the server's
// certificate can be inspected. Inner authentication (PEAP-MSCHAPv2, EAP-TLS
// client cert) builds on the same session and is a later milestone.
type EAPSession struct {
	Addr     string
	Secret   string
	Timeout  time.Duration
	Identity string
	Attrs    []Attribute // common NAS attributes added to every request

	radiusID byte
	state    []byte // RADIUS State attribute to echo back
	rounds   int
}

const maxEAPRounds = 60 // guards against a misbehaving server looping forever

// send transmits one Access-Request carrying eap and returns the reply's
// reassembled EAP packet plus the RADIUS reply code.
func (s *EAPSession) send(eap []byte) (*EAPPacket, Code, error) {
	s.rounds++
	if s.rounds > maxEAPRounds {
		return nil, 0, errors.New("eap: too many round trips")
	}
	s.radiusID++
	p, err := NewAccessRequest(s.radiusID)
	if err != nil {
		return nil, 0, err
	}
	p.AddString(AttrUserName, s.Identity)
	for _, a := range s.Attrs {
		p.Add(a.Type, a.Value)
	}
	p.AddEAP(eap)
	if s.state != nil {
		p.Add(AttrState, s.state)
	}

	reply, _, _, err := Exchange(s.Addr, s.Secret, p, s.Timeout)
	if err != nil {
		return nil, 0, err
	}
	if st := reply.Get(AttrState); st != nil {
		s.state = st
	}
	raw := reply.ConcatEAP()
	if len(raw) == 0 {
		// Access-Accept/Reject may carry no EAP-Message.
		return nil, reply.Code, nil
	}
	ep, err := ParseEAP(raw)
	if err != nil {
		return nil, reply.Code, err
	}
	return ep, reply.Code, nil
}

// startTunnel performs EAP-Identity then negotiates the requested tunnel type
// (PEAP or EAP-TLS), NAK-ing until the server offers it. It returns the first
// server EAP-Request for that type (the TLS "start").
func (s *EAPSession) startTunnel(eapType byte) (*EAPPacket, error) {
	idResp := (&EAPPacket{Code: EAPResponse, ID: 0, Type: EAPTypeIdentity, Data: []byte(s.Identity)}).Marshal()
	req, code, err := s.send(idResp)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 6; i++ {
		if req == nil {
			return nil, fmt.Errorf("server ended EAP early (%s) — it may not offer this method", code)
		}
		if req.Code == EAPFailure {
			return nil, errors.New("server rejected EAP negotiation (EAP-Failure)")
		}
		if req.Type == eapType {
			return req, nil // got our tunnel type (start)
		}
		// Server proposed a different type; NAK to the one we want.
		nak := (&EAPPacket{Code: EAPResponse, ID: req.ID, Type: EAPTypeNak, Data: []byte{eapType}}).Marshal()
		req, code, err = s.send(nak)
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("server never offered the requested EAP method")
}

// CapturedCert holds what the probe learned from the outer TLS handshake.
type CapturedCert struct {
	Chain       []*x509.Certificate
	TLSVersion  uint16
	CipherSuite uint16
}

var errCertCaptured = errors.New("certificate captured")

// InspectServerCert establishes the PEAP outer TLS tunnel far enough to receive
// and record the RADIUS server's certificate chain, then aborts (it never sends
// inner credentials or a client certificate). serverName sets SNI; empty is
// allowed. This is read-only: no authentication is attempted or completed.
func (s *EAPSession) InspectServerCert(ctx context.Context, serverName string) (*CapturedCert, error) {
	start, err := s.startTunnel(EAPTypePEAP)
	if err != nil {
		return nil, err
	}

	conn := &eapTLSConn{sess: s, eapType: EAPTypePEAP, curID: start.ID, fragSize: 1024}
	captured := &CapturedCert{}
	conf := &tls.Config{
		InsecureSkipVerify: true, // we inspect the cert ourselves; we are not authenticating
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12, // EAP servers overwhelmingly speak <=1.2
		ServerName:         serverName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			captured.Chain = cs.PeerCertificates
			captured.TLSVersion = cs.Version
			captured.CipherSuite = cs.CipherSuite
			return errCertCaptured // stop before we'd send a client cert
		},
	}
	tc := tls.Client(conn, conf)
	hsErr := tc.HandshakeContext(ctx)
	if len(captured.Chain) > 0 {
		return captured, nil
	}
	if hsErr != nil {
		return nil, fmt.Errorf("TLS handshake did not yield a certificate: %w", hsErr)
	}
	return nil, errors.New("no certificate presented by server")
}

// eapTLSConn adapts the half-duplex EAP-TLS transport to net.Conn so crypto/tls
// can run a handshake over it. TLS writes a flight (buffered), then reads —
// the read triggers a RADIUS exchange that ships the flight and returns the
// server's response flight, reassembled across EAP-TLS fragments.
type eapTLSConn struct {
	sess     *EAPSession
	eapType  byte
	curID    byte // EAP identifier of the last server request (echoed on responses)
	fragSize int
	inBuf    []byte // server TLS bytes not yet consumed by tls.Read
	outBuf   []byte // client TLS bytes not yet shipped
}

func (c *eapTLSConn) Write(p []byte) (int, error) {
	c.outBuf = append(c.outBuf, p...)
	return len(p), nil
}

func (c *eapTLSConn) Read(p []byte) (int, error) {
	if len(c.inBuf) == 0 {
		server, err := c.exchange(c.outBuf)
		if err != nil {
			return 0, err
		}
		c.outBuf = nil
		c.inBuf = server
	}
	n := copy(p, c.inBuf)
	c.inBuf = c.inBuf[n:]
	return n, nil
}

// exchange ships a full TLS flight as (possibly fragmented) EAP-TLS records and
// returns the reassembled server flight.
func (c *eapTLSConn) exchange(tlsOut []byte) ([]byte, error) {
	// Send our flight, fragmented to fragSize.
	total := len(tlsOut)
	off := 0
	first := true
	for {
		remaining := total - off
		frag := remaining
		if frag > c.fragSize {
			frag = c.fragSize
		}
		more := off+frag < total

		var flags byte
		if first && more {
			flags |= tlsFlagLength // total length included on the first of several fragments
		}
		if more {
			flags |= tlsFlagMore
		}
		data := []byte{flags}
		if flags&tlsFlagLength != 0 {
			var l [4]byte
			binary.BigEndian.PutUint32(l[:], uint32(total))
			data = append(data, l[:]...)
		}
		data = append(data, tlsOut[off:off+frag]...)

		resp := (&EAPPacket{Code: EAPResponse, ID: c.curID, Type: c.eapType, Data: data}).Marshal()
		req, code, err := c.sess.send(resp)
		if err != nil {
			return nil, err
		}
		off += frag
		first = false

		if more {
			// Server should ACK with an empty EAP-TLS request; advance the id.
			if req == nil {
				return nil, fmt.Errorf("server did not ACK a fragment (%s)", code)
			}
			c.curID = req.ID
			continue
		}
		// Last fragment sent; the server's reply begins its flight.
		return c.receive(req, code)
	}
}

// receive reassembles the server's flight, ACKing fragments as needed.
func (c *eapTLSConn) receive(req *EAPPacket, code Code) ([]byte, error) {
	var server []byte
	for {
		if req == nil {
			// No EAP payload (e.g. Access-Accept/Reject); nothing more to read.
			return server, nil
		}
		if req.Code == EAPFailure {
			return nil, errors.New("server sent EAP-Failure during TLS handshake")
		}
		if req.Type != c.eapType || len(req.Data) < 1 {
			return nil, fmt.Errorf("unexpected EAP packet (type %d) during handshake", req.Type)
		}
		c.curID = req.ID
		flags := req.Data[0]
		payload := req.Data[1:]
		if flags&tlsFlagLength != 0 {
			if len(payload) < 4 {
				return nil, errors.New("eap-tls: truncated length header")
			}
			payload = payload[4:]
		}
		server = append(server, payload...)

		if flags&tlsFlagMore == 0 {
			return server, nil // full flight received
		}
		// More fragments: ACK with an empty EAP-TLS response.
		ack := (&EAPPacket{Code: EAPResponse, ID: c.curID, Type: c.eapType, Data: []byte{0}}).Marshal()
		var err error
		req, code, err = c.sess.send(ack)
		if err != nil {
			return nil, err
		}
	}
}

// net.Conn boilerplate — the transport is message-based, so these are no-ops.
func (c *eapTLSConn) Close() error                     { return nil }
func (c *eapTLSConn) LocalAddr() net.Addr              { return netAddr{} }
func (c *eapTLSConn) RemoteAddr() net.Addr             { return netAddr{} }
func (c *eapTLSConn) SetDeadline(time.Time) error      { return nil }
func (c *eapTLSConn) SetReadDeadline(time.Time) error  { return nil }
func (c *eapTLSConn) SetWriteDeadline(time.Time) error { return nil }

type netAddr struct{}

func (netAddr) Network() string { return "eap-radius" }
func (netAddr) String() string  { return "eap-radius" }
