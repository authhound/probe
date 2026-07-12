package radius

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
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

// tlsConfig builds the PEAP outer-tunnel TLS config. The server certificate is
// always captured for reporting. When abort is true, the handshake stops right
// after the certificate is received (used by the read-only cert check); when
// false, the handshake completes so inner authentication can run.
func (s *EAPSession) tlsConfig(serverName string, captured *CapturedCert, abort bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // we inspect the cert ourselves; trust is a separate check
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12, // EAP servers overwhelmingly speak <=1.2
		ServerName:         serverName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			captured.Chain = cs.PeerCertificates
			captured.TLSVersion = cs.Version
			captured.CipherSuite = cs.CipherSuite
			if abort {
				return errCertCaptured
			}
			return nil
		},
	}
}

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
	tc := tls.Client(conn, s.tlsConfig(serverName, captured, true))
	hsErr := tc.HandshakeContext(ctx)
	if len(captured.Chain) > 0 {
		return captured, nil
	}
	if hsErr != nil {
		return nil, fmt.Errorf("TLS handshake did not yield a certificate: %w", hsErr)
	}
	return nil, errors.New("no certificate presented by server")
}

// PEAPResult reports the outcome of a PEAP-MSCHAPv2 authentication attempt.
type PEAPResult struct {
	Success      bool
	ServerProved bool // the server's MSCHAPv2 authenticator response verified
	ErrorCode    int  // MSCHAPv2 error code on failure (e.g. 691), else 0
	ErrorCause   string
	Cert         *CapturedCert
}

// AuthPEAPMSCHAPv2 completes the PEAP tunnel and runs a real inner EAP-MSCHAPv2
// authentication with the given credentials. It reports success/failure, decodes
// the MSCHAPv2 error code on rejection, and verifies the server's authenticator
// response (mutual proof). The password is used only to build the response and
// is never transmitted or logged.
func (s *EAPSession) AuthPEAPMSCHAPv2(ctx context.Context, userName, password, serverName string) (*PEAPResult, error) {
	start, err := s.startTunnel(EAPTypePEAP)
	if err != nil {
		return nil, err
	}
	conn := &eapTLSConn{sess: s, eapType: EAPTypePEAP, curID: start.ID, fragSize: 1024}
	captured := &CapturedCert{}
	tc := tls.Client(conn, s.tlsConfig(serverName, captured, false))
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("PEAP tunnel handshake failed: %w", err)
	}
	res, err := runInnerMSCHAPv2(tc, userName, password)
	if err != nil {
		return nil, err
	}
	res.Cert = captured
	return res, nil
}

// runInnerMSCHAPv2 drives the inner EAP-MSCHAPv2 exchange inside the completed
// PEAP TLS tunnel (tc).
//
// PEAPv0 (the near-universal Microsoft variant, and FreeRADIUS's default) carries
// inner EAP packets HEADER-STRIPPED: the tunnel bytes are [EAP-Type, type-data],
// with the outer EAP Code/Identifier/Length omitted (PEAP reconstructs them).
// So we read/write inner packets as (type, data) pairs, one per TLS record.
func runInnerMSCHAPv2(tc innerConn, userName, password string) (*PEAPResult, error) {
	typ, data, err := readInner(tc)
	if err != nil {
		return nil, fmt.Errorf("reading first inner EAP request: %w", err)
	}
	dbg("inner req#1 type=%d datalen=%d raw=%x", typ, len(data), append([]byte{typ}, data...))

	// The server begins with an inner EAP-Identity request.
	if typ == EAPTypeIdentity {
		if err := writeInner(tc, EAPTypeIdentity, []byte(userName)); err != nil {
			return nil, err
		}
		typ, data, err = readInner(tc)
		if err != nil {
			return nil, fmt.Errorf("reading inner MSCHAPv2 challenge: %w", err)
		}
	}
	dbg("inner challenge type=%d datalen=%d", typ, len(data))
	if typ != EAPTypeMSCHAPv2 || len(data) < 1 || data[0] != 1 {
		return nil, fmt.Errorf("expected inner MSCHAPv2 Challenge, got EAP type %d", typ)
	}
	// MSCHAPv2 Challenge type-data: OpCode(1) ID(1) MS-Length(2) ValueSize(1) Challenge(16) Name...
	if len(data) < 5+16 || data[4] != 16 {
		return nil, errors.New("malformed MSCHAPv2 challenge")
	}
	msChapID := data[1]
	var authChallenge [16]byte
	copy(authChallenge[:], data[5:21])

	peer, err := NewPeerChallenge()
	if err != nil {
		return nil, err
	}
	ntResponse := GenerateNTResponse(authChallenge, peer, userName, password)
	if err := writeInner(tc, EAPTypeMSCHAPv2, buildMSCHAPResponse(msChapID, peer, ntResponse, userName)); err != nil {
		return nil, err
	}

	// The server now signals the outcome, either as an MSCHAPv2 Success/Failure
	// (with a decodable E=code) or straight as a PEAP Result-TLV. Loop over a few
	// packets so we handle whichever order a server uses (FreeRADIUS sends the
	// Result-TLV directly on failure; MSCHAPv2 Success then TLV on success).
	res := &PEAPResult{}
	for i := 0; i < 4; i++ {
		typ, data, err = readInner(tc)
		if err != nil {
			if res.ErrorCode != 0 || res.Success {
				return res, nil // we already have a verdict; a torn-down tail is fine
			}
			return nil, fmt.Errorf("reading MSCHAPv2 result: %w", err)
		}
		dbg("inner result type=%d datalen=%d", typ, len(data))

		switch {
		case typ == EAPTypeMSCHAPv2 && len(data) >= 1 && data[0] == 3: // Success
			want := GenerateAuthenticatorResponse(authChallenge, peer, ntResponse, userName, password)
			res.Success = true
			res.ServerProved = strings.Contains(string(data[1:]), want)
			_ = writeInner(tc, EAPTypeMSCHAPv2, []byte{3})
			return res, nil

		case typ == EAPTypeMSCHAPv2 && len(data) >= 1 && data[0] == 4: // Failure
			res.ErrorCode, res.ErrorCause = DecodeMSCHAPError(string(data[1:]))
			_ = writeInner(tc, EAPTypeMSCHAPv2, []byte{4})
			// keep looping for the Result-TLV that confirms the failure

		case typ == EAPTypeTLV: // PEAP Result-TLV — authoritative
			success := len(data) >= 6 && data[5] == 1
			_ = writeInner(tc, EAPTypeTLV, data) // echo the result TLV
			if success {
				res.Success = true
				return res, nil
			}
			res.Success = false
			if res.ErrorCause == "" {
				res.ErrorCause = "the server rejected the credentials — wrong password, or the account is disabled, expired, or otherwise not permitted."
			}
			return res, nil
		}
	}
	if res.ErrorCode != 0 {
		return res, nil
	}
	return nil, errors.New("no PEAP result after the MSCHAPv2 response")
}

// innerConn is the subset of net.Conn / tls.Conn that the inner exchange needs.
type innerConn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}

// readInner reads one header-stripped inner EAP packet (one TLS record) and
// returns its EAP type and type-data.
// readInner reads one inner EAP packet (one TLS record) and returns its EAP
// type and type-data. PEAPv0 mixes two framings: the inner method (MSCHAPv2) is
// header-stripped ([type, data]), while EAP-Identity and the Result-TLV arrive
// with a full EAP header ([code, id, len, len, type, data]). We detect a full
// header when byte 0 is a valid EAP code (1–4) and the length field matches the
// record — an MSCHAPv2 packet starts with 0x1a (26), which never collides.
func readInner(c innerConn) (typ byte, data []byte, err error) {
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil && n == 0 {
		return 0, nil, err
	}
	if n < 1 {
		return 0, nil, errors.New("empty inner EAP record")
	}
	dbg("readInner n=%d raw=%x", n, buf[:n])
	if n >= 5 && buf[0] >= 1 && buf[0] <= 4 {
		if length := int(buf[2])<<8 | int(buf[3]); length == n {
			return buf[4], append([]byte(nil), buf[5:n]...), nil // full EAP header
		}
	}
	return buf[0], append([]byte(nil), buf[1:n]...), nil // header-stripped
}

// writeInner sends one header-stripped inner EAP packet (type + data).
func writeInner(c innerConn, typ byte, data []byte) error {
	pkt := make([]byte, 0, 1+len(data))
	pkt = append(pkt, typ)
	pkt = append(pkt, data...)
	_, err := c.Write(pkt)
	return err
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

// dbg prints EAP debug lines when AHPROBE_DEBUG is set (development only).
func dbg(format string, args ...any) {
	if os.Getenv("AHPROBE_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[eap] "+format+"\n", args...)
	}
}
