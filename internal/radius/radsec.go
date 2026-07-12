package radius

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// RadSecResult reports what the probe learned about a RadSec (RADIUS/TLS,
// RFC 6614) endpoint on TCP/2083.
type RadSecResult struct {
	Connected     bool // TCP connection established
	TLSOK         bool // TLS handshake completed
	TLSVersion    uint16
	Cert          []*x509.Certificate
	RADIUSReplyOK bool   // a RADIUS request over the tunnel got a reply
	Reason        string // failure detail when a stage didn't pass
}

// DialRadSec connects to a RadSec endpoint, completes the TLS handshake
// (presenting clientCert if given), captures the server certificate, and — if
// the tunnel comes up — sends one RADIUS Access-Request over it to confirm the
// RADIUS layer answers. Read-only: no state is changed on the server.
func DialRadSec(ctx context.Context, addr string, clientCert *tls.Certificate, serverName string, timeout time.Duration) *RadSecResult {
	res := &RadSecResult{}
	d := net.Dialer{Timeout: timeout}
	tcp, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Reason = "TCP connect to " + addr + " failed: " + err.Error()
		return res
	}
	defer tcp.Close()
	res.Connected = true
	_ = tcp.SetDeadline(time.Now().Add(timeout))

	captured := &captureState{}
	conf := &tls.Config{
		InsecureSkipVerify: true, // we inspect the cert ourselves; trust is reported separately
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			captured.chain = cs.PeerCertificates
			captured.version = cs.Version
			return nil
		},
	}
	if clientCert != nil {
		cc := *clientCert
		conf.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cc, nil }
	}

	tc := tls.Client(tcp, conf)
	if err := tc.HandshakeContext(ctx); err != nil {
		res.Cert = captured.chain // may still have the server cert
		res.TLSVersion = captured.version
		res.Reason = explainTLSError(err)
		return res
	}
	res.TLSOK = true
	res.TLSVersion = captured.version
	res.Cert = captured.chain

	// RadSec uses the fixed shared secret "radsec" (RFC 6614 §2.3).
	if replied, err := radiusOverStream(tc, "radsec", timeout); err == nil && replied {
		res.RADIUSReplyOK = true
	}
	return res
}

type captureState struct {
	chain   []*x509.Certificate
	version uint16
}

// radiusOverStream sends one Access-Request over an established stream (TCP/TLS)
// and reports whether a RADIUS reply came back. RADIUS-over-TCP frames each
// packet with the 2-byte length in the header (RFC 6613).
func radiusOverStream(conn net.Conn, secret string, timeout time.Duration) (bool, error) {
	p, err := NewAccessRequest(1)
	if err != nil {
		return false, err
	}
	p.AddString(AttrUserName, "authhound-probe")
	wire, err := p.encode(secret)
	if err != nil {
		return false, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(wire); err != nil {
		return false, err
	}

	var hdr [20]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return false, err
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < 20 || length > 4096 {
		return false, errors.New("radsec: bad reply length")
	}
	buf := make([]byte, length)
	copy(buf, hdr[:])
	if length > 20 {
		if _, err := io.ReadFull(conn, buf[20:]); err != nil {
			return false, err
		}
	}
	if _, err := decode(buf); err != nil {
		return false, err
	}
	return true, nil
}
