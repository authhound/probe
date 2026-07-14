package radius

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
)

// EAP-TTLS (RFC 5281) establishes the same outer TLS tunnel as PEAP, but the
// inner authentication is carried as Diameter AVPs rather than tunnelled EAP.
// The common (and most useful) inner method is PAP: the cleartext password is
// safe because the TLS tunnel encrypts it, and PAP works against *any* backend
// password store — including SSHA/bcrypt hashes that MSCHAPv2 can't use. So if
// PEAP-MSCHAPv2 fails but TTLS-PAP succeeds, the backend simply can't produce
// the NT hash MSCHAPv2 needs.

// TTLSResult reports the outcome of an EAP-TTLS (inner PAP) authentication.
type TTLSResult struct {
	Success bool
	Reason  string
	Cert    *CapturedCert
	Accept  *Packet // final Access-Accept, for authorization attributes; may be nil
}

// AuthEAPTTLS completes the EAP-TTLS tunnel and authenticates with inner PAP.
// The password is sent as a Diameter AVP *inside* the TLS tunnel (never over the
// wire in the clear) and is never logged.
func (s *EAPSession) AuthEAPTTLS(ctx context.Context, userName, password, serverName string) (*TTLSResult, error) {
	start, err := s.startTunnel(EAPTypeTTLS)
	if err != nil {
		return &TTLSResult{Reason: "the server did not offer EAP-TTLS (" + err.Error() + ")"}, nil
	}
	conn := &eapTLSConn{sess: s, eapType: EAPTypeTTLS, curID: start.ID, fragSize: 1024}
	captured := &CapturedCert{}
	tc := tls.Client(conn, s.tlsConfig(serverName, captured, false))
	if err := tc.HandshakeContext(ctx); err != nil {
		return &TTLSResult{Reason: "EAP-TTLS tunnel handshake failed: " + err.Error(), Cert: captured}, nil
	}

	// Send the inner PAP credentials as Diameter AVPs through the tunnel.
	if _, err := tc.Write(ttlsInnerPAP(userName, password)); err != nil {
		return nil, err
	}
	code, err := conn.exchangeAppData()
	if err != nil {
		return nil, fmt.Errorf("reading EAP-TTLS result: %w", err)
	}
	switch code {
	case AccessAccept:
		return &TTLSResult{Success: true, Cert: captured, Accept: s.lastReply}, nil
	case AccessReject:
		return &TTLSResult{Success: false, Cert: captured,
			Reason: "the server rejected the login — wrong password, or the account/policy denies it. " +
				"(TTLS-PAP works against hashed password stores, so a reject here is usually the credential itself.)"}, nil
	default:
		return &TTLSResult{Success: false, Cert: captured, Reason: "unexpected reply: " + code.String()}, nil
	}
}

// ttlsInnerPAP builds the inner Diameter AVPs for TTLS-PAP: User-Name (code 1)
// and User-Password (code 2), both mandatory, cleartext (the tunnel protects
// them). RFC 5281 / RFC 6733 AVP framing.
func ttlsInnerPAP(userName, password string) []byte {
	return append(diameterAVP(1, []byte(userName)), diameterAVP(2, []byte(password))...)
}

func diameterAVP(code uint32, data []byte) []byte {
	length := 8 + len(data) // 4 code + 1 flags + 3 length, no vendor id
	padded := (length + 3) &^ 3
	out := make([]byte, padded)
	binary.BigEndian.PutUint32(out[0:4], code)
	out[4] = 0x40 // Mandatory flag
	out[5] = byte(length >> 16)
	out[6] = byte(length >> 8)
	out[7] = byte(length)
	copy(out[8:], data)
	return out
}
