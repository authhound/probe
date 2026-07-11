package check

import (
	"context"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/authhound/probe/internal/radius"
)

const certExpiryWarnDays = 21

// ServerCert establishes the PEAP outer TLS tunnel and inspects the RADIUS
// server's certificate — expiry, chain completeness, and TLS version. Expired
// or soon-to-expire server certificates are the classic "Wi-Fi died overnight
// and nothing was changed" outage; a missing intermediate breaks clients that
// don't already cache it.
//
// This is read-only: the probe receives the certificate during the handshake
// and stops before sending any credential or client certificate.
type ServerCert struct {
	ServerName string
}

func (ServerCert) Name() string { return "server-cert" }

func (c ServerCert) Run(ctx context.Context, t Target) Result {
	sess := &radius.EAPSession{
		Addr:     t.Address,
		Secret:   t.Secret,
		Timeout:  t.Timeout,
		Identity: "authhound-probe",
		Attrs:    commonAttrs(t),
	}

	captured, err := sess.InspectServerCert(ctx, c.ServerName)
	if err != nil {
		return Result{
			Check: "server-cert", Status: StatusSkip,
			Summary: "Could not inspect the server certificate",
			Detail: "The PEAP/TLS handshake didn't get far enough to read the certificate: " +
				err.Error() + ". This is expected if the server doesn't offer PEAP or EAP-TLS, " +
				"or if reachability/secret checks above failed.",
		}
	}
	if len(captured.Chain) == 0 {
		return Result{Check: "server-cert", Status: StatusSkip, Summary: "Server presented no certificate"}
	}

	leaf := captured.Chain[0]
	fields := map[string]string{
		"tls_version": tlsVersionName(captured.TLSVersion),
		"subject":     leaf.Subject.CommonName,
		"not_after":   leaf.NotAfter.UTC().Format("2006-01-02"),
		"chain_len":   strconv.Itoa(len(captured.Chain)),
	}
	if sans := append(leaf.DNSNames, leaf.EmailAddresses...); len(sans) > 0 {
		fields["san"] = strings.Join(sans, ", ")
	}

	now := time.Now()
	daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)

	// Expiry is the headline finding.
	if now.After(leaf.NotAfter) {
		return Result{
			Check: "server-cert", Status: StatusFail, Fields: fields,
			Summary: fmt.Sprintf("Server certificate EXPIRED on %s", leaf.NotAfter.UTC().Format("2006-01-02")),
			Detail: "Every client rejects the handshake once the RADIUS server certificate " +
				"expires — this is the classic whole-site outage. Renew it and reselect it " +
				"in the server/policy config.",
		}
	}
	if now.Before(leaf.NotBefore) {
		return Result{
			Check: "server-cert", Status: StatusFail, Fields: fields,
			Summary: fmt.Sprintf("Server certificate is not yet valid (starts %s)", leaf.NotBefore.UTC().Format("2006-01-02")),
			Detail:  "The certificate's validity hasn't started — check the clock on the server and clients.",
		}
	}

	// Chain completeness heuristic: a non-self-signed leaf with no issuer in the
	// presented chain means clients that don't cache the intermediate will fail.
	if incomplete := chainLooksIncomplete(captured.Chain); incomplete {
		return Result{
			Check: "server-cert", Status: StatusWarn, Fields: fields,
			Summary: "Server sent only its leaf certificate — the intermediate chain looks incomplete",
			Detail: "Clients that don't already trust/cache the issuing intermediate will fail " +
				"with an 'unknown CA' error. Configure the server to present the full chain " +
				"(leaf + intermediates).",
		}
	}

	if daysLeft <= certExpiryWarnDays {
		return Result{
			Check: "server-cert", Status: StatusWarn, Fields: fields,
			Summary: fmt.Sprintf("Server certificate expires in %d days (%s)", daysLeft, leaf.NotAfter.UTC().Format("2006-01-02")),
			Detail: "Renew before it lapses. Continuous certificate-expiry alerting across every " +
				"server is part of AuthHound's monitoring tier.",
		}
	}

	return Result{
		Check: "server-cert", Status: StatusPass, Fields: fields,
		Summary: fmt.Sprintf("Server certificate valid for %d more days, chain looks complete (%s)",
			daysLeft, tlsVersionName(captured.TLSVersion)),
	}
}

func chainLooksIncomplete(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	leaf := chain[0]
	if leaf.CheckSignatureFrom(leaf) == nil {
		return false // self-signed leaf: unusual but not an "incomplete chain"
	}
	// Is the leaf's issuer present later in the chain?
	for _, c := range chain[1:] {
		if c.Subject.String() == leaf.Issuer.String() {
			return false
		}
	}
	return true
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
