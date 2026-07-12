package check

import (
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const certExpiryWarnDays = 21

// analyzeCert turns a captured server-certificate chain into a Result: it flags
// expiry (the classic "Wi-Fi died overnight" outage), an incomplete intermediate
// chain, and reports the negotiated TLS version. Shared by the EAP server-cert
// check and RadSec.
func analyzeCert(checkName string, chain []*x509.Certificate, tlsVersion uint16) Result {
	if len(chain) == 0 {
		return Result{Check: checkName, Status: StatusSkip, Summary: "Server presented no certificate"}
	}
	leaf := chain[0]
	fields := map[string]string{
		"tls_version": tlsVersionName(tlsVersion),
		"subject":     leaf.Subject.CommonName,
		"not_after":   leaf.NotAfter.UTC().Format("2006-01-02"),
		"chain_len":   strconv.Itoa(len(chain)),
	}
	if sans := append(leaf.DNSNames, leaf.EmailAddresses...); len(sans) > 0 {
		fields["san"] = strings.Join(sans, ", ")
	}

	now := time.Now()
	daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)

	switch {
	case now.After(leaf.NotAfter):
		return Result{
			Check: checkName, Status: StatusFail, Fields: fields,
			Summary: fmt.Sprintf("Server certificate EXPIRED on %s", leaf.NotAfter.UTC().Format("2006-01-02")),
			Detail: "Every client rejects the handshake once the RADIUS server certificate " +
				"expires — this is the classic whole-site outage. Renew it and reselect it " +
				"in the server/policy config.",
		}
	case now.Before(leaf.NotBefore):
		return Result{
			Check: checkName, Status: StatusFail, Fields: fields,
			Summary: fmt.Sprintf("Server certificate is not yet valid (starts %s)", leaf.NotBefore.UTC().Format("2006-01-02")),
			Detail:  "The certificate's validity hasn't started — check the clock on the server and clients.",
		}
	case chainLooksIncomplete(chain):
		return Result{
			Check: checkName, Status: StatusWarn, Fields: fields,
			Summary: "Server sent only its leaf certificate — the intermediate chain looks incomplete",
			Detail: "Clients that don't already trust/cache the issuing intermediate will fail " +
				"with an 'unknown CA' error. Configure the server to present the full chain " +
				"(leaf + intermediates).",
		}
	case daysLeft <= certExpiryWarnDays:
		return Result{
			Check: checkName, Status: StatusWarn, Fields: fields,
			Summary: fmt.Sprintf("Server certificate expires in %d days (%s)", daysLeft, leaf.NotAfter.UTC().Format("2006-01-02")),
			Detail: "Renew before it lapses. Continuous certificate-expiry alerting across every " +
				"server is part of AuthHound's monitoring tier.",
		}
	default:
		return Result{
			Check: checkName, Status: StatusPass, Fields: fields,
			Summary: fmt.Sprintf("Server certificate valid for %d more days, chain looks complete (%s)",
				daysLeft, tlsVersionName(tlsVersion)),
		}
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
