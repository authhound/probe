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
// chain, a name mismatch against serverName, and reports the negotiated TLS
// version. Shared by the EAP server-cert check and RadSec.
//
// serverName is the name the caller expects the certificate to be valid for
// (from --server-name). Empty means the operator asserted nothing, so name
// validation is skipped — and that is reported as a WARN, never as a silent
// PASS: "valid" without a name check is not what most readers would assume.
func analyzeCert(checkName string, chain []*x509.Certificate, tlsVersion uint16, serverName string) Result {
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

	nameErr := error(nil)
	switch {
	case serverName == "":
		fields["name_validation"] = "skipped"
	case leaf.VerifyHostname(serverName) == nil:
		fields["name_validation"] = "match"
	default:
		nameErr = leaf.VerifyHostname(serverName)
		fields["name_validation"] = "mismatch"
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
	case nameErr != nil:
		return Result{
			Check: checkName, Status: StatusFail, Fields: fields,
			Summary: fmt.Sprintf("Server certificate does not match the expected name %q", serverName),
			Detail: "Names the certificate is actually valid for: " + certNames(leaf) + ". " +
				"Clients configured to validate this server name will reject the handshake. " +
				"Either the wrong certificate is selected on the server, or the expected name " +
				"(--server-name) is out of date.",
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
	case serverName == "":
		return Result{
			Check: checkName, Status: StatusWarn, Fields: fields,
			Summary: fmt.Sprintf("Certificate captured — expiry and chain OK, but name validation was SKIPPED (%s)",
				tlsVersionName(tlsVersion)),
			Detail: "No --server-name was given, so the probe could not check that this is the " +
				"certificate your clients expect. Names it is valid for: " + certNames(leaf) + ". " +
				"Re-run with --server-name <name> to validate it — real clients do, and a name " +
				"mismatch fails them even when expiry and chain are fine.",
		}
	default:
		return Result{
			Check: checkName, Status: StatusPass, Fields: fields,
			Summary: fmt.Sprintf("Server certificate valid for %d more days, name matches %q, chain looks complete (%s)",
				daysLeft, serverName, tlsVersionName(tlsVersion)),
		}
	}
}

// certNames renders the names a certificate is actually valid for, for humans:
// SANs when present, else the legacy Common Name (marked as such, since modern
// clients ignore it).
func certNames(leaf *x509.Certificate) string {
	if len(leaf.DNSNames) > 0 {
		return strings.Join(leaf.DNSNames, ", ")
	}
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName + " (CN only — no SAN, which many clients reject outright)"
	}
	return "(none — the certificate carries no DNS name at all)"
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
