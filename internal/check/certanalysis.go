package check

import (
	"crypto/x509"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const certExpiryWarnDays = 21

// analyzeCert turns a captured server-certificate chain into a Result: it flags
// expiry (the classic "Wi-Fi died overnight" outage) of the leaf and of any
// intermediate that was sent, a missing intermediate, a name mismatch against
// serverName, and reports the negotiated TLS version. Shared by the EAP
// server-cert check and RadSec.
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

	// Name validation: "match" (a SAN matches), "cn-only" (no SAN at all, but the
	// legacy Common Name matches — Windows accepts this, modern clients do not),
	// "mismatch", or "skipped".
	name := "skipped"
	switch {
	case serverName == "":
	case leaf.VerifyHostname(serverName) == nil:
		name = "match"
	case len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 && strings.EqualFold(leaf.Subject.CommonName, serverName):
		name = "cn-only"
	default:
		name = "mismatch"
	}
	fields["name_validation"] = name

	ch := assessChain(chain)
	fields["chain"] = ch.kind

	now := time.Now()
	daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
	tlsv := tlsVersionName(tlsVersion)

	// CA certificates the server sent are part of what clients validate: an
	// expired one breaks the handshake exactly like an expired leaf.
	var expiredInter, interSoon *x509.Certificate
	for _, c := range chain[1:] {
		if expiredInter == nil && now.After(c.NotAfter) {
			expiredInter = c
		}
		if interSoon == nil && !now.After(c.NotAfter) && int(c.NotAfter.Sub(now).Hours()/24) <= certExpiryWarnDays {
			interSoon = c
		}
	}

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
	case expiredInter != nil:
		return Result{
			Check: checkName, Status: StatusFail, Fields: fields,
			Summary: fmt.Sprintf("Intermediate certificate %q EXPIRED on %s", expiredInter.Subject.CommonName, expiredInter.NotAfter.UTC().Format("2006-01-02")),
			Detail: "The server certificate itself is still valid, but a CA certificate the server " +
				"sends with it has expired, so clients cannot build a valid chain. Install the " +
				"renewed CA certificate on the RADIUS server (certificate_file / the NPS machine store).",
		}
	case name == "mismatch":
		return Result{
			Check: checkName, Status: StatusFail, Fields: fields,
			Summary: fmt.Sprintf("Server certificate does not match the expected name %q", serverName),
			Detail: "Names the certificate is actually valid for: " + certNames(leaf) + ". " +
				"Clients configured to validate this server name will reject the handshake. " +
				"Either the wrong certificate is selected on the server, or the expected name " +
				"(--server-name) is out of date.",
		}
	case ch.kind == "leaf-only" && ch.intermediateLikely:
		return Result{
			Check: checkName, Status: StatusWarn, Fields: fields,
			Summary: "Server sent only its leaf certificate — the intermediate chain looks incomplete",
			Detail: fmt.Sprintf("The certificate was issued by %q, which looks like an intermediate CA "+
				"(it is not in the chain the server sent, and the certificate points at an issuer "+
				"download URL). Clients that don't already trust/cache that intermediate fail with "+
				"an 'unknown CA' error. Configure the server to present the full chain (leaf + "+
				"intermediates).", ch.issuer),
		}
	case daysLeft <= certExpiryWarnDays:
		return Result{
			Check: checkName, Status: StatusWarn, Fields: fields,
			Summary: fmt.Sprintf("Server certificate expires in %d days (%s)", daysLeft, leaf.NotAfter.UTC().Format("2006-01-02")),
			Detail: "Renew before it lapses. Continuous certificate-expiry alerting across every " +
				"server is part of AuthHound's monitoring tier.",
		}
	case interSoon != nil:
		return Result{
			Check: checkName, Status: StatusWarn, Fields: fields,
			Summary: fmt.Sprintf("Intermediate certificate %q expires in %d days (%s)", interSoon.Subject.CommonName,
				int(interSoon.NotAfter.Sub(now).Hours()/24), interSoon.NotAfter.UTC().Format("2006-01-02")),
			Detail: "The server certificate is fine, but the intermediate CA certificate sent with it " +
				"lapses soon and would break every client's chain validation. Install the renewed intermediate.",
		}
	case name == "cn-only":
		return Result{
			Check: checkName, Status: StatusWarn, Fields: fields,
			Summary: fmt.Sprintf("Server certificate matches %q by Common Name only — it has no Subject Alternative Name", serverName),
			Detail: "Windows supplicants accept a CN match, so this may work today; Android 11+, " +
				"iOS/macOS and most modern clients require the name in a DNS SAN and reject the " +
				"handshake. Reissue the certificate with subjectAltName = DNS:" + serverName + ".",
		}
	case serverName == "":
		return Result{
			Check: checkName, Status: StatusWarn, Fields: fields,
			Summary: fmt.Sprintf("Certificate captured — expiry and chain OK, but name validation was SKIPPED (%s)", tlsv),
			Detail: "No --server-name was given, so the probe could not check that this is the " +
				"certificate your clients expect. Names it is valid for: " + certNames(leaf) + ". " +
				"Re-run with --server-name <name> to validate it — real clients do, and a name " +
				"mismatch fails them even when expiry and chain are fine." + ch.note(),
		}
	default:
		return Result{
			Check: checkName, Status: StatusPass, Fields: fields,
			Summary: fmt.Sprintf("Server certificate valid for %d more days, name matches %q, %s (%s)",
				daysLeft, serverName, ch.phrase(), tlsv),
			Detail: strings.TrimSpace(ch.note()),
		}
	}
}

// chainAssessment describes what the server sent alongside its leaf.
type chainAssessment struct {
	kind               string // "self-signed", "complete", "leaf-only"
	issuer             string // leaf issuer CN (leaf-only)
	intermediateLikely bool   // leaf-only AND the missing issuer looks like an intermediate
}

// intermediateNameRe matches issuer names that are conventionally intermediate
// (issuing) CAs rather than roots. Belt and braces next to the AIA check.
var intermediateNameRe = regexp.MustCompile(`(?i)\b(intermediate|issuing|sub[- ]?ca|subordinate)\b`)

// assessChain classifies the chain. A lone leaf issued directly by a private
// root that clients already trust is the most common enterprise setup (single-
// tier AD CS, FreeRADIUS's own CA); nothing is missing there, so it must NOT be
// reported as an incomplete chain. Only when the leaf carries an AIA "CA
// Issuers" URL (every two-tier AD CS and public CA leaf does) or the issuer is
// named like an intermediate do we call the missing issuer a real gap.
func assessChain(chain []*x509.Certificate) chainAssessment {
	leaf := chain[0]
	if leaf.CheckSignatureFrom(leaf) == nil {
		return chainAssessment{kind: "self-signed"}
	}
	for _, c := range chain[1:] {
		if c.Subject.String() == leaf.Issuer.String() {
			return chainAssessment{kind: "complete"}
		}
	}
	a := chainAssessment{kind: "leaf-only", issuer: leaf.Issuer.CommonName}
	a.intermediateLikely = len(leaf.IssuingCertificateURL) > 0 || intermediateNameRe.MatchString(leaf.Issuer.String())
	return a
}

// phrase is the chain fragment of the PASS summary line.
func (a chainAssessment) phrase() string {
	if a.kind == "leaf-only" {
		return fmt.Sprintf("issuer %q not sent (fine if it is a root your clients trust)", a.issuer)
	}
	return "chain looks complete"
}

// note is the chain sentence appended to a detail when the leaf was sent alone
// but nothing indicates a missing intermediate.
func (a chainAssessment) note() string {
	if a.kind != "leaf-only" || a.intermediateLikely {
		return ""
	}
	return fmt.Sprintf(" Chain: only the server certificate was sent; its issuer %q is not included. "+
		"That is fine when %q is a root CA your clients already trust (single-tier PKI); if it "+
		"is an intermediate, configure the server to send it too.", a.issuer, a.issuer)
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

// chainLooksIncomplete is kept for callers/tests that only need the boolean
// view: true when the leaf's issuer is missing and looks like an intermediate.
func chainLooksIncomplete(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	a := assessChain(chain)
	return a.kind == "leaf-only" && a.intermediateLikely
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
