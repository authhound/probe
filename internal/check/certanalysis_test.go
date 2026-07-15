package check

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCert builds a self-signed certificate with the given SANs and validity,
// enough for analyzeCert (which never verifies the chain to a root).
func testCert(t *testing.T, cn string, dnsNames []string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		// Self-signed: mark as CA so chainLooksIncomplete recognises the
		// self-signature and doesn't flag a missing intermediate.
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func healthyCert(t *testing.T, dnsNames ...string) *x509.Certificate {
	t.Helper()
	return testCert(t, "radius.corp.com", dnsNames,
		time.Now().Add(-24*time.Hour), time.Now().Add(365*24*time.Hour))
}

func TestAnalyzeCertNameMatch(t *testing.T) {
	chain := []*x509.Certificate{healthyCert(t, "radius.corp.com")}
	r := analyzeCert("server-cert", chain, tls.VersionTLS12, "radius.corp.com")
	if r.Status != StatusPass {
		t.Fatalf("name match: got %s (%s), want pass", r.Status, r.Summary)
	}
	if r.Fields["name_validation"] != "match" {
		t.Errorf("name_validation: got %q, want match", r.Fields["name_validation"])
	}
	if !strings.Contains(r.Summary, `name matches "radius.corp.com"`) {
		t.Errorf("summary should state the name matched: %q", r.Summary)
	}
}

func TestAnalyzeCertWildcardMatch(t *testing.T) {
	chain := []*x509.Certificate{healthyCert(t, "*.corp.com")}
	r := analyzeCert("server-cert", chain, tls.VersionTLS12, "radius.corp.com")
	if r.Status != StatusPass {
		t.Fatalf("wildcard match: got %s (%s), want pass", r.Status, r.Summary)
	}
}

func TestAnalyzeCertNameMismatch(t *testing.T) {
	chain := []*x509.Certificate{healthyCert(t, "other.corp.com")}
	r := analyzeCert("server-cert", chain, tls.VersionTLS12, "radius.corp.com")
	if r.Status != StatusFail {
		t.Fatalf("name mismatch: got %s (%s), want fail", r.Status, r.Summary)
	}
	if r.Fields["name_validation"] != "mismatch" {
		t.Errorf("name_validation: got %q, want mismatch", r.Fields["name_validation"])
	}
	if !strings.Contains(r.Detail, "other.corp.com") {
		t.Errorf("detail should list the names the cert is valid for: %q", r.Detail)
	}
}

// A certificate with no SAN must mismatch: modern clients (and Go) do not fall
// back to the Common Name, and the detail should say so.
func TestAnalyzeCertCNOnlyMismatch(t *testing.T) {
	chain := []*x509.Certificate{healthyCert(t /* no SANs */)}
	r := analyzeCert("server-cert", chain, tls.VersionTLS12, "radius.corp.com")
	if r.Status != StatusFail {
		t.Fatalf("CN-only: got %s (%s), want fail", r.Status, r.Summary)
	}
	if !strings.Contains(r.Detail, "CN only") {
		t.Errorf("detail should flag the missing SAN: %q", r.Detail)
	}
}

// No --server-name: everything else healthy must be a WARN that says name
// validation was skipped — never a silent "valid".
func TestAnalyzeCertNameValidationSkipped(t *testing.T) {
	chain := []*x509.Certificate{healthyCert(t, "radius.corp.com")}
	r := analyzeCert("server-cert", chain, tls.VersionTLS12, "")
	if r.Status != StatusWarn {
		t.Fatalf("skipped: got %s (%s), want warn", r.Status, r.Summary)
	}
	if r.Fields["name_validation"] != "skipped" {
		t.Errorf("name_validation: got %q, want skipped", r.Fields["name_validation"])
	}
	if !strings.Contains(r.Summary, "SKIPPED") {
		t.Errorf("summary must say name validation was skipped: %q", r.Summary)
	}
	if !strings.Contains(r.Detail, "--server-name") {
		t.Errorf("detail should tell the user which flag to add: %q", r.Detail)
	}
}

// Expiry outranks the name verdict: an expired cert is a FAIL about expiry even
// when a matching (or absent) name would otherwise decide, and the
// name_validation field still reports what the name check found.
func TestAnalyzeCertExpiredOutranksName(t *testing.T) {
	chain := []*x509.Certificate{testCert(t, "radius.corp.com", []string{"radius.corp.com"},
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))}
	r := analyzeCert("server-cert", chain, tls.VersionTLS12, "radius.corp.com")
	if r.Status != StatusFail || !strings.Contains(r.Summary, "EXPIRED") {
		t.Fatalf("expired: got %s (%s), want expiry fail", r.Status, r.Summary)
	}
	if r.Fields["name_validation"] != "match" {
		t.Errorf("name_validation: got %q, want match", r.Fields["name_validation"])
	}
}

// Name mismatch outranks the expiring-soon warning: both are wrong, but the
// mismatch is the hard failure.
func TestAnalyzeCertMismatchOutranksExpiringSoon(t *testing.T) {
	chain := []*x509.Certificate{testCert(t, "other.corp.com", []string{"other.corp.com"},
		time.Now().Add(-24*time.Hour), time.Now().Add(5*24*time.Hour))}
	r := analyzeCert("server-cert", chain, tls.VersionTLS12, "radius.corp.com")
	if r.Status != StatusFail || !strings.Contains(r.Summary, "does not match") {
		t.Fatalf("mismatch+expiring: got %s (%s), want name-mismatch fail", r.Status, r.Summary)
	}
}
