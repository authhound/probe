package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/authhound/probe/internal/radius"
)

// EAPTLS runs a real EAP-TLS authentication using a client certificate + key.
// EAP-TLS is certificate-only (no password): the TLS handshake is the login. The
// check reports success, or a plain-English reason on failure — most commonly an
// untrusted CA or an expired/rejected client certificate.
//
// It is skipped unless a client cert is supplied. The private key is read from
// disk, used only to complete the handshake, and never transmitted.
type EAPTLS struct {
	CertFile   string
	KeyFile    string
	ServerName string
}

func (EAPTLS) Name() string { return "eap-tls" }

func (c EAPTLS) Run(ctx context.Context, t Target) Result {
	if c.CertFile == "" {
		return Result{
			Check: "eap-tls", Status: StatusSkip,
			Summary: "No client certificate supplied — skipped (pass --client-cert and --client-key to run it)",
		}
	}

	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return Result{
			Check: "eap-tls", Status: StatusFail,
			Summary: "Could not load the client certificate/key",
			Detail: "Error: " + err.Error() + ". Both files must be PEM. If you have a " +
				".pfx/.p12 (a common Windows export), convert it first — see the README's " +
				"EAP-TLS section for the one-line openssl commands.",
		}
	}

	// The outer EAP identity for EAP-TLS is conventionally the certificate's
	// subject; use it so server logs and policies line up.
	identity := "authhound-probe"
	if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
		if leaf.Subject.CommonName != "" {
			identity = leaf.Subject.CommonName
		} else if len(leaf.EmailAddresses) > 0 {
			identity = leaf.EmailAddresses[0]
		}
	}

	sess := &radius.EAPSession{
		Addr:     t.Address,
		Secret:   t.Secret,
		Timeout:  t.Timeout,
		Identity: identity,
		Attrs:    commonAttrs(t),
	}

	res, err := sess.AuthEAPTLS(ctx, cert, c.ServerName)
	if err != nil {
		r := Result{Check: "eap-tls", Status: StatusFail, Summary: "EAP-TLS exchange failed: " + err.Error()}
		if errors.Is(err, radius.ErrTimeout) {
			r = markTimeout(r)
		}
		return r
	}

	fields := map[string]string{"identity": identity}
	if res.Cert != nil && len(res.Cert.Chain) > 0 {
		fields["server_cert"] = res.Cert.Chain[0].Subject.CommonName
	}

	if res.Success {
		return applyAuthorization(Result{
			Check: "eap-tls", Status: StatusPass, Fields: fields,
			Summary: fmt.Sprintf("EAP-TLS authentication succeeded (client cert %q accepted)", identity),
		}, res.Accept, t)
	}
	return Result{
		Check: "eap-tls", Status: StatusFail, Fields: fields,
		Summary: "EAP-TLS authentication failed",
		Detail:  "Reason: " + res.Reason,
	}
}
