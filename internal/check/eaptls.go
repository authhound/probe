package check

import "context"

// EAPTLSCert will initiate an EAP-TLS/PEAP handshake far enough to capture the
// RADIUS server's certificate chain and report expiry, completeness, and TLS
// version — the failure class behind a large share of 802.1X outages (expired
// server cert, missing intermediate, untrusted CA).
//
// It is deliberately NOT implemented in v1. Tunnelling a TLS handshake through
// EAP-Message attributes is the riskiest part of the probe, and shipping
// untested crypto would be worse than shipping nothing. The check exists so the
// framework and CLI already have its shape; it reports StatusSkip until the
// tested implementation lands.
type EAPTLSCert struct{}

func (EAPTLSCert) Name() string { return "eap-tls-cert" }

func (EAPTLSCert) Run(ctx context.Context, t Target) Result {
	return Result{
		Check:   "eap-tls-cert",
		Status:  StatusSkip,
		Summary: "EAP-TLS certificate inspection is coming in the next release",
		Detail: "This will capture the server certificate chain over a real EAP-TLS " +
			"handshake and flag expiry, missing intermediates, and weak TLS versions. " +
			"Continuous certificate-expiry alerting across every server is part of " +
			"AuthHound's monitoring tier.",
	}
}
