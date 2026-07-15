package check

import (
	"context"
	"errors"

	"github.com/authhound/probe/internal/radius"
)

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
		Addr:      t.Address,
		Secret:    t.Secret,
		Timeout:   t.Timeout,
		Identity:  "authhound-probe",
		Attrs:     commonAttrs(t),
		LocalAddr: t.LocalAddr,
	}

	captured, err := sess.InspectServerCert(ctx, c.ServerName)
	if err != nil {
		r := Result{
			Check: "server-cert", Status: StatusSkip,
			Summary: "Could not inspect the server certificate",
			Detail: "The PEAP/TLS handshake didn't get far enough to read the certificate: " +
				err.Error() + ". This is expected if the server doesn't offer PEAP or EAP-TLS, " +
				"or if reachability/secret checks above failed.",
		}
		if errors.Is(err, radius.ErrTimeout) {
			r = markTimeout(r)
		}
		return r
	}
	return analyzeCert("server-cert", captured.Chain, captured.TLSVersion)
}
