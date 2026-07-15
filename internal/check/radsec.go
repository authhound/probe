package check

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/authhound/probe/internal/radius"
)

// RadSecReport dials a RadSec (RADIUS/TLS on TCP/2083) endpoint once and returns
// the diagnostic results: reachability + TLS handshake, the server certificate,
// and — if the tunnel comes up — a RADIUS exchange over it. RadSec's security is
// the TLS layer (often mutual), so an optional client cert can be supplied.
func RadSecReport(ctx context.Context, addr, certFile, keyFile, serverName string, timeout time.Duration) []Result {
	var clientCert *tls.Certificate
	if certFile != "" {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return []Result{{
				Check: "radsec", Status: StatusFail,
				Summary: "Could not load the client certificate/key",
				Detail:  "Error: " + err.Error() + ". Both files must be PEM (convert a .pfx/.p12 with openssl first).",
			}}
		}
		clientCert = &c
	}

	res := radius.DialRadSec(ctx, addr, clientCert, serverName, timeout)

	if !res.Connected {
		return []Result{{
			Check: "radsec-connect", Status: StatusFail,
			Summary: "RadSec endpoint is unreachable",
			Detail: res.Reason + ". Check the host/port (RadSec is TCP/2083), and that a firewall " +
				"isn't blocking it — RadSec is TCP, not UDP like classic RADIUS.",
		}}
	}

	var out []Result
	if res.TLSOK {
		out = append(out, Result{
			Check: "radsec-tls", Status: StatusPass,
			Summary: fmt.Sprintf("RadSec reachable; TLS handshake OK (%s)", tlsVersionName(res.TLSVersion)),
		})
	} else {
		out = append(out, Result{
			Check: "radsec-tls", Status: StatusFail,
			Summary: "Reached the endpoint, but the TLS handshake failed",
			Detail: "Reason: " + res.Reason + ". RadSec is usually mutual TLS — if it wants a client " +
				"certificate, supply one with --client-cert / --client-key.",
		})
	}

	if len(res.Cert) > 0 {
		out = append(out, analyzeCert("radsec-cert", res.Cert, res.TLSVersion, serverName))
	}

	if res.TLSOK {
		if res.RADIUSReplyOK {
			out = append(out, Result{
				Check: "radsec-radius", Status: StatusPass,
				Summary: "RADIUS-over-TLS exchange succeeded — the endpoint answers RADIUS",
			})
		} else {
			out = append(out, Result{
				Check: "radsec-radius", Status: StatusInfo,
				Summary: "TLS is up, but the endpoint didn't answer a RADIUS request over the tunnel",
				Detail: "It completed TLS but returned no RADIUS reply — it may only accept a specific " +
					"client-certificate identity, or RADIUS from known peers only. TLS reachability itself is fine.",
			})
		}
	}
	return out
}
