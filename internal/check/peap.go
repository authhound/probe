package check

import (
	"context"
	"fmt"
	"strconv"

	"github.com/authhound/probe/internal/radius"
)

// PEAPMSCHAPv2 runs a real PEAP-MSCHAPv2 authentication — the method most
// enterprise 802.1X networks actually use. It completes the TLS tunnel and the
// inner MSCHAPv2 exchange, then reports success, or decodes the MSCHAPv2 error
// on rejection (wrong password, disabled account, expired password, …).
//
// This is the "can my users actually log in?" test. It also confirms the
// primary-auth path independently of any MFA layer that may sit behind it.
type PEAPMSCHAPv2 struct {
	User       string
	Pass       string
	ServerName string
}

func (PEAPMSCHAPv2) Name() string { return "peap-mschapv2" }

func (c PEAPMSCHAPv2) Run(ctx context.Context, t Target) Result {
	if c.User == "" {
		return Result{
			Check: "peap-mschapv2", Status: StatusSkip,
			Summary: "No credentials supplied — skipped (pass --peap user:pass to run it)",
		}
	}

	sess := &radius.EAPSession{
		Addr:     t.Address,
		Secret:   t.Secret,
		Timeout:  t.Timeout,
		Identity: c.User,
		Attrs:    commonAttrs(t),
	}

	res, err := sess.AuthPEAPMSCHAPv2(ctx, c.User, c.Pass, c.ServerName)
	if err != nil {
		return Result{
			Check: "peap-mschapv2", Status: StatusFail,
			Summary: "PEAP-MSCHAPv2 exchange did not complete",
			Detail: "The tunnel or inner exchange broke before a verdict: " + err.Error() +
				". If reachability/secret above failed, fix those first; otherwise the server " +
				"may not offer PEAP-MSCHAPv2.",
		}
	}

	fields := map[string]string{}
	if res.Cert != nil && len(res.Cert.Chain) > 0 {
		fields["server_cert"] = res.Cert.Chain[0].Subject.CommonName
	}

	if res.Success {
		summary := "PEAP-MSCHAPv2 authentication succeeded for " + c.User
		detail := ""
		if res.ServerProved {
			detail = "The server also proved it holds this account's password (MSCHAPv2 mutual auth verified) — you're talking to the real RADIUS server, not an impostor."
		} else {
			detail = "Authentication succeeded, but the server's authenticator response did not verify against this password — unusual; worth a look if it persists."
		}
		return Result{Check: "peap-mschapv2", Status: StatusPass, Summary: summary, Detail: detail, Fields: fields}
	}

	if res.ErrorCode > 0 {
		fields["mschap_error"] = strconv.Itoa(res.ErrorCode)
	}
	return Result{
		Check: "peap-mschapv2", Status: StatusFail, Fields: fields,
		Summary: fmt.Sprintf("PEAP-MSCHAPv2 rejected %s", c.User),
		Detail:  "Reason: " + res.ErrorCause,
	}
}
