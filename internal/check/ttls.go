package check

import (
	"context"
	"errors"

	"github.com/authhound/probe/internal/radius"
)

// EAPTTLS runs a real EAP-TTLS authentication with inner PAP. Because the
// cleartext password travels inside the TLS tunnel, TTLS-PAP works against any
// backend password store — so it's the method that succeeds when a directory
// only holds hashed passwords that PEAP-MSCHAPv2 can't use. That contrast is the
// diagnostic: PEAP fails + TTLS-PAP works => the backend can't produce an NT hash.
type EAPTTLS struct {
	User       string
	Pass       string
	ServerName string
}

func (EAPTTLS) Name() string { return "eap-ttls" }

func (c EAPTTLS) Run(ctx context.Context, t Target) Result {
	if c.User == "" {
		return Result{
			Check: "eap-ttls", Status: StatusSkip,
			Summary: "No credentials supplied — skipped (pass --ttls user:pass to run it)",
		}
	}

	sess := &radius.EAPSession{
		Addr:     t.Address,
		Secret:   t.Secret,
		Timeout:  t.Timeout,
		Identity: c.User,
		Attrs:    commonAttrs(t),
	}

	res, err := sess.AuthEAPTTLS(ctx, c.User, c.Pass, c.ServerName)
	if err != nil {
		r := Result{
			Check: "eap-ttls", Status: StatusFail,
			Summary: "EAP-TTLS exchange did not complete",
			Detail:  "The tunnel or inner exchange broke before a verdict: " + err.Error() + ".",
		}
		if errors.Is(err, radius.ErrTimeout) {
			r = markTimeout(r)
		}
		return r
	}

	fields := map[string]string{}
	if res.Cert != nil && len(res.Cert.Chain) > 0 {
		fields["server_cert"] = res.Cert.Chain[0].Subject.CommonName
	}

	if res.Success {
		return applyAuthorization(Result{
			Check: "eap-ttls", Status: StatusPass, Fields: fields,
			Summary: "EAP-TTLS (inner PAP) authentication succeeded for " + c.User,
		}, res.Accept, t)
	}
	return Result{
		Check: "eap-ttls", Status: StatusFail, Fields: fields,
		Summary: "EAP-TTLS (inner PAP) authentication failed for " + c.User,
		Detail:  "Reason: " + res.Reason,
	}
}
