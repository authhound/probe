package check

import (
	"context"
	"errors"

	"github.com/authhound/probe/internal/radius"
)

// PAP performs a real PAP authentication with the supplied credentials and
// reports Accept vs Reject. It is skipped when no username is configured.
//
// PAP is the simplest auth method and a useful baseline: if PAP against the
// directory works but PEAP/EAP-TLS fails for real users, the problem is in the
// TLS/EAP layer, not reachability, secrets, or the backend password store —
// exactly the kind of hop-isolation the paid product automates.
type PAP struct{}

func (PAP) Name() string { return "pap-auth" }

func (PAP) Run(ctx context.Context, t Target) Result {
	if t.Username == "" {
		return Result{
			Check: "pap-auth", Status: StatusSkip,
			Summary: "No credentials supplied — skipped (pass --pap user:pass to run it)",
		}
	}

	p, err := radius.NewAccessRequest(3)
	if err != nil {
		return Result{Check: "pap-auth", Status: StatusFail, Summary: "internal error: " + err.Error()}
	}
	p.AddString(radius.AttrUserName, t.Username)
	p.SetUserPassword(t.Password, t.Secret)
	if t.NASIdentifier != "" {
		p.AddString(radius.AttrNASIdentifier, t.NASIdentifier)
	}

	reply, _, _, err := radius.Exchange(t.Address, t.Secret, p, t.Timeout)
	if err != nil {
		if errors.Is(err, radius.ErrTimeout) {
			return Result{Check: "pap-auth", Status: StatusSkip, Summary: "No reply — resolve reachability first"}
		}
		return Result{Check: "pap-auth", Status: StatusFail, Summary: "PAP exchange failed: " + err.Error()}
	}

	switch reply.Code {
	case radius.AccessAccept:
		return Result{Check: "pap-auth", Status: StatusPass, Summary: "PAP authentication accepted for " + t.Username}
	case radius.AccessReject:
		return Result{
			Check: "pap-auth", Status: StatusFail,
			Summary: "PAP authentication rejected for " + t.Username,
			Detail: "The server processed the login and said no. Causes: wrong password; " +
				"the account can't be checked via PAP (e.g. the backend only stores an " +
				"NT hash); or a network policy denies this user. If PEAP works but PAP " +
				"doesn't, the policy simply may not permit PAP — that can be expected.",
		}
	case radius.AccessChallenge:
		return Result{
			Check: "pap-auth", Status: StatusWarn,
			Summary: "Server issued a challenge — it expects EAP, not PAP here",
			Detail:  "This endpoint wants an EAP method (PEAP/EAP-TLS). PAP testing isn't meaningful against it; use the EAP checks (coming soon) instead.",
		}
	default:
		return Result{Check: "pap-auth", Status: StatusInfo, Summary: "Unexpected reply: " + reply.Code.String()}
	}
}
