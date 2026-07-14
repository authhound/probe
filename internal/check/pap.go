package check

import (
	"context"
	"errors"
	"strings"

	"github.com/authhound/probe/internal/radius"
)

// PAP performs a real PAP authentication with the supplied credentials and
// reports Accept vs Reject. It is skipped when no username is configured.
//
// PAP is the simplest auth method and a useful baseline: if PAP against the
// directory works but PEAP/EAP-TLS fails for real users, the problem is in the
// TLS/EAP layer, not reachability, secrets, or the backend password store —
// exactly the kind of hop-isolation the paid product automates.
type PAP struct {
	User string
	Pass string
}

func (PAP) Name() string { return "pap-auth" }

func (c PAP) Run(ctx context.Context, t Target) Result {
	if c.User == "" {
		return Result{
			Check: "pap-auth", Status: StatusSkip,
			Summary: "No credentials supplied — skipped (pass --pap user:pass to run it)",
		}
	}

	p, err := radius.NewAccessRequest(3)
	if err != nil {
		return Result{Check: "pap-auth", Status: StatusFail, Summary: "internal error: " + err.Error()}
	}
	p.AddString(radius.AttrUserName, c.User)
	p.SetUserPassword(c.Pass, t.Secret)
	addCommon(p, t)

	reply, _, _, err := radius.Exchange(t.Address, t.Secret, p, t.Timeout)
	if err != nil {
		if errors.Is(err, radius.ErrTimeout) {
			return markTimeout(Result{Check: "pap-auth", Status: StatusSkip, Summary: "No reply — resolve reachability first"})
		}
		return Result{Check: "pap-auth", Status: StatusFail, Summary: "PAP exchange failed: " + err.Error()}
	}

	switch reply.Code {
	case radius.AccessAccept:
		return Result{Check: "pap-auth", Status: StatusPass, Summary: "PAP authentication accepted for " + c.User}
	case radius.AccessReject:
		return Result{
			Check: "pap-auth", Status: StatusFail,
			Summary: "PAP authentication rejected for " + c.User,
			Detail: "The server processed the login and said no. Causes: wrong password; " +
				"the account can't be checked via PAP (e.g. the backend only stores an " +
				"NT hash); or a network policy denies this user. If PEAP works but PAP " +
				"doesn't, the policy simply may not permit PAP — that can be expected.",
		}
	case radius.AccessChallenge:
		// A challenge means either the server wants EAP, or (with a valid
		// password) it's a challenge-response second factor: MFA/OTP.
		if reply.Get(radius.AttrEAPMessage) != nil {
			return Result{
				Check: "pap-auth", Status: StatusWarn,
				Summary: "Server issued an EAP challenge — it expects EAP, not PAP here",
				Detail:  "This endpoint wants an EAP method (PEAP/EAP-TLS). The server-cert check exercises that path; PAP isn't meaningful here.",
			}
		}
		prompt := reply.GetAllString(radius.AttrReplyMessage)
		detail := "The server accepted the primary credentials and is now asking for a " +
			"second factor (OTP/passcode, or a push it just sent to the user's phone). " +
			"That means the RADIUS primary-auth path is healthy — the MFA layer is separate " +
			"and this probe intentionally does not complete second factors. For monitoring, " +
			"use a test account exempt from MFA so the primary path can be validated cleanly."
		if prompt != "" {
			detail = "Server prompt: \"" + strings.TrimSpace(prompt) + "\". " + detail
		}
		return Result{
			Check: "pap-auth", Status: StatusWarn,
			Summary: "Primary credentials accepted; server issued an MFA/second-factor challenge",
			Detail:  detail,
		}
	default:
		return Result{Check: "pap-auth", Status: StatusInfo, Summary: "Unexpected reply: " + reply.Code.String()}
	}
}
