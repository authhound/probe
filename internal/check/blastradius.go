package check

import (
	"context"
	"errors"

	"github.com/authhound/probe/internal/radius"
)

// BlastRADIUSField carries the observed reply-signing posture in --json:
// "signed" when the server returned a valid Message-Authenticator, "unsigned"
// when it did not. Additive within schema major "1".
const BlastRADIUSField = "blastradius_posture"

// BlastRADIUS observes whether the server signs its replies with a
// Message-Authenticator (RFC 3579) — the mitigation for the RADIUS/UDP
// reply-forgery class known as BlastRADIUS (CVE-2024-3596, 2024).
//
// This is observation only: the probe always includes a Message-Authenticator
// in its own requests (see radius.Exchange), sends one normal Access-Request,
// and reports whether the reply came back signed. It never attempts any attack
// technique — presence/absence on a single exchange, nothing more. And it can
// only speak to behaviour toward THIS probe's client entry: a server may sign
// for one client and not another, so the result is scoped to what we can see.
type BlastRADIUS struct{}

func (BlastRADIUS) Name() string { return "blastradius-posture" }

func (BlastRADIUS) Run(ctx context.Context, t Target) Result {
	p, err := radius.NewAccessRequest(6)
	if err != nil {
		return Result{Check: "blastradius-posture", Status: StatusFail, Summary: "internal error: " + err.Error()}
	}
	p.AddString(radius.AttrUserName, "authhound-probe")
	// A throwaway password: we only inspect whether the reply is signed, not
	// whether auth succeeds — Access-Accept and Access-Reject are both fine.
	p.SetUserPassword("authhound-probe-blastradius-check", t.Secret)
	addCommon(p, t)

	reqAuth := p.Authenticator
	_, raw, _, err := radius.Exchange(t.Address, t.Secret, p, t.Timeout)
	if err != nil {
		if errors.Is(err, radius.ErrTimeout) {
			return markTimeout(Result{
				Check: "blastradius-posture", Status: StatusSkip,
				Summary: "Could not check reply signing — no reply; resolve reachability first",
			})
		}
		return Result{Check: "blastradius-posture", Status: StatusSkip, Summary: "Could not check reply signing: " + err.Error()}
	}

	present, valid := radius.VerifyMessageAuthenticator(raw, reqAuth, t.Secret)
	switch {
	case present && valid:
		return Result{
			Check: "blastradius-posture", Status: StatusPass,
			Summary: "Server signs its replies with Message-Authenticator (BlastRADIUS-hardened)",
			Detail: "The server returned a valid Message-Authenticator, so it is hardened " +
				"against the RADIUS/UDP reply-forgery class (CVE-2024-3596) on this client " +
				"entry. This only reflects behaviour toward this probe's client entry — a " +
				"server can be configured per-client.",
			Fields: map[string]string{BlastRADIUSField: "signed"},
		}
	case present && !valid:
		// A signature that doesn't verify almost always means the shared secret
		// differs; the shared-secret check diagnoses that. Flag it, don't claim
		// exposure we can't attribute.
		return Result{
			Check: "blastradius-posture", Status: StatusWarn,
			Summary: "Server sent a Message-Authenticator that did not validate — check the shared secret",
			Detail: "The reply carried a Message-Authenticator, but it did not verify with the " +
				"secret given to this probe. That is almost always a shared-secret mismatch " +
				"(see the shared-secret check), not a signing gap. Fix the secret and re-run.",
			Fields: map[string]string{BlastRADIUSField: "unsigned"},
		}
	default:
		return Result{
			Check: "blastradius-posture", Status: StatusWarn,
			Summary: "Server accepted our request but replied WITHOUT Message-Authenticator (BlastRADIUS-exposed)",
			Detail: "The server processed a signed Access-Request but did not sign its reply, so " +
				"RADIUS/UDP responses to this probe's client entry are forgeable by an on-path " +
				"attacker (CVE-2024-3596, \"BlastRADIUS\"). This reflects only what we can see " +
				"toward this probe's client entry; a server may sign for some clients and not others.",
			Hint:   blastRADIUSHint,
			Fields: map[string]string{BlastRADIUSField: "unsigned"},
		}
	}
}

// blastRADIUSHint is the paste-ready remediation for an unsigned reply. It names
// the concrete config for the two servers this audience runs, then points at
// RadSec as the durable fix. No secrets appear here.
const blastRADIUSHint = `Require Message-Authenticator on both directions:

FreeRADIUS — in each client{} block (clients.conf), then restart:
  client ... {
      require_message_authenticator = yes
      limit_proxy_state = yes
  }

Windows NPS — install the July 2024 security update (KB5040268 / your
build's equivalent) and enable Message-Authenticator enforcement; see
Microsoft's guidance for CVE-2024-3596.

RadSec (RADIUS/TLS) removes this class entirely — test it with:
  authhound-probe radsec test --server <host>

Background: https://blastradius.fail  /  CVE-2024-3596`
