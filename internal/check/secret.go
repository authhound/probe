package check

import (
	"context"
	"errors"

	"github.com/authhound/probe/internal/radius"
)

// SharedSecret sends an Access-Request and verifies the Response Authenticator
// on the reply. A verifying reply cryptographically proves the server holds the
// SAME shared secret this probe used — the single most common source of
// "it's rejecting everyone" tickets that turn out to be a secret mismatch.
//
// It disambiguates three states an admin usually can't tell apart:
//   - reply verifies            -> secret is correct
//   - reply doesn't verify      -> secret mismatch (rare; most servers just drop)
//   - no reply (timeout)        -> unreachable OR probe not whitelisted as a client
type SharedSecret struct{}

func (SharedSecret) Name() string { return "shared-secret" }

func (SharedSecret) Run(ctx context.Context, t Target) Result {
	p, err := radius.NewAccessRequest(2)
	if err != nil {
		return Result{Check: "shared-secret", Status: StatusFail, Summary: "internal error: " + err.Error()}
	}
	p.AddString(radius.AttrUserName, "authhound-probe")
	// A wrong password is fine here — we only care whether the reply is signed
	// with our secret, not whether auth succeeds.
	p.SetUserPassword("authhound-probe-secret-check", t.Secret)
	if t.NASIdentifier != "" {
		p.AddString(radius.AttrNASIdentifier, t.NASIdentifier)
	}

	reqAuth := p.Authenticator
	_, raw, _, err := radius.Exchange(t.Address, t.Secret, p, t.Timeout)
	if err != nil {
		if errors.Is(err, radius.ErrTimeout) {
			return Result{
				Check: "shared-secret", Status: StatusSkip,
				Summary: "Could not verify the shared secret — no reply",
				Detail: "Most RADIUS servers silently drop requests when the secret is " +
					"wrong OR when the client isn't whitelisted, so a timeout alone can't " +
					"tell them apart. Fix reachability/whitelisting first, then re-run.",
			}
		}
		return Result{Check: "shared-secret", Status: StatusSkip, Summary: "Could not verify the shared secret: " + err.Error()}
	}

	if radius.VerifyResponse(raw, reqAuth, t.Secret) {
		return Result{
			Check: "shared-secret", Status: StatusPass,
			Summary: "Shared secret is correct (reply signature verified)",
		}
	}
	return Result{
		Check: "shared-secret", Status: StatusFail,
		Summary: "Shared secret mismatch — the reply signature did not verify",
		Detail: "The server answered but signed its reply with a different secret than " +
			"the one given to this probe. Re-enter the secret on both the server's " +
			"client entry and here (retype, don't paste — trailing whitespace is a " +
			"classic cause).",
	}
}
