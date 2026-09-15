package check

import (
	"context"

	"github.com/authhound/probe/internal/radius"
)

// SharedSecret verifies the Response Authenticator on the reply to the shared
// exchange (see BaseExchange). A verifying reply cryptographically proves the
// server holds the SAME shared secret this probe used — the single most common
// source of "it's rejecting everyone" tickets that turn out to be a secret
// mismatch.
//
// It disambiguates three states an admin usually can't tell apart:
//   - reply verifies            -> secret is correct
//   - reply doesn't verify      -> secret mismatch (rare; most servers just drop)
//   - no reply (timeout)        -> unreachable OR probe not whitelisted as a client
type SharedSecret struct {
	Base *BaseExchange // shared with Reachability; nil = send its own request
}

func (SharedSecret) Name() string { return "shared-secret" }

func (c SharedSecret) Run(ctx context.Context, t Target) Result {
	b := c.Base
	if b == nil || !b.done {
		b = &BaseExchange{}
		b.run(t)
	}
	if b.timedOut {
		return markTimeout(Result{
			Check: "shared-secret", Status: StatusSkip,
			Summary: "Could not verify the shared secret — no reply",
			Detail: "Most RADIUS servers silently drop requests when the secret is " +
				"wrong OR when the client isn't whitelisted, so a timeout alone can't " +
				"tell them apart. Fix reachability/whitelisting first, then re-run.",
		})
	}
	if b.err != nil {
		return Result{Check: "shared-secret", Status: StatusSkip, Summary: "Could not verify the shared secret: " + b.err.Error()}
	}

	if radius.VerifyResponse(b.raw, b.reqAuth, t.Secret) {
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
