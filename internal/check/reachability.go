package check

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/authhound/probe/internal/radius"
)

// Reachability sends a minimal Access-Request and reports whether the server
// answered at all, plus the round-trip time. Any validly-formed reply — even
// an Access-Reject — proves reachability; RADIUS servers reject unknown users
// but still answer, whereas an unknown *client* (unwhitelisted probe) gets
// silence.
type Reachability struct{}

func (Reachability) Name() string { return "reachability" }

func (Reachability) Run(ctx context.Context, t Target) Result {
	p, err := radius.NewAccessRequest(1)
	if err != nil {
		return Result{Check: "reachability", Status: StatusFail, Summary: "internal error building request: " + err.Error()}
	}
	p.AddString(radius.AttrUserName, "authhound-probe")
	if t.NASIdentifier != "" {
		p.AddString(radius.AttrNASIdentifier, t.NASIdentifier)
	}

	_, _, rtt, err := radius.Exchange(t.Address, t.Secret, p, t.Timeout)
	fields := map[string]string{"rtt_ms": strconv.FormatInt(rtt.Milliseconds(), 10)}

	if err == nil {
		return Result{
			Check: "reachability", Status: StatusPass,
			Summary: fmt.Sprintf("RADIUS server answered in %dms", rtt.Milliseconds()),
			Fields:  fields,
		}
	}
	if errors.Is(err, radius.ErrTimeout) {
		return Result{
			Check: "reachability", Status: StatusFail,
			Summary: fmt.Sprintf("No reply from %s within %s", t.Address, t.Timeout),
			Detail: "The server is unreachable, not listening on this port, or it is " +
				"silently dropping this probe's requests — which happens when the " +
				"probe's IP is not whitelisted as a RADIUS client OR when the shared " +
				"secret is wrong (servers drop unverifiable requests without replying). " +
				"Check the client entry in clients.conf (FreeRADIUS) or RADIUS Clients " +
				"(NPS): both the IP and the secret must match, then retry.",
			Fields: fields,
		}
	}
	return Result{
		Check: "reachability", Status: StatusFail,
		Summary: "Could not reach the server: " + err.Error(),
		Fields:  fields,
	}
}
