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
	addCommon(p, t)

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
		srcIP := "<this host's IP>"
		var te *radius.TimeoutError
		if errors.As(err, &te) && te.LocalIP != "" {
			srcIP = te.LocalIP
			fields["source_ip"] = te.LocalIP
		}
		return Result{
			Check: "reachability", Status: StatusFail,
			Summary: fmt.Sprintf("No reply from %s within %s", t.Address, t.Timeout),
			Detail: "Silence has three causes, and the first two look identical from " +
				"here — a server drops the request without replying in both cases. In " +
				"order of likelihood: 1) this probe isn't registered as a RADIUS client " +
				"on the server (the most common first-run cause — fix below); 2) the " +
				"shared secret is wrong (also silent, so a timeout can't tell 1 and 2 " +
				"apart); 3) the server is down, not listening on this port, or a " +
				"firewall is dropping the UDP. Register the client first, re-run; if it " +
				"still times out, re-enter the secret on both ends, then check the " +
				"network path.",
			Hint:   registrationHint(srcIP),
			Fields: fields,
		}
	}
	return Result{
		Check: "reachability", Status: StatusFail,
		Summary: "Could not reach the server: " + err.Error(),
		Fields:  fields,
	}
}

// secretPlaceholder stands in for the shared secret in the registration hint.
// The real value must never be rendered (doc rule: secrets never appear in
// output), so the snippet stays paste-ready except for this one token.
const secretPlaceholder = "<the secret you passed to this probe>"

// registrationHint builds the paste-ready "register this probe as a RADIUS
// client" snippet with the detected source IP filled in. srcIP is the local
// address of the socket that just timed out — the exact IP the server saw
// (unless NAT rewrote it, which the hint calls out).
func registrationHint(srcIP string) string {
	return fmt.Sprintf(`If this probe isn't registered as a RADIUS client yet, that's the most
likely cause — servers silently drop requests from unknown clients.

FreeRADIUS — add to clients.conf and restart:
  client authhound-probe {
      ipaddr = %[1]s
      secret = %[2]s
  }

Windows NPS — PowerShell (elevated), or NPS console → RADIUS Clients → New:
  New-NpsRadiusClient -Name "authhound-probe" -Address "%[1]s" -SharedSecret "%[2]s"

Cloud/hosted RADIUS — register client IP %[1]s and the same shared
secret in the vendor's admin UI (see their documentation).

Note: if NAT sits between this host and the server, the server sees a
different source IP — register the post-NAT address instead.`, srcIP, secretPlaceholder)
}
