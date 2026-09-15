package check

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/authhound/probe/internal/radius"
)

// Reachability sends the shared credential-shaped Access-Request (see
// BaseExchange) and reports whether the server answered at all, plus the
// round-trip time. Any validly-formed reply — even an Access-Reject — proves
// reachability; RADIUS servers reject unknown users but still answer, whereas
// an unknown *client* (unwhitelisted probe) gets silence.
//
// The datagram is retransmitted on a NAS-like schedule before "no reply" is
// declared, so a single lost packet reads as a WARN about loss, not as "server
// down". Latency is taken from the Status-Server reply when the server answered
// one (never delayed); otherwise from the rejected test login, which FreeRADIUS
// delays by reject_delay (1 s default) — the output says which.
type Reachability struct {
	Base *BaseExchange // shared with SharedSecret/BlastRADIUS; nil = standalone
}

func (Reachability) Name() string { return "reachability" }

func (c Reachability) Run(ctx context.Context, t Target) Result {
	b := c.Base
	if b == nil {
		b = &BaseExchange{}
	}
	b.resetForIteration()
	b.run(t)

	fields := map[string]string{"rtt_ms": strconv.FormatInt(b.rtt.Milliseconds(), 10)}
	if b.retransmits > 0 {
		fields["retransmits"] = strconv.Itoa(b.retransmits)
	}

	if b.err == nil {
		r := Result{Check: "reachability", Status: StatusPass, Fields: fields}
		if b.statusOK {
			fields["rtt_ms"] = strconv.FormatInt(b.statusRTT.Milliseconds(), 10)
			fields["rtt_source"] = "status-server"
			fields["auth_rtt_ms"] = strconv.FormatInt(b.rtt.Milliseconds(), 10)
			r.Summary = fmt.Sprintf("RADIUS server answered in %dms", b.statusRTT.Milliseconds())
		} else {
			fields["rtt_source"] = "access-reject"
			r.Summary = fmt.Sprintf("RADIUS server answered in %dms", b.rtt.Milliseconds())
			r.Detail = "Measured on a rejected test login. FreeRADIUS delays every Access-Reject " +
				"by reject_delay (1 s by default), so this figure usually includes that second; " +
				"enable Status-Server on the server to get an undelayed number."
		}
		if b.retransmits > 0 {
			r.Status = StatusWarn
			r.Summary += fmt.Sprintf(" — after %d retransmit(s)", b.retransmits)
			r.Detail = joinDetail(r.Detail, fmt.Sprintf(
				"The first datagram got no reply and had to be re-sent %d time(s): packets are "+
					"being lost between this host and the server. Real clients retransmit too, but a "+
					"lossy path is exactly what produces intermittent 802.1X failures; run with --count "+
					"to measure the loss rate.", b.retransmits))
		}
		return r
	}
	if b.timedOut {
		fields[TimeoutField] = "true"
		srcIP := "<this host's IP>"
		if b.localIP != "" {
			srcIP = b.localIP
			fields["source_ip"] = b.localIP
		}
		return Result{
			Check: "reachability", Status: StatusFail,
			Summary: fmt.Sprintf("No reply from %s within %s (sent %d times)", t.Address, t.Timeout, 1+b.retransmits),
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
	if errors.Is(b.err, radius.ErrTimeout) { // defensive: timedOut should already be set
		fields[TimeoutField] = "true"
	}
	return Result{
		Check: "reachability", Status: StatusFail,
		Summary: "Could not reach the server: " + b.err.Error(),
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
