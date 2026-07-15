package check

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/authhound/probe/internal/radius"
)

// StatusServer runs an RFC 5997 Status-Server liveness query. Unlike an
// Access-Request, it never consumes an authentication attempt on the server: a
// server that supports it answers with an Access-Accept and logs nothing about a
// user. It runs before the auth tests as a clean "is the server alive?" ping.
//
// It degrades gracefully. Many servers do not enable Status-Server, and — like
// any RADIUS request — an unregistered client is dropped silently, so a timeout
// here is ambiguous. It therefore never FAILs: a reply is a PASS, and silence is
// an INFO that defers to the reachability check below rather than guessing.
type StatusServer struct{}

func (StatusServer) Name() string { return "status-server" }

func (StatusServer) Run(ctx context.Context, t Target) Result {
	p, err := radius.NewStatusServer(1)
	if err != nil {
		return Result{Check: "status-server", Status: StatusInfo, Summary: "internal error building Status-Server request: " + err.Error()}
	}
	// NAS-Identifier only — Status-Server carries no User-Name or password
	// (RFC 5997). The Message-Authenticator it also requires is added by Exchange.
	if t.NASIdentifier != "" {
		p.AddString(radius.AttrNASIdentifier, t.NASIdentifier)
	}

	_, _, rtt, err := radius.Exchange(t.Address, t.Secret, p, t.Timeout, t.LocalAddr)
	if err == nil {
		return Result{
			Check: "status-server", Status: StatusPass,
			Summary: fmt.Sprintf("Server answered Status-Server in %dms (live; no auth attempt consumed)", rtt.Milliseconds()),
			Fields: map[string]string{
				"rtt_ms":    strconv.FormatInt(rtt.Milliseconds(), 10),
				"supported": "true",
			},
		}
	}
	// Anything short of a reply is reported as INFO, never FAIL: Status-Server is
	// a bonus liveness signal, and the reachability check is the authoritative one.
	fields := map[string]string{"supported": "false"}
	if errors.Is(err, radius.ErrTimeout) {
		fields[TimeoutField] = "true"
	}
	return Result{
		Check: "status-server", Status: StatusInfo, Fields: fields,
		Summary: "No Status-Server reply — the server may not have it enabled (harmless)",
		Detail: "Status-Server (RFC 5997) lets a monitor check liveness without " +
			"consuming an auth attempt. Two reasons for silence here, and they look " +
			"identical: the server doesn't have it turned on (in FreeRADIUS, set " +
			"status_server = yes in radiusd.conf), or it isn't answering this probe at " +
			"all — the reachability check below tells you which. Either way this is not " +
			"a failure; the auth tests still verify the server end to end.",
	}
}
