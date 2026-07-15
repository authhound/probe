// Package check defines the probe's diagnostic framework: a Check produces a
// Result, a Runner executes a Plan of Checks with a safety rate ceiling, a
// PlanSource decides which checks to run, and a ResultSink decides what happens
// to the results.
//
// v1 ships only the local implementations (flags -> plan, results -> terminal).
// The premium "connect to cloud" mode is the SAME Runner with a cloud-backed
// PlanSource and an additional CloudSink — no rearchitecting, which is the
// whole point of these interfaces existing now.
package check

import (
	"context"
	"net"
	"time"
)

// Status is the outcome of a single check.
type Status string

const (
	StatusPass Status = "pass" // the thing works / is reachable / is valid
	StatusFail Status = "fail" // the thing is broken — actionable
	StatusWarn Status = "warn" // works, but something is off (e.g. cert expiring)
	StatusInfo Status = "info" // neutral observation (latency, TLS version)
	StatusSkip Status = "skip" // not run (e.g. no credentials given)
)

// Result is the structured output of a check. It is intentionally free of any
// secret: credentials, shared secrets, and full certificates never appear here,
// so a Result is always safe to print, log, or (in premium) upload.
type Result struct {
	Check    string            `json:"check"`
	Status   Status            `json:"status"`
	Summary  string            `json:"summary"`          // one plain-English line
	Detail   string            `json:"detail,omitempty"` // optional extra context
	Hint     string            `json:"hint,omitempty"`   // multi-line, paste-ready remediation; formatting is significant, never contains secrets
	Fields   map[string]string `json:"fields,omitempty"` // e.g. rtt_ms, tls_version
	Duration time.Duration     `json:"duration_ns,omitempty"`

	// Authorization is set by auth checks that reached an Access-Accept: the
	// decoded authorization attributes the server returned (VLAN/Filter-Id/…)
	// plus the outcome of any --expect-vlan/--expect-attr assertions. Additive;
	// present only on a successful authentication that carried attributes or was
	// asked to assert on them.
	Authorization *Authorization `json:"authorization,omitempty"`
}

// Target holds the connection info for one RADIUS server — everything a check
// needs to reach it. Credentials live on the individual auth checks (PAP, PEAP,
// …), not here, so different methods can test different accounts and future
// protocols carry their own auth shape. Assembled from local config/flags (v1)
// or, later, a signed plan from the cloud (premium) — the Check never knows which.
type Target struct {
	Address       string // host:port
	Secret        string
	Timeout       time.Duration
	NASIdentifier string

	// LocalAddr is the source address to bind outgoing sockets to (--bind), for
	// pinning the outgoing interface on a multi-homed host. nil = OS default.
	// Whatever source IP results is what the server sees and what the
	// registration hint reports.
	LocalAddr net.Addr

	// NAS attributes make the probe's request look like a real 802.1X client so
	// server network policies (which key on these) evaluate the same way.
	NASPortType    int // radius.NASPort* value; 0 = omit
	CalledStation  string
	CallingStation string

	// Expect holds authorization assertions (--expect-vlan/--expect-attr) to
	// evaluate against the Access-Accept of every auth method that succeeds. A
	// mismatch turns that method's PASS into a FAIL — "auth worked, wrong VLAN".
	Expect []Expectation
}

// Check is one diagnostic. Implementations must be read-only and must not
// mutate the target server in any way (doc rule: read-only posture).
type Check interface {
	Name() string
	Run(ctx context.Context, t Target) Result
}

// Plan is an ordered set of checks to run against a target.
type Plan struct {
	Target Target
	Checks []Check
}

// PlanSource yields the plan to execute. LocalPlan (this package) builds it
// from CLI flags; a future CloudPlan would fetch and verify a signed plan.
type PlanSource interface {
	Plan(ctx context.Context) (Plan, error)
}

// ResultSink consumes results. TextSink (package report) prints them; a future
// CloudSink would POST them upstream while still printing locally.
type ResultSink interface {
	Emit(Result)
	Close() error
}
