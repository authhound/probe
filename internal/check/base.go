package check

import (
	"errors"
	"time"

	"github.com/authhound/probe/internal/radius"
)

// BaseExchange shares ONE credential-shaped Access-Request between the
// reachability, shared-secret and BlastRADIUS-posture checks. They used to send
// three near-identical requests, each ending in an Access-Reject for the
// synthetic user "authhound-probe" — three failed-logon lines in the server's
// log per run (150 under --count 50), which SIEMs alert on. One request answers
// all three questions: did a reply arrive, does its Response Authenticator
// verify, and did the server sign it with a Message-Authenticator.
//
// It also records whether the server was reachable at all, so the checks that
// depend on reachability (auth methods, certificate, MTU) can skip immediately
// instead of each waiting out the full timeout on a server that is not there.
//
// A nil *BaseExchange keeps every check fully self-contained (tests, and any
// caller composing checks by hand).
type BaseExchange struct {
	// Status-Server result for this iteration, recorded by StatusServer so
	// reachability can report an undelayed round-trip time (an Access-Reject is
	// delayed by FreeRADIUS's reject_delay, 1 s by default).
	statusOK  bool
	statusRTT time.Duration

	done        bool
	err         error // non-nil when no usable reply arrived
	timedOut    bool
	localIP     string
	raw         []byte
	reqAuth     [16]byte
	rtt         time.Duration
	retransmits int
}

// resetForIteration clears the previous iteration's exchange but keeps the
// Status-Server observation made moments ago by the StatusServer check, which
// always runs first.
func (b *BaseExchange) resetForIteration() {
	*b = BaseExchange{statusOK: b.statusOK, statusRTT: b.statusRTT}
}

// run performs the shared exchange: a PAP-shaped Access-Request (RFC 2865 §4.1
// requires a credential attribute) with a throwaway password. Accept and Reject
// are equally useful; only the reply's presence and signatures matter.
func (b *BaseExchange) run(t Target) {
	b.done = true
	p, err := radius.NewAccessRequest(2)
	if err != nil {
		b.err = err
		return
	}
	p.AddString(radius.AttrUserName, "authhound-probe")
	p.SetUserPassword("authhound-probe-check", t.Secret)
	addCommon(p, t)
	b.reqAuth = p.Authenticator

	res, err := radius.ExchangeR(t.Address, t.Secret, p, t.Timeout, t.LocalAddr)
	if res != nil {
		b.rtt = res.RTT
		b.retransmits = res.Retransmits
		b.raw = res.Raw
	}
	b.err = err
	if errors.Is(err, radius.ErrTimeout) {
		b.timedOut = true
		var te *radius.TimeoutError
		if errors.As(err, &te) {
			b.localIP = te.LocalIP
		}
	}
}

// Unreachable reports whether this iteration's shared exchange got no reply.
func (b *BaseExchange) Unreachable() bool { return b != nil && b.done && b.timedOut }

// skipIfUnreachable returns the SKIP result a dependent check should emit when
// the server never answered the reachability probe: there is no point waiting
// another full timeout. The result is marked as a timeout so --count still
// counts the iteration as lost.
func (b *BaseExchange) skipIfUnreachable(check string) (Result, bool) {
	if !b.Unreachable() {
		return Result{}, false
	}
	return markTimeout(Result{
		Check: check, Status: StatusSkip,
		Summary: "Skipped — the server did not answer the reachability probe; fix that first",
	}), true
}
