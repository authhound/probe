package check

import (
	"fmt"
	"strings"

	"github.com/authhound/probe/internal/radius"
)

// Expectation is one authorization assertion the user asked for: --expect-vlan
// (a convenience for Tunnel-Private-Group-ID) or a general --expect-attr
// 'Name=Value'. Name is the authorization attribute's display name as decoded
// by radius.AuthorizationAttributes; Label is what we call it in output ("VLAN"
// for the convenience flag, otherwise the attribute name).
type Expectation struct {
	Name  string
	Value string
	Label string
}

// Authorization is the Access-Accept authorization block attached to a
// successful auth check's Result: the attributes the server returned plus the
// outcome of any assertions. Shape is additive to the --json schema.
type Authorization struct {
	Attributes []radius.AuthAttr `json:"attributes"`
	Assertions []AssertionResult `json:"assertions,omitempty"`
}

// AssertionResult is the outcome of one expectation against the Access-Accept.
// Indeterminate is set when the accept could not be read (best-effort EAP paths),
// so the run WARNs rather than FAILs — we can't prove a mismatch we never saw.
type AssertionResult struct {
	Label         string `json:"label"`    // "VLAN" or the attribute name
	Name          string `json:"name"`     // attribute name checked
	Expected      string `json:"expected"` // value asked for
	Actual        string `json:"actual"`   // decoded value, "" if the attribute was absent
	Pass          bool   `json:"pass"`     // matched
	Indeterminate bool   `json:"indeterminate,omitempty"`
}

// evalAuthorization decodes reply's authorization attributes and evaluates the
// expectations. reply is nil when a successful auth couldn't yield the
// Access-Accept; then attributes are empty and every assertion is indeterminate.
// Returns nil when there is nothing to show (no attributes and no expectations).
func evalAuthorization(reply *radius.Packet, expect []Expectation) *Authorization {
	var attrs []radius.AuthAttr
	if reply != nil {
		attrs = reply.AuthorizationAttributes()
	}
	if len(attrs) == 0 && len(expect) == 0 {
		return nil
	}
	auth := &Authorization{Attributes: attrs}
	for _, e := range expect {
		ar := AssertionResult{Label: e.Label, Name: e.Name, Expected: e.Value}
		if reply == nil {
			ar.Indeterminate = true
		} else {
			actual, found := findAttr(attrs, e.Name)
			ar.Actual = actual
			ar.Pass = found && strings.EqualFold(strings.TrimSpace(actual), strings.TrimSpace(e.Value))
		}
		auth.Assertions = append(auth.Assertions, ar)
	}
	return auth
}

// findAttr returns the value of the first attribute whose name matches (case-
// insensitively) and whether it was present.
func findAttr(attrs []radius.AuthAttr, name string) (string, bool) {
	for _, a := range attrs {
		if strings.EqualFold(a.Name, name) {
			return a.Value, true
		}
	}
	return "", false
}

// failed reports whether any assertion is a definite mismatch (attribute present
// but wrong, or absent when expected) — the FAIL condition.
func (a *Authorization) failed() bool {
	for _, ar := range a.Assertions {
		if !ar.Pass && !ar.Indeterminate {
			return true
		}
	}
	return false
}

// indeterminate reports whether any assertion couldn't be evaluated (the accept
// wasn't captured) — a WARN, not a FAIL.
func (a *Authorization) indeterminate() bool {
	for _, ar := range a.Assertions {
		if ar.Indeterminate {
			return true
		}
	}
	return false
}

// applyAuthorization attaches the decoded Access-Accept authorization block to a
// successful auth Result and, if an assertion failed, turns the PASS into a FAIL
// with plain-English guidance. reply is the Access-Accept (nil if it couldn't be
// captured). Called only after authentication succeeded.
func applyAuthorization(r Result, reply *radius.Packet, t Target) Result {
	auth := evalAuthorization(reply, t.Expect)
	if auth == nil {
		return r
	}
	r.Authorization = auth
	switch {
	case auth.failed():
		r.Status = StatusFail
		r.Summary = r.Summary + " — but the returned authorization does not match"
		r.Detail = assertionFailureDetail(auth, t)
	case auth.indeterminate():
		if r.Status == StatusPass {
			r.Status = StatusWarn
		}
		r.Detail = joinDetail(r.Detail,
			"Authentication succeeded, but the probe could not read the Access-Accept to verify the expected authorization attributes.")
	}
	return r
}

// assertionFailureDetail renders the "wrong VLAN/policy" explanation for the
// failed assertions, naming what the server returned vs. what was expected and
// pointing at the policy inputs that select it — including the NAS-Port-Type
// this probe sent, which policies frequently branch on.
func assertionFailureDetail(auth *Authorization, t Target) string {
	var lines []string
	for _, ar := range auth.Assertions {
		if ar.Pass || ar.Indeterminate {
			continue
		}
		if ar.Actual == "" {
			lines = append(lines, fmt.Sprintf(
				"Server returned no %s, expected %s.", ar.Label, ar.Expected))
		} else {
			lines = append(lines, fmt.Sprintf(
				"Server assigned %s %s, expected %s.", ar.Label, ar.Actual, ar.Expected))
		}
	}
	guidance := "Check the policy/authorization rules that matched this request " +
		"(NAS-Port-Type, user group, time-of-day)."
	if name := nasPortTypeName(t.NASPortType); name != "" {
		guidance += fmt.Sprintf(" This probe sent NAS-Port-Type=%s; many policies "+
			"branch on it, so a different value (--nas-port-type wireless|ethernet|virtual) "+
			"can select a different VLAN/policy.", name)
	}
	return strings.Join(lines, " ") + " " + guidance
}

// joinDetail appends add to an existing detail string, keeping a single space.
func joinDetail(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + " " + add
}

// nasPortTypeName renders the NAS-Port-Type the probe sent, for the failure
// guidance. Empty when none was set.
func nasPortTypeName(v int) string {
	switch v {
	case radius.NASPortWireless80211:
		return "wireless"
	case radius.NASPortEthernet:
		return "ethernet"
	case radius.NASPortVirtual:
		return "virtual"
	}
	return ""
}
