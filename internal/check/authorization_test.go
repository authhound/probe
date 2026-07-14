package check

import (
	"context"
	"strings"
	"testing"

	"github.com/authhound/probe/internal/radius"
)

// vlanAttrs is a raw Access-Accept authorization block assigning VLAN 20.
func vlanAttrs() []byte {
	var b []byte
	add := func(t byte, v ...byte) {
		b = append(b, t, byte(2+len(v)))
		b = append(b, v...)
	}
	add(64, 0x00, 0x00, 0x00, 0x0d) // Tunnel-Type = VLAN
	add(65, 0x00, 0x00, 0x00, 0x06) // Tunnel-Medium-Type = IEEE-802
	add(81, 0x01, '2', '0')         // Tunnel-Private-Group-ID = "20" (tagged)
	return b
}

func vlanServer(t *testing.T) Target {
	addr := startFakeServer(t, &fakeServer{
		secret: "s3cret", goodUser: "alice", goodPass: "pw", acceptAttrs: vlanAttrs(),
	})
	return target(addr, "s3cret")
}

func TestAuthorizationSurfaced(t *testing.T) {
	// Even without an assertion, a successful accept shows the returned VLAN.
	tgt := vlanServer(t)
	r := PAP{User: "alice", Pass: "pw"}.Run(context.Background(), tgt)
	if r.Status != StatusPass {
		t.Fatalf("status = %s (%s), want pass", r.Status, r.Summary)
	}
	if r.Authorization == nil {
		t.Fatal("no authorization block attached")
	}
	if v, ok := findAttr(r.Authorization.Attributes, "Tunnel-Private-Group-ID"); !ok || v != "20" {
		t.Errorf("VLAN attribute = %q (ok=%v), want 20", v, ok)
	}
}

func TestExpectVLANMatch(t *testing.T) {
	tgt := vlanServer(t)
	tgt.Expect = []Expectation{{Name: "Tunnel-Private-Group-ID", Value: "20", Label: "VLAN"}}
	r := PAP{User: "alice", Pass: "pw"}.Run(context.Background(), tgt)
	if r.Status != StatusPass {
		t.Fatalf("status = %s (%s), want pass on VLAN match", r.Status, r.Summary)
	}
	if len(r.Authorization.Assertions) != 1 || !r.Authorization.Assertions[0].Pass {
		t.Errorf("assertion did not pass: %+v", r.Authorization.Assertions)
	}
}

func TestExpectVLANMismatch(t *testing.T) {
	tgt := vlanServer(t)
	tgt.NASPortType = radius.NASPortWireless80211
	tgt.Expect = []Expectation{{Name: "Tunnel-Private-Group-ID", Value: "30", Label: "VLAN"}}
	r := PAP{User: "alice", Pass: "pw"}.Run(context.Background(), tgt)
	if r.Status != StatusFail {
		t.Fatalf("status = %s, want fail on VLAN mismatch", r.Status)
	}
	// The failure line must name both values and point at the policy inputs,
	// including the NAS-Port-Type the probe sent.
	for _, want := range []string{"assigned VLAN 20", "expected 30", "NAS-Port-Type"} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("detail missing %q; detail:\n%s", want, r.Detail)
		}
	}
	a := r.Authorization.Assertions[0]
	if a.Pass || a.Actual != "20" || a.Expected != "30" {
		t.Errorf("assertion = %+v, want mismatch actual=20 expected=30", a)
	}
}

func TestExpectAttrAbsent(t *testing.T) {
	// Expecting a Filter-Id the server never returns fails with "not returned".
	tgt := vlanServer(t)
	tgt.Expect = []Expectation{{Name: "Filter-Id", Value: "Guests", Label: "Filter-Id"}}
	r := PAP{User: "alice", Pass: "pw"}.Run(context.Background(), tgt)
	if r.Status != StatusFail {
		t.Fatalf("status = %s, want fail when expected attribute is absent", r.Status)
	}
	if a := r.Authorization.Assertions[0]; a.Pass || a.Actual != "" {
		t.Errorf("assertion = %+v, want mismatch with empty actual", a)
	}
}

func TestNoAuthorizationWithoutAttrsOrExpect(t *testing.T) {
	// A bare accept with no attributes and no assertions carries no block, so
	// existing output/JSON is unchanged.
	addr := startFakeServer(t, &fakeServer{secret: "s3cret", goodUser: "alice", goodPass: "pw"})
	r := PAP{User: "alice", Pass: "pw"}.Run(context.Background(), target(addr, "s3cret"))
	if r.Status != StatusPass || r.Authorization != nil {
		t.Errorf("status=%s authorization=%v, want pass with nil authorization", r.Status, r.Authorization)
	}
}
