package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/authhound/probe/internal/check"
	"github.com/authhound/probe/internal/radius"
)

// update regenerates the golden file: `go test ./internal/report -run Golden -update`.
var update = flag.Bool("update", false, "update the JSON schema golden file")

// goldenResults is a fixed, representative set of check results that exercises
// every Status and every optional field (detail, hint, fields, duration). The
// JSONSink render of these is pinned by testdata/schema-v1.golden.json.
//
// This is the guard for the --json stability contract: if the document shape
// changes (a renamed/removed field, a new field, a changed type, a different
// summary layout) the golden no longer matches and this test fails in CI. The
// fix is deliberate: update the golden AND bump SchemaVersion / json-schema.md
// if the change is not backward compatible.
func goldenResults() []check.Result {
	return []check.Result{
		{
			Check:   "reachability",
			Status:  check.StatusPass,
			Summary: "RADIUS server answered",
			Fields:  map[string]string{"rtt_ms": "3"},
			// duration_ns present to pin the type/name.
			Duration: 3_000_000,
		},
		{
			Check:   "shared-secret",
			Status:  check.StatusFail,
			Summary: "Shared secret appears wrong",
			Detail:  "The Message-Authenticator did not validate.",
			Hint:    "Check the secret on both the NAS and the server:\n  secret = <same on both sides>",
		},
		{
			Check:   "server-cert",
			Status:  check.StatusWarn,
			Summary: "Server certificate expires in 10 days (2026-07-24)",
			Fields:  map[string]string{"not_after": "2026-07-24", "tls_version": "TLS 1.3"},
		},
		{
			Check:   "mtu",
			Status:  check.StatusInfo,
			Summary: "Largest un-fragmented EAP packet: 1400 bytes",
		},
		{
			Check:   "eap-tls",
			Status:  check.StatusSkip,
			Summary: "No client certificate given",
		},
		{
			// Pins the additive `authorization` block: attributes returned on an
			// Access-Accept plus an assertion outcome (here, a VLAN mismatch FAIL).
			Check:   "peap-mschapv2",
			Status:  check.StatusFail,
			Summary: "PEAP-MSCHAPv2 authentication succeeded for alice — but the returned authorization does not match",
			Authorization: &check.Authorization{
				Attributes: []radius.AuthAttr{
					{Name: "Tunnel-Type", Value: "VLAN (13)"},
					{Name: "Tunnel-Private-Group-ID", Value: "30"},
					{Name: "Cisco-AVPair", Value: "shell:priv-lvl=15", Raw: "7368656c6c3a707269762d6c766c3d3135", Vendor: 9},
				},
				Assertions: []check.AssertionResult{
					{Label: "VLAN", Name: "Tunnel-Private-Group-ID", Expected: "20", Actual: "30", Pass: false},
				},
			},
		},
	}
}

func TestJSONSchemaGolden(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONSink(&buf)
	for _, r := range goldenResults() {
		sink.Emit(r)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := buf.Bytes()

	golden := filepath.Join("testdata", "schema-v1.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		t.Logf("updated %s", golden)
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("--json shape changed vs %s.\n"+
			"If this change is intentional and BACKWARD COMPATIBLE (additive only), "+
			"regenerate with:\n    go test ./internal/report -run Golden -update\n"+
			"If it is NOT backward compatible, also bump report.SchemaVersion and "+
			"document it in docs/json-schema.md.\n\n--- got ---\n%s\n--- want ---\n%s",
			golden, got, want)
	}
}

// TestJSONSummaryAlwaysComplete pins the item-5 guarantee: every status count is
// present in .summary even when zero, so scripts can address them unconditionally.
func TestJSONSummaryAlwaysComplete(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONSink(&buf)
	sink.Emit(check.Result{Check: "reachability", Status: check.StatusPass, Summary: "ok"})
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, key := range []string{
		`"schema_version": "1"`,
		`"pass": 1`, `"fail": 0`, `"warn": 0`, `"info": 0`, `"skip": 0`,
	} {
		if !bytes.Contains(buf.Bytes(), []byte(key)) {
			t.Errorf("expected %s in output:\n%s", key, buf.String())
		}
	}
}
