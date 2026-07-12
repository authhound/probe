package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/authhound/probe/internal/check"
	"github.com/authhound/probe/internal/report"
)

// TestNoCredentialLeak plants sentinel values as the shared secret and every
// auth password, drives all checks down their failure/timeout paths against an
// unroutable address, and asserts neither sentinel ever reaches rendered text or
// JSON output. This guards the invariant that a Result is secret-free: credentials
// are used only to build packets, never printed, logged, or serialized.
func TestNoCredentialLeak(t *testing.T) {
	const (
		sentinelSecret = "SENTINELSECRET_do_not_print"
		sentinelPass   = "SENTINELPASS_do_not_print"
	)

	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737): reserved, unroutable, so every
	// network check fails or times out — exercising the error paths that render
	// err.Error() into Detail/Summary, where a leak would most plausibly hide.
	target := check.Target{
		Address:       "192.0.2.1:1812",
		Secret:        sentinelSecret,
		Timeout:       150 * time.Millisecond,
		NASIdentifier: "authhound-probe",
	}
	checks := []check.Check{
		check.Reachability{},
		check.SharedSecret{},
		check.PAP{User: "alice", Pass: sentinelPass},
		check.PEAPMSCHAPv2{User: "alice", Pass: sentinelPass},
		check.EAPTTLS{User: "alice", Pass: sentinelPass},
		check.ServerCert{},
		check.MTUProbe{Enabled: true},
	}

	var textBuf, jsonBuf bytes.Buffer
	textSink := report.NewTextSink(&textBuf, false)
	jsonSink := report.NewJSONSink(&jsonBuf)
	for _, c := range checks {
		res := c.Run(context.Background(), target)
		textSink.Emit(res)
		jsonSink.Emit(res)
	}
	_ = textSink.Close()
	_ = jsonSink.Close()

	for _, out := range []struct{ name, body string }{
		{"text", textBuf.String()},
		{"json", jsonBuf.String()},
	} {
		for _, sentinel := range []string{sentinelSecret, sentinelPass} {
			if strings.Contains(out.body, sentinel) {
				t.Errorf("%s output leaked a credential (%q):\n%s", out.name, sentinel, out.body)
			}
		}
	}
}
