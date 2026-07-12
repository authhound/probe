package check

import (
	"context"
	"fmt"
	"strconv"

	"github.com/authhound/probe/internal/radius"
)

// MTUProbe finds the largest RADIUS packet that survives the round trip between
// the probe and the server, by padding requests with Proxy-State (which the
// server echoes, so the reply is padded too) and binary-searching the size.
//
// This pinpoints one of the nastiest invisible failures: a firewall or tunnel
// on the path drops large or IP-fragmented UDP, so the multi-kilobyte EAP-TLS
// certificate flight never arrives and 802.1X silently stalls — while every
// server-side log looks clean. Opt-in via --mtu (it sends a handful of probes).
type MTUProbe struct {
	Enabled bool
}

func (MTUProbe) Name() string { return "path-mtu" }

const (
	mtuMin  = 512  // baseline; smaller than any real path MTU
	mtuMax  = 4000 // just under the RADIUS 4096-byte ceiling
	mtuStep = 48   // stop the search once the window is this small
	mtuSafe = 1500 // at/above one Ethernet MTU means no fragment-drop problem
)

func (c MTUProbe) Run(ctx context.Context, t Target) Result {
	if !c.Enabled {
		return Result{Check: "path-mtu", Status: StatusSkip, Summary: "Path-MTU probe not run (pass --mtu to enable)"}
	}
	attrs := commonAttrs(t)

	// Baseline: a small packet must round-trip, or there's nothing to measure.
	ok, _, err := radius.MTUReachable(t.Address, t.Secret, mtuMin, attrs, t.Timeout)
	if err != nil {
		return Result{Check: "path-mtu", Status: StatusSkip, Summary: "Could not reach the server for the MTU probe: " + err.Error()}
	}
	if !ok {
		return Result{
			Check: "path-mtu", Status: StatusSkip,
			Summary: "Even a small padded request was dropped — resolve reachability/secret first",
		}
	}

	// Binary-search the largest size that still round-trips.
	lo, hi, maxOK := mtuMin, mtuMax, mtuMin
	for hi-lo > mtuStep {
		mid := (lo + hi) / 2
		got, _, err := radius.MTUReachable(t.Address, t.Secret, mid, attrs, t.Timeout)
		if err != nil {
			break
		}
		if got {
			lo, maxOK = mid, mid
		} else {
			hi = mid
		}
	}

	fields := map[string]string{"max_bytes": strconv.Itoa(maxOK)}

	if maxOK >= mtuMax-mtuStep {
		return Result{
			Check: "path-mtu", Status: StatusPass, Fields: fields,
			Summary: fmt.Sprintf("Path carries full-size RADIUS packets (≥%dB) — no fragmentation problem", maxOK),
		}
	}
	if maxOK >= mtuSafe {
		return Result{
			Check: "path-mtu", Status: StatusPass, Fields: fields,
			Summary: fmt.Sprintf("Largest RADIUS packet that round-trips: ~%dB (fine for typical EAP-TLS)", maxOK),
		}
	}
	return Result{
		Check: "path-mtu", Status: StatusWarn, Fields: fields,
		Summary: fmt.Sprintf("RADIUS packets larger than ~%dB are dropped on the path", maxOK),
		Detail: fmt.Sprintf("This is the classic fragmentation black hole: the multi-kilobyte EAP-TLS "+
			"certificate flight won't arrive, so 802.1X stalls with no server-side error. "+
			"Either lower the server's EAP fragment_size below ~%dB, or fix the path (a "+
			"firewall/tunnel dropping large or IP-fragmented UDP, or a reduced MTU on a VPN/GRE hop).", maxOK),
	}
}
