package check

import (
	"fmt"
	"sort"
	"strings"
)

// ServerRun is one server's outcome within a multi-server run: the address that
// was tested and the results it produced. It feeds CompareServers.
type ServerRun struct {
	Server  string
	Results []Result
}

// Comparison is the cross-server verdict printed after testing more than one
// --server. Split-brain between RADIUS servers — one healthy, one silently down,
// or two that disagree — is the classic hidden cause of "intermittent" auth
// tickets: whether a login works depends on which server the client's DNS
// round-robin or VIP happened to pick.
type Comparison struct {
	Verdict     string   `json:"verdict"`             // one plain-English headline
	Reachable   []string `json:"reachable"`           // servers that answered the reachability probe
	Unreachable []string `json:"unreachable"`         // servers that did not answer
	Divergent   []string `json:"divergent,omitempty"` // per-check disagreements among the servers that DID answer
}

// CompareServers classifies a set of per-server runs and produces the plain-English
// comparison verdict. Reachability is the split line: a server whose reachability
// check passed is "responding". Among the responding servers it then looks for
// checks that disagree (one accepts, another rejects) — config or replication drift.
func CompareServers(runs []ServerRun) Comparison {
	var c Comparison
	for _, r := range runs {
		if serverResponded(r.Results) {
			c.Reachable = append(c.Reachable, r.Server)
		} else {
			c.Unreachable = append(c.Unreachable, r.Server)
		}
	}
	c.Divergent = divergentChecks(runs)

	total := len(runs)
	switch {
	case len(c.Unreachable) == total:
		c.Verdict = "No server responded — none of the tested RADIUS servers answered. " +
			"Fix the network path or client registration before reading the per-check results above."
	case len(c.Unreachable) > 0:
		pct := int(float64(len(c.Unreachable))/float64(total)*100 + 0.5)
		c.Verdict = fmt.Sprintf(
			"%s responding, but %s NOT. If clients reach these servers via DNS "+
				"round-robin or a shared VIP, roughly %d%% of authentications would fail "+
				"intermittently depending on which server they land on — the classic "+
				"'it works sometimes' ticket. Take the unresponsive server(s) out of rotation or bring them back.",
			joinServers(c.Reachable), joinServers(c.Unreachable), pct)
	case len(c.Divergent) > 0:
		c.Verdict = fmt.Sprintf(
			"All %d servers responded, but they DISAGREE on some checks (below) — likely "+
				"config or replication drift between them. Clients that land on the odd server "+
				"out will fail intermittently even though every server is 'up'.", total)
	default:
		c.Verdict = fmt.Sprintf(
			"All %d servers responded and returned matching results — no split-brain between them.", total)
	}
	return c
}

// serverResponded reports whether the reachability check passed for a run.
func serverResponded(results []Result) bool {
	for _, r := range results {
		if r.Check == "reachability" {
			return r.Status == StatusPass
		}
	}
	return false
}

// divergentChecks finds checks that ran on the responding servers but ended in
// different states — the "one accepts, one rejects" drift. Servers that never
// responded are excluded (they fail everything, which is noise, not drift), as
// are checks that were skipped everywhere.
func divergentChecks(runs []ServerRun) []string {
	// checkName -> server -> status, only over responding servers.
	byCheck := map[string]map[string]Status{}
	var order []string
	for _, r := range runs {
		if !serverResponded(r.Results) {
			continue
		}
		for _, res := range r.Results {
			if res.Status == StatusSkip {
				continue
			}
			if _, ok := byCheck[res.Check]; !ok {
				byCheck[res.Check] = map[string]Status{}
				order = append(order, res.Check)
			}
			byCheck[res.Check][r.Server] = res.Status
		}
	}

	var out []string
	for _, name := range order {
		perServer := byCheck[name]
		if len(perServer) < 2 {
			continue // only one responding server ran it; nothing to compare
		}
		if !statusesAgree(perServer) {
			out = append(out, fmt.Sprintf("%s: %s — servers disagree", name, describeStatuses(perServer)))
		}
	}
	return out
}

func statusesAgree(perServer map[string]Status) bool {
	first := Status("")
	for _, s := range perServer {
		if first == "" {
			first = s
			continue
		}
		if s != first {
			return false
		}
	}
	return true
}

// describeStatuses renders "server1=pass, server2=fail" with servers in a stable
// order, so the divergence line is deterministic.
func describeStatuses(perServer map[string]Status) string {
	servers := make([]string, 0, len(perServer))
	for s := range perServer {
		servers = append(servers, s)
	}
	sort.Strings(servers)
	parts := make([]string, 0, len(servers))
	for _, s := range servers {
		parts = append(parts, fmt.Sprintf("%s=%s", s, perServer[s]))
	}
	return strings.Join(parts, ", ")
}

// joinServers renders a list of servers for the verdict headline, tolerating the
// empty case (every server down) without an awkward dangling phrase.
func joinServers(servers []string) string {
	if len(servers) == 0 {
		return "No server is"
	}
	return strings.Join(servers, ", ") + " " + plural(len(servers), "is", "are")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
