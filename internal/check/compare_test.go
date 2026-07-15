package check

import (
	"strings"
	"testing"
)

// resultSet is a compact way to build a server's results for comparison tests:
// each entry is check name -> status.
func resultSet(pairs ...string) []Result {
	var out []Result
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, Result{Check: pairs[i], Status: Status(pairs[i+1])})
	}
	return out
}

func run(server string, results []Result) ServerRun {
	return ServerRun{Server: server, Results: results}
}

func TestCompareAllHealthyMatching(t *testing.T) {
	c := CompareServers([]ServerRun{
		run("a:1812", resultSet("reachability", "pass", "pap", "pass")),
		run("b:1812", resultSet("reachability", "pass", "pap", "pass")),
	})
	if len(c.Unreachable) != 0 || len(c.Divergent) != 0 {
		t.Fatalf("expected all healthy, matching; got unreachable=%v divergent=%v", c.Unreachable, c.Divergent)
	}
	if !strings.Contains(c.Verdict, "no split-brain") {
		t.Errorf("verdict: %q", c.Verdict)
	}
}

func TestCompareOneDown(t *testing.T) {
	c := CompareServers([]ServerRun{
		run("primary:1812", resultSet("reachability", "pass", "pap", "pass")),
		run("secondary:1812", resultSet("reachability", "fail")),
	})
	if len(c.Reachable) != 1 || c.Unreachable[0] != "secondary:1812" {
		t.Fatalf("classification wrong: reachable=%v unreachable=%v", c.Reachable, c.Unreachable)
	}
	// 1 of 2 down -> ~50%, and the round-robin story.
	if !strings.Contains(c.Verdict, "50%") || !strings.Contains(c.Verdict, "round-robin") {
		t.Errorf("verdict should name the ~50%% round-robin risk: %q", c.Verdict)
	}
}

func TestCompareDivergent(t *testing.T) {
	c := CompareServers([]ServerRun{
		run("a:1812", resultSet("reachability", "pass", "pap", "pass")),
		run("b:1812", resultSet("reachability", "pass", "pap", "fail")),
	})
	if len(c.Unreachable) != 0 {
		t.Fatalf("both should be reachable, got unreachable=%v", c.Unreachable)
	}
	if len(c.Divergent) != 1 || !strings.Contains(c.Divergent[0], "pap") {
		t.Fatalf("expected a pap divergence, got %v", c.Divergent)
	}
	if !strings.Contains(c.Divergent[0], "a:1812=pass") || !strings.Contains(c.Divergent[0], "b:1812=fail") {
		t.Errorf("divergence should name each server's status: %q", c.Divergent[0])
	}
	if !strings.Contains(c.Verdict, "DISAGREE") {
		t.Errorf("verdict should flag disagreement: %q", c.Verdict)
	}
}

func TestCompareAllDown(t *testing.T) {
	c := CompareServers([]ServerRun{
		run("a:1812", resultSet("reachability", "fail")),
		run("b:1812", resultSet("reachability", "fail")),
	})
	if !strings.Contains(c.Verdict, "No server responded") {
		t.Errorf("verdict: %q", c.Verdict)
	}
}

// A check that only one responding server ran (skipped on the other) is not a
// divergence — there's nothing to compare.
func TestCompareSkipNotDivergent(t *testing.T) {
	c := CompareServers([]ServerRun{
		run("a:1812", resultSet("reachability", "pass", "eap-tls", "pass")),
		run("b:1812", resultSet("reachability", "pass", "eap-tls", "skip")),
	})
	if len(c.Divergent) != 0 {
		t.Errorf("skip on one server is not a divergence, got %v", c.Divergent)
	}
}
