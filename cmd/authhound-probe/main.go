// Command authhound-probe runs outside-in authentication diagnostics from
// inside your network. In v1 it runs one-shot, locally, with no account and no
// cloud — everything you enter stays on this host.
//
//	authhound-probe radius test --server radius.corp.com --secret '***' \
//	    --pap 'alice:***'
//
// The protocol is a subcommand namespace (`radius` today; `ldap`, `sso` planned)
// so the same single agent grows to cover more auth backends. `connect`
// (premium) turns the same binary into a continuous probe reporting to
// AuthHound's monitoring service — see https://authhound.com.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"time"

	"github.com/authhound/probe/internal/check"
	"github.com/authhound/probe/internal/credential"
	"github.com/authhound/probe/internal/radius"
	"github.com/authhound/probe/internal/report"
)

// version is stamped at release time by GoReleaser via
// -ldflags "-X main.version=<tag>". For `go install ...@latest` builds (no
// ldflags) it stays "dev" and resolveVersion falls back to the module version
// Go records in the build info.
var version = "dev"

// resolveVersion returns the release tag when stamped, otherwise the module
// version recorded by `go install` (e.g. v0.1.0), otherwise "dev".
func resolveVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return version
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "radius":
		os.Exit(cmdRadius(os.Args[2:]))
	case "radsec":
		os.Exit(cmdRadsec(os.Args[2:]))
	case "connect":
		cmdConnect()
	case "version", "-v", "--version":
		fmt.Println("authhound-probe", resolveVersion())
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

// cmdRadius dispatches the RADIUS protocol subcommands. Future protocols
// (`ldap`, `sso`) get their own top-level command alongside this one.
func cmdRadius(args []string) int {
	if len(args) < 1 {
		radiusUsage()
		return 2
	}
	switch args[0] {
	case "test":
		return cmdRadiusTest(args[1:])
	case "help", "-h", "--help":
		radiusUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown radius subcommand %q\n\n", args[0])
		radiusUsage()
		return 2
	}
}

func radiusUsage() {
	fmt.Fprintln(os.Stderr, `Usage: authhound-probe radius test --server HOST --secret SECRET [--pap user:pass]

Runs local, read-only RADIUS/802.1X checks. Nothing leaves this host.
Run 'authhound-probe radius test --help' for all flags.`)
}

// cmdRadsec dispatches the RadSec (RADIUS/TLS) subcommands.
func cmdRadsec(args []string) int {
	if len(args) < 1 {
		radsecUsage()
		return 2
	}
	switch args[0] {
	case "test":
		return cmdRadsecTest(args[1:])
	case "help", "-h", "--help":
		radsecUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown radsec subcommand %q\n\n", args[0])
		radsecUsage()
		return 2
	}
}

func radsecUsage() {
	fmt.Fprintln(os.Stderr, `Usage: authhound-probe radsec test --server HOST [--client-cert cert.pem --client-key key.pem]

Checks a RadSec (RADIUS/TLS, TCP/2083) endpoint: reachability, TLS handshake,
server certificate, and a RADIUS exchange over the tunnel. Read-only.`)
}

func cmdRadsecTest(args []string) int {
	fs := flag.NewFlagSet("radsec test", flag.ExitOnError)
	server := fs.String("server", "", "RadSec server host or host:port (default port 2083)")
	clientCert := fs.String("client-cert", "", "client certificate (PEM) for mutual TLS; optional")
	clientKey := fs.String("client-key", "", "client private key (PEM); required with --client-cert")
	serverName := fs.String("server-name", "", "expected server certificate name (TLS SNI); optional")
	timeout := fs.Duration("timeout", 5*time.Second, "connection/handshake timeout")
	jsonOut := fs.Bool("json", false, "emit results as JSON instead of text")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	strict := fs.Bool("strict", false, "exit non-zero on warnings too (for scheduled monitoring)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: authhound-probe radsec test --server HOST [--client-cert cert.pem --client-key key.pem]")
		fmt.Fprint(os.Stderr, "\nChecks a RadSec (RADIUS/TLS, TCP/2083) endpoint. Nothing leaves this host.\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprint(os.Stderr, exitCodeHelp)
	}
	_ = fs.Parse(args)

	if *server == "" {
		fmt.Fprint(os.Stderr, "error: --server is required\n\n")
		fs.Usage()
		return 2
	}
	if (*clientCert == "") != (*clientKey == "") {
		fmt.Fprintln(os.Stderr, "error: --client-cert and --client-key must be given together")
		return 2
	}
	addr := *server
	if !strings.Contains(addr, ":") {
		addr += ":2083"
	}

	var sink resultSink
	if *jsonOut {
		sink = report.NewJSONSink(os.Stdout)
	} else {
		fmt.Printf("Testing RadSec endpoint %s\n\n", addr)
		sink = report.NewTextSink(os.Stdout, report.UseColor(os.Stdout, *noColor))
	}

	results := check.RadSecReport(context.Background(), addr, *clientCert, *clientKey, *serverName, *timeout)
	for _, r := range results {
		sink.Emit(r)
	}
	_ = sink.Close()
	return exitCode(sink, *strict)
}

func cmdRadiusTest(args []string) int {
	fs := flag.NewFlagSet("radius test", flag.ExitOnError)
	server := fs.String("server", "", "RADIUS server host or host:port (default port 1812); comma-separate several to compare them (e.g. primary,secondary)")
	secret := fs.String("secret", "", "shared secret (leaks into shell history/ps — prefer AUTHHOUND_SECRET, --secret-file, or the prompt)")
	secretFile := fs.String("secret-file", "", "read the shared secret from this file (must not be world-readable on unix)")
	secretStdin := fs.Bool("secret-stdin", false, "read the shared secret from standard input (one line)")
	passwordFile := fs.String("password-file", "", "read the auth password from this file, for any --pap/--peap/--ttls given as just 'user'")
	pap := fs.String("pap", "", "run a PAP auth test as 'user:password', or just 'user' to be prompted for the password")
	peap := fs.String("peap", "", "run a PEAP-MSCHAPv2 auth test as 'user:password', or just 'user' to be prompted")
	ttls := fs.String("ttls", "", "run an EAP-TTLS (inner PAP) auth test as 'user:password', or just 'user' to be prompted")
	clientCert := fs.String("client-cert", "", "client certificate (PEM) for an EAP-TLS auth test")
	clientKey := fs.String("client-key", "", "client private key (PEM) for the EAP-TLS test")
	nasID := fs.String("nas-id", "authhound-probe", "NAS-Identifier to send")
	nasPortType := fs.String("nas-port-type", "wireless", "NAS-Port-Type: wireless, ethernet, or virtual")
	serverName := fs.String("server-name", "", "expected server certificate name (TLS SNI); optional")
	expectVLAN := fs.String("expect-vlan", "", "assert the Access-Accept assigns this VLAN (Tunnel-Private-Group-ID); a mismatch is a FAIL")
	var expectAttr stringSliceFlag
	fs.Var(&expectAttr, "expect-attr", "assert a returned authorization attribute as 'Name=Value' (repeatable); a mismatch is a FAIL")
	mtu := fs.Bool("mtu", false, "run the path-MTU / fragmentation probe (sends a few padded packets)")
	count := fs.Int("count", 1, "run the checks N times (2..50) and report aggregate statistics — for chasing intermittent failures")
	interval := fs.Duration("interval", 2*time.Second, "pause between --count iterations (a hard-coded safety floor applies)")
	timeout := fs.Duration("timeout", 5*time.Second, "per-request timeout")
	bind := fs.String("bind", "", "source IP[:port] to send from, for pinning the outgoing interface on a multi-homed host")
	jsonOut := fs.Bool("json", false, "emit results as JSON instead of text")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	strict := fs.Bool("strict", false, "exit non-zero on warnings too (for scheduled monitoring)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: authhound-probe radius test --server HOST --secret SECRET [--pap user:pass]")
		fmt.Fprint(os.Stderr, "\nRuns local, read-only RADIUS/802.1X checks. Nothing leaves this host.\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprint(os.Stderr, exitCodeHelp)
	}
	_ = fs.Parse(args)

	if *server == "" {
		fmt.Fprint(os.Stderr, "error: --server is required\n\n")
		fs.Usage()
		return 2
	}
	provided := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })

	servers, err := parseServers(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	// --bind pins the outgoing interface on a multi-homed host. The resolved
	// source address flows into every socket the run opens, so the detected
	// source IP (and thus the registration hint) reflects the bind.
	localAddr, err := resolveBindAddr(*bind)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	portType, ok := nasPortTypes[*nasPortType]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: --nas-port-type must be wireless, ethernet, or virtual\n")
		return 2
	}

	// --count 1 (the default) is exactly the classic single run; repeat mode is
	// hard-capped at RepeatCountMax — this is a diagnosis loop a human watches,
	// not a monitor (that's `connect`).
	if *count != 1 && (*count < check.RepeatCountMin || *count > check.RepeatCountMax) {
		fmt.Fprintf(os.Stderr, "error: --count must be between %d and %d\n", check.RepeatCountMin, check.RepeatCountMax)
		return 2
	}
	if provided["interval"] && *count == 1 {
		fmt.Fprintln(os.Stderr, "error: --interval only makes sense with --count")
		return 2
	}
	// --count multiplies requests against ONE server; comparing several servers
	// is a different job. Keeping them separate keeps the output legible and the
	// per-server load obviously bounded. Test one server at a time with --count.
	if len(servers) > 1 && *count != 1 {
		fmt.Fprintln(os.Stderr, "error: --count tests a single server; drop it to compare multiple --server entries, or test one server at a time")
		return 2
	}

	prompter := credential.Default()
	secretValue, err := prompter.Resolve(credential.Spec{
		Name:      "shared secret",
		Inline:    *secret,
		InlineSet: provided["secret"],
		File:      *secretFile,
		Stdin:     *secretStdin,
		EnvVar:    "AUTHHOUND_SECRET",
		Required:  true,
		Exclusive: true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	// Address is set per server below; everything else is shared across a
	// multi-server comparison.
	target := check.Target{
		Secret:        secretValue,
		Timeout:       *timeout,
		NASIdentifier: *nasID,
		NASPortType:   portType,
		LocalAddr:     localAddr,
	}

	papUser, papPass, err := resolveCreds(prompter, *pap, "--pap", *passwordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	peapUser, peapPass, err := resolveCreds(prompter, *peap, "--peap", *passwordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	ttlsUser, ttlsPass, err := resolveCreds(prompter, *ttls, "--ttls", *passwordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if (*clientCert == "") != (*clientKey == "") {
		fmt.Fprintln(os.Stderr, "error: --client-cert and --client-key must be given together")
		return 2
	}

	expect, err := buildExpectations(*expectVLAN, expectAttr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	// Assertions verify what an Access-Accept returned, so they need an auth
	// method to produce one — otherwise nothing is ever checked.
	if len(expect) > 0 && papUser == "" && peapUser == "" && ttlsUser == "" && *clientCert == "" {
		fmt.Fprintln(os.Stderr, "error: --expect-vlan/--expect-attr need an auth method to assert on (add --pap, --peap, --ttls, or --client-cert)")
		return 2
	}
	target.Expect = expect

	// Status-Server runs first: an RFC 5997 liveness ping that doesn't consume an
	// auth attempt. The rest follow in dependency order (reachability/secret before
	// the auth methods that rely on them).
	checks := []check.Check{
		check.StatusServer{},
		check.Reachability{},
		check.SharedSecret{},
		check.BlastRADIUS{},
		check.PAP{User: papUser, Pass: papPass},
		check.PEAPMSCHAPv2{User: peapUser, Pass: peapPass, ServerName: *serverName},
		check.EAPTTLS{User: ttlsUser, Pass: ttlsPass, ServerName: *serverName},
		check.EAPTLS{CertFile: *clientCert, KeyFile: *clientKey, ServerName: *serverName},
		check.ServerCert{ServerName: *serverName},
		check.MTUProbe{Enabled: *mtu},
	}

	if len(servers) > 1 {
		return runMultiServer(target, checks, servers, *jsonOut, *noColor, *strict)
	}

	target.Address = servers[0]
	plan := check.Plan{Target: target, Checks: checks}

	// Sink: JSON for scripting, text for humans.
	var sink resultSink
	if *jsonOut {
		sink = report.NewJSONSink(os.Stdout)
	} else {
		fmt.Printf("Testing RADIUS server %s (as NAS %q)\n\n", servers[0], *nasID)
		sink = report.NewTextSink(os.Stdout, report.UseColor(os.Stdout, *noColor))
	}

	if *count != 1 {
		return runRepeat(plan, sink, *count, *interval, *strict, *jsonOut)
	}

	runner := check.Runner{Sink: sink}
	runner.Run(context.Background(), plan)
	_ = sink.Close()

	return exitCode(sink, *strict)
}

// parseServers splits the --server value on commas into normalized host:port
// entries (default port 1812), dropping empties (a trailing comma) and
// duplicates while preserving order. At least one server must remain.
func parseServers(raw string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if !strings.Contains(s, ":") {
			s += ":1812"
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errors.New("--server is required")
	}
	return out, nil
}

// resolveBindAddr turns a --bind IP[:port] value into the source address sockets
// bind to. Empty means "let the OS choose". The source must be an IP literal (a
// specific local address on this host), never a hostname — binding is about
// which interface leaves, not name resolution. Port defaults to 0 (ephemeral).
func resolveBindAddr(s string) (*net.UDPAddr, error) {
	if s == "" {
		return nil, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// Most commonly there's no port (a bare source IP); retry with port 0.
		host, port = s, "0"
	}
	if net.ParseIP(host) == nil {
		return nil, fmt.Errorf("--bind %q: source must be a local IP address, not a hostname", s)
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("--bind %q is not a valid IP[:port]: %w", s, err)
	}
	return addr, nil
}

// runMultiServer runs the full check plan against each server in turn, prints
// each server's block, then a comparison verdict — split-brain between RADIUS
// servers being a classic hidden cause of "intermittent" auth tickets. Each
// server is still bounded by the runner's rate ceiling; comparing servers never
// raises the load on any one of them. The exit code follows the combined result
// (a FAIL on any server fails the run; under --strict, a WARN does too).
func runMultiServer(base check.Target, checks []check.Check, servers []string, jsonOut, noColor, strict bool) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var jsink *report.JSONSink
	if jsonOut {
		jsink = report.NewJSONSink(os.Stdout)
	}

	var runs []check.ServerRun
	for i, srv := range servers {
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "interrupted — tested %d of %d servers\n", i, len(servers))
			break
		}
		target := base
		target.Address = srv
		plan := check.Plan{Target: target, Checks: checks}

		var results []check.Result
		if jsonOut {
			runner := check.Runner{Sink: jsink} // accumulates combined results + summary
			results = runner.Run(ctx, plan)
		} else {
			fmt.Printf("=== Server %d/%d: %s ===\n\n", i+1, len(servers), srv)
			ts := report.NewTextSink(os.Stdout, report.UseColor(os.Stdout, noColor))
			runner := check.Runner{Sink: ts}
			results = runner.Run(ctx, plan)
			_ = ts.Close()
			fmt.Println()
		}
		runs = append(runs, check.ServerRun{Server: srv, Results: results})
	}

	cmp := check.CompareServers(runs)
	if jsonOut {
		jsink.SetServers(runs, cmp)
		_ = jsink.Close()
	} else {
		fmt.Print(report.ComparisonBlock(cmp))
	}
	return multiExitCode(runs, strict)
}

// multiExitCode maps the combined multi-server results to the process exit code,
// independent of the sink: 1 if any server had a FAIL, or — under --strict — a
// WARN; otherwise 0.
func multiExitCode(runs []check.ServerRun, strict bool) int {
	for _, r := range runs {
		for _, res := range r.Results {
			if res.Status == check.StatusFail || (strict && res.Status == check.StatusWarn) {
				return 1
			}
		}
	}
	return 0
}

// runRepeat drives --count: N sequential iterations, then the aggregate
// verdicts through the normal sink, so text/JSON rendering and the exit-code
// contract are identical to a single run. Ctrl-C mid-loop aggregates the
// iterations that completed instead of throwing them away.
func runRepeat(plan check.Plan, sink resultSink, count int, interval time.Duration, strict, jsonOut bool) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	effective, stretched := check.EffectiveInterval(interval)
	if stretched {
		// Stderr in both modes: with --json, stdout stays pure JSON (the
		// document carries interval_stretched for scripts).
		fmt.Fprintf(os.Stderr, "note: --interval %s is below the probe's hard-coded safety floor; running %s apart instead\n", interval, effective)
	}
	opts := check.RepeatOptions{Count: count, Interval: interval}
	if !jsonOut {
		fmt.Printf("Running %d iterations, %s apart\n\n", count, effective)
		opts.OnIteration = func(i int, results []check.Result) {
			fmt.Println(report.IterationLine(i, count, results))
		}
	}

	runner := check.Runner{}
	run, err := check.RunRepeated(ctx, &runner, plan, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if completed := len(run.Iterations); completed < count {
		fmt.Fprintf(os.Stderr, "interrupted — aggregating the %d completed iteration(s)\n", completed)
		if completed == 0 {
			return 1
		}
	}

	stats := check.AggregateRepeat(run)
	if !jsonOut {
		fmt.Printf("\nAggregate over %d runs:\n\n", len(run.Iterations))
	}
	for _, s := range stats {
		sink.Emit(s.Verdict())
	}
	if js, ok := sink.(*report.JSONSink); ok {
		js.SetRepeat(count, run, stats)
	}
	_ = sink.Close()
	return exitCode(sink, strict)
}

// resultSink is the report-sink surface both subcommands use: the check.ResultSink
// contract plus the tallies that drive the process exit code.
type resultSink interface {
	check.ResultSink
	Failed() bool
	Warned() bool
}

// exitCodeHelp is appended to --help for both subcommands. The 0/1/2 contract is
// stable — RMM scripts and Task Scheduler depend on it — so it is documented in
// one place and shown identically everywhere.
const exitCodeHelp = `
Exit codes:
  0  all checks passed (warnings allowed unless --strict)
  1  a check FAILED — or, under --strict, a WARN (e.g. a cert expiring soon)
  2  usage error (bad flags or missing --server)

With --json the same result is machine-readable: .summary.fail / .summary.warn
counts and per-check .results[].status. Schema: docs/json-schema.md.
`

// exitCode maps a finished run to the process exit code: 1 if any check failed,
// or — under --strict — if any check warned; otherwise 0. Usage errors (2) are
// handled at the call sites before a run starts.
func exitCode(sink resultSink, strict bool) int {
	if sink.Failed() || (strict && sink.Warned()) {
		return 1
	}
	return 0
}

var nasPortTypes = map[string]int{
	"wireless": radius.NASPortWireless80211,
	"ethernet": radius.NASPortEthernet,
	"virtual":  radius.NASPortVirtual,
}

// stringSliceFlag collects a repeatable string flag (e.g. --expect-attr given
// several times), in order.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ", ") }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// buildExpectations turns --expect-vlan and --expect-attr flags into the
// authorization assertions the checks evaluate on Access-Accept. --expect-vlan
// is a convenience for Tunnel-Private-Group-ID labelled "VLAN"; --expect-attr
// takes 'Name=Value' where Name is the attribute's display name.
func buildExpectations(vlan string, attrs stringSliceFlag) ([]check.Expectation, error) {
	var out []check.Expectation
	if vlan != "" {
		out = append(out, check.Expectation{Name: "Tunnel-Private-Group-ID", Value: vlan, Label: "VLAN"})
	}
	for _, a := range attrs {
		name, value, ok := strings.Cut(a, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("--expect-attr must be 'Name=Value', got %q", a)
		}
		out = append(out, check.Expectation{Name: name, Value: value, Label: name})
	}
	return out, nil
}

// resolveCreds parses a "user[:password]" flag value and resolves the password
// without ever requiring it on the command line. Empty means the check is
// skipped. "user:password" uses the inline password (with a TTY warning, since
// it leaks into history/ps); a bare "user" resolves the password from
// --password-file, AUTHHOUND_PASSWORD, or an interactive prompt. A password may
// contain colons; only the first colon splits.
func resolveCreds(p credential.Prompter, v, flagName, passwordFile string) (user, pass string, err error) {
	if v == "" {
		return "", "", nil
	}
	u, inlinePass, hasColon := strings.Cut(v, ":")
	if u == "" {
		return "", "", fmt.Errorf("%s must be user or user:password", flagName)
	}
	pass, err = p.Resolve(credential.Spec{
		Name:      "password for " + u,
		Inline:    inlinePass,
		InlineSet: hasColon,
		File:      passwordFile,
		EnvVar:    "AUTHHOUND_PASSWORD",
		Required:  true,
	})
	if err != nil {
		return "", "", err
	}
	return u, pass, nil
}

func cmdConnect() {
	fmt.Println("Continuous monitoring (connect) is part of AuthHound's paid tier.")
	fmt.Println("The same probe you're running will report scheduled results to the")
	fmt.Println("AuthHound service, catching failures before your users complain.")
	fmt.Println("\nLearn more / join the waitlist: https://authhound.com")
}

func usage() {
	fmt.Fprintln(os.Stderr, `authhound-probe — outside-in auth diagnostics, run from inside your network

Usage:
  authhound-probe radius test --server HOST --secret SECRET [--pap user:pass]
  authhound-probe radsec test --server HOST [--client-cert cert.pem --client-key key.pem]
  authhound-probe connect             (premium: continuous monitoring)
  authhound-probe version

'radius test' and 'radsec test' run once, locally, with no account — nothing you
enter leaves this host. More protocols (ldap, sso) are planned as sibling commands.
Full docs: https://authhound.com`)
}
