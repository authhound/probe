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
	"flag"
	"fmt"
	"os"
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
	server := fs.String("server", "", "RADIUS server host or host:port (default port 1812)")
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
	mtu := fs.Bool("mtu", false, "run the path-MTU / fragmentation probe (sends a few padded packets)")
	timeout := fs.Duration("timeout", 5*time.Second, "per-request timeout")
	jsonOut := fs.Bool("json", false, "emit results as JSON instead of text")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	strict := fs.Bool("strict", false, "exit non-zero on warnings too (for scheduled monitoring)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: authhound-probe radius test --server HOST --secret SECRET [--pap user:pass]")
		fmt.Fprint(os.Stderr, "\nRuns local, read-only RADIUS/802.1X checks. Nothing leaves this host.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if *server == "" {
		fmt.Fprint(os.Stderr, "error: --server is required\n\n")
		fs.Usage()
		return 2
	}
	provided := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	addr := *server
	if !strings.Contains(addr, ":") {
		addr += ":1812"
	}

	portType, ok := nasPortTypes[*nasPortType]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: --nas-port-type must be wireless, ethernet, or virtual\n")
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

	target := check.Target{
		Address:       addr,
		Secret:        secretValue,
		Timeout:       *timeout,
		NASIdentifier: *nasID,
		NASPortType:   portType,
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

	// Sink: JSON for scripting, text for humans.
	var sink resultSink
	if *jsonOut {
		sink = report.NewJSONSink(os.Stdout)
	} else {
		fmt.Printf("Testing RADIUS server %s (as NAS %q)\n\n", addr, *nasID)
		sink = report.NewTextSink(os.Stdout, report.UseColor(os.Stdout, *noColor))
	}

	runner := check.Runner{Sink: sink}
	plan := check.Plan{
		Target: target,
		Checks: []check.Check{
			check.Reachability{},
			check.SharedSecret{},
			check.PAP{User: papUser, Pass: papPass},
			check.PEAPMSCHAPv2{User: peapUser, Pass: peapPass, ServerName: *serverName},
			check.EAPTTLS{User: ttlsUser, Pass: ttlsPass, ServerName: *serverName},
			check.EAPTLS{CertFile: *clientCert, KeyFile: *clientKey, ServerName: *serverName},
			check.ServerCert{ServerName: *serverName},
			check.MTUProbe{Enabled: *mtu},
		},
	}
	runner.Run(context.Background(), plan)
	_ = sink.Close()

	return exitCode(sink, *strict)
}

// resultSink is the report-sink surface both subcommands use: the check.ResultSink
// contract plus the tallies that drive the process exit code.
type resultSink interface {
	check.ResultSink
	Failed() bool
	Warned() bool
}

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
