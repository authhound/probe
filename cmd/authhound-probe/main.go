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
	"strings"
	"time"

	"github.com/authhound/probe/internal/check"
	"github.com/authhound/probe/internal/radius"
	"github.com/authhound/probe/internal/report"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "radius":
		os.Exit(cmdRadius(os.Args[2:]))
	case "connect":
		cmdConnect()
	case "version", "-v", "--version":
		fmt.Println("authhound-probe", version)
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

func cmdRadiusTest(args []string) int {
	fs := flag.NewFlagSet("radius test", flag.ExitOnError)
	server := fs.String("server", "", "RADIUS server host or host:port (default port 1812)")
	secret := fs.String("secret", "", "shared secret configured for this probe on the server")
	pap := fs.String("pap", "", "run a PAP auth test with these credentials: user:password")
	peap := fs.String("peap", "", "run a PEAP-MSCHAPv2 auth test with these credentials: user:password")
	clientCert := fs.String("client-cert", "", "client certificate (PEM) for an EAP-TLS auth test")
	clientKey := fs.String("client-key", "", "client private key (PEM) for the EAP-TLS test")
	nasID := fs.String("nas-id", "authhound-probe", "NAS-Identifier to send")
	nasPortType := fs.String("nas-port-type", "wireless", "NAS-Port-Type: wireless, ethernet, or virtual")
	serverName := fs.String("server-name", "", "expected server certificate name (TLS SNI); optional")
	timeout := fs.Duration("timeout", 5*time.Second, "per-request timeout")
	jsonOut := fs.Bool("json", false, "emit results as JSON instead of text")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: authhound-probe radius test --server HOST --secret SECRET [--pap user:pass]")
		fmt.Fprint(os.Stderr, "\nRuns local, read-only RADIUS/802.1X checks. Nothing leaves this host.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if *server == "" || *secret == "" {
		fmt.Fprint(os.Stderr, "error: --server and --secret are required\n\n")
		fs.Usage()
		return 2
	}
	addr := *server
	if !strings.Contains(addr, ":") {
		addr += ":1812"
	}

	portType, ok := nasPortTypes[*nasPortType]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: --nas-port-type must be wireless, ethernet, or virtual\n")
		return 2
	}

	target := check.Target{
		Address:       addr,
		Secret:        *secret,
		Timeout:       *timeout,
		NASIdentifier: *nasID,
		NASPortType:   portType,
	}

	papUser, papPass, err := splitCreds(*pap, "--pap")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	peapUser, peapPass, err := splitCreds(*peap, "--peap")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if (*clientCert == "") != (*clientKey == "") {
		fmt.Fprintln(os.Stderr, "error: --client-cert and --client-key must be given together")
		return 2
	}

	// Sink: JSON for scripting, text for humans.
	var sink interface {
		check.ResultSink
		Failed() bool
	}
	if *jsonOut {
		sink = report.NewJSONSink(os.Stdout)
	} else {
		fmt.Printf("Testing RADIUS server %s (as NAS %q)\n\n", addr, *nasID)
		sink = report.NewTextSink(os.Stdout, !*noColor)
	}

	runner := check.Runner{Sink: sink}
	plan := check.Plan{
		Target: target,
		Checks: []check.Check{
			check.Reachability{},
			check.SharedSecret{},
			check.PAP{User: papUser, Pass: papPass},
			check.PEAPMSCHAPv2{User: peapUser, Pass: peapPass, ServerName: *serverName},
			check.EAPTLS{CertFile: *clientCert, KeyFile: *clientKey, ServerName: *serverName},
			check.ServerCert{ServerName: *serverName},
		},
	}
	runner.Run(context.Background(), plan)
	_ = sink.Close()

	if sink.Failed() {
		return 1
	}
	return 0
}

var nasPortTypes = map[string]int{
	"wireless": radius.NASPortWireless80211,
	"ethernet": radius.NASPortEthernet,
	"virtual":  radius.NASPortVirtual,
}

// splitCreds parses a "user:password" flag value. Empty is allowed (the check
// is skipped). A password may contain colons; only the first splits.
func splitCreds(v, flagName string) (user, pass string, err error) {
	if v == "" {
		return "", "", nil
	}
	u, p, ok := strings.Cut(v, ":")
	if !ok || u == "" {
		return "", "", fmt.Errorf("%s must be user:password", flagName)
	}
	return u, p, nil
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
  authhound-probe connect             (premium: continuous monitoring)
  authhound-probe version

'radius test' runs once, locally, with no account — nothing you enter leaves
this host. More protocols (ldap, sso) are planned as sibling commands.
Full docs: https://authhound.com`)
}
