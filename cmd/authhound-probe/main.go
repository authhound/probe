// Command authhound-probe runs outside-in RADIUS diagnostics from inside your
// network. In v1 it runs one-shot, locally, with no account and no cloud —
// everything you paste stays on this host.
//
//	authhound-probe test --server radius.corp.com --secret '***' \
//	    --pap 'alice:***'
//
// `connect` (premium) turns the same binary into a continuous probe reporting
// to AuthHound's monitoring service — see https://authhound.com.
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
	case "test":
		os.Exit(cmdTest(os.Args[2:]))
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

func cmdTest(args []string) int {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	server := fs.String("server", "", "RADIUS server host or host:port (default port 1812)")
	secret := fs.String("secret", "", "shared secret configured for this probe on the server")
	pap := fs.String("pap", "", "run a PAP auth test with these credentials: user:password")
	nasID := fs.String("nas-id", "authhound-probe", "NAS-Identifier to send")
	nasPortType := fs.String("nas-port-type", "wireless", "NAS-Port-Type: wireless, ethernet, or virtual")
	serverName := fs.String("server-name", "", "expected server certificate name (TLS SNI); optional")
	timeout := fs.Duration("timeout", 5*time.Second, "per-request timeout")
	jsonOut := fs.Bool("json", false, "emit results as JSON instead of text")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: authhound-probe test --server HOST --secret SECRET [--pap user:pass]")
		fmt.Fprint(os.Stderr, "\nRuns local, read-only RADIUS checks. Nothing leaves this host.\n\nFlags:\n")
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
	if *pap != "" {
		u, p, ok := strings.Cut(*pap, ":")
		if !ok {
			fmt.Fprintln(os.Stderr, "error: --pap must be user:password")
			return 2
		}
		target.Username, target.Password = u, p
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
			check.PAP{},
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

func cmdConnect() {
	fmt.Println("Continuous monitoring (connect) is part of AuthHound's paid tier.")
	fmt.Println("The same probe you're running will report scheduled results to the")
	fmt.Println("AuthHound service, catching failures before your users complain.")
	fmt.Println("\nLearn more / join the waitlist: https://authhound.com")
}

func usage() {
	fmt.Fprintln(os.Stderr, `authhound-probe — outside-in RADIUS diagnostics, run from inside your network

Usage:
  authhound-probe test --server HOST --secret SECRET [--pap user:pass]
  authhound-probe connect        (premium: continuous monitoring)
  authhound-probe version

'test' runs once, locally, with no account. Nothing you enter leaves this host.
Full docs: https://authhound.com`)
}
