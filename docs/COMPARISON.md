# authhound-probe vs eapol_test vs radtest

`eapol_test` and `radtest` are the two tools RADIUS admins have reached for
over two decades, and both are excellent at what they were built for.
`eapol_test` (part of Jouni Malinen's wpa_supplicant/hostap project) is the
reference EAP test client — nothing else covers as many EAP methods.
`radtest` (from the FreeRADIUS utilities) is the fastest possible "does an
Access-Request come back" sanity check, installed anywhere FreeRADIUS is.

`authhound-probe` sits in a different spot: it's built for the *diagnosis*
workflow — one binary, no config file, plain-English verdicts with next steps,
and machine-readable output for RMM/monitoring scripts. This page is a factual
comparison so you can pick the right tool for the job at hand.

## At a glance

| | **authhound-probe** | **eapol_test** | **radtest** |
|---|---|---|---|
| Ships as | Single static binary (Linux/macOS/Windows), signed releases | Part of wpa_supplicant; usually compiled from source with `CONFIG_EAPOL_TEST=y` (some distros/ports package it) | `freeradius-utils` package (a wrapper around `radclient`) |
| Configuration | Command-line flags only | wpa_supplicant-style config file per scenario | Command-line arguments |
| PAP | ✅ | — (EAP only) | ✅ (also CHAP, MSCHAP via radclient) |
| PEAP-MSCHAPv2 | ✅ | ✅ | — |
| EAP-TTLS | ✅ (inner PAP) | ✅ (many inner methods) | — |
| EAP-TLS | ✅ | ✅ | — |
| Other EAP methods (FAST, PWD, SIM/AKA, …) | — | ✅ widest coverage anywhere | — |
| Server certificate analysis (expiry, chain, name) | ✅ with PASS/WARN/FAIL verdicts | Cert is in the debug output; you interpret it | — |
| Path-MTU / EAP fragmentation probing | ✅ (`--mtu`) | fragment size is configurable, not probed | — |
| RadSec (RADIUS/TLS) testing | ✅ (`radsec test`) | — | — |
| Status-Server (RFC 5997) liveness | ✅ | — | ✅ (`radclient status`) |
| BlastRADIUS (CVE-2024-3596) posture check | ✅ | — | — |
| Multi-server comparison / flakiness stats | ✅ (`--server a,b`, `--count N`) | scriptable around it | scriptable around it |
| Output | Plain-English PASS/WARN/FAIL + what to check next | Full protocol debug trace (excellent for deep debugging) | Terse packet dump |
| Machine-readable output | ✅ `--json` (versioned schema) + stable exit codes | exit code | exit code |
| Windows | ✅ first-class (NPS-aware, `.exe`, Scheduled Task recipes) | not practical | via WSL/ports |
| Best at | Fast diagnosis, monitoring scripts, handing a check to a colleague | Exhaustive EAP method coverage, protocol-level debugging | Instant PAP/secret sanity check where FreeRADIUS is installed |

## When to use which

**Use `radtest`** when you're on a box that already has FreeRADIUS installed
and you want a two-second answer to "does the server accept this PAP login /
is the secret right". It's the ubiquitous quick check — no download needed.

**Use `eapol_test`** when you need an EAP method the probe doesn't speak
(EAP-FAST, EAP-PWD, EAP-SIM/AKA, exotic inner methods), or when you want the
full protocol trace to debug a genuinely weird interop problem. It is the
reference implementation; its debug output is the ground truth. The cost is
getting a build of it and writing a config file per scenario, and reading raw
protocol output.

**Use `authhound-probe`** when the question is "why is 802.1X broken and
which hop do I fix" or "script this check into my RMM": one command with
flags, a verdict per layer (reachability → secret → auth → certificate →
MTU), guidance on what to check next, `--json` with a versioned schema, and
the same binary on the Windows box next to your NPS server. It covers the
methods that dominate real networks (PAP, PEAP-MSCHAPv2, EAP-TTLS/PAP,
EAP-TLS) plus the checks the classics don't attempt: certificate expiry/name
verdicts, path-MTU probing, RadSec, BlastRADIUS posture, and multi-server
drift comparison.

They compose, too: plenty of workflows start with `authhound-probe` to
localise the failure in seconds, then drop into `eapol_test` for a
protocol-level trace of the one broken method.

*Something in this table outdated or unfair? Open an issue — factual
corrections are very welcome.*
