# Security

You run this tool inside your network with your RADIUS shared secret, often on
a shared jump box. That only works if you can answer "what does this thing do
to my network and my secrets" without reading the code. This page is that
answer — the threat model first, then how to report a problem, then how we
keep the supply chain checkable.

## What the probe sends

- **RADIUS traffic to the server you name, and nothing else.** Access-Request
  and Status-Server packets out (UDP/1812 for `radius test`, TLS on TCP/2083
  for `radsec test`), replies in. Exactly what a switch or access point would
  send — the probe *is* a NAS as far as the server can tell.
- **No telemetry, no phone-home, no update check.** The free tool never
  contacts authhound.com or any other host. The only network peer of a run is
  the RADIUS server on the command line. (`connect`, the paid tier, is
  explicitly opt-in and prints what it would do; in this open-source tool it
  does nothing else.)
- **Bounded rate.** A hard-coded rate ceiling in the runner caps how fast
  packets leave, and `--count` is capped at 50 iterations with an enforced
  interval floor. There is no flag, environment variable, or config file that
  raises either — the probe cannot be turned into a load generator or used to
  hammer someone else's server.

## What it stores

Nothing. The probe is a one-shot process:

- no config files written, no cache, no history, no state directory;
- no daemon or watch mode — when the run ends, the process and everything it
  knew are gone;
- secrets read from a file (`--secret-file` / `--password-file`) stay on the
  file you own; the probe only ever reads them.

## What it never does

- **Never captures packets** or opens raw sockets — it sends its own requests
  and reads its own replies, nothing else on the wire.
- **Never changes anything on the RADIUS server.** Authentication requests
  are read-only from the server's point of view; the probe has no
  provisioning, CoA, or accounting-write capability.
- **Never completes a second factor.** If the server issues an MFA challenge,
  the probe reports that boundary and stops — completing a push/OTP from an
  unattended tool would mean holding a live MFA secret, which it refuses to do.
- **Never proxies or forwards authentication** for anything else.
- **Never sends your secrets anywhere** except inside the RADIUS/EAP exchange
  they are for (see below).

## How credentials are handled

- **Inputs stay off the command line by default.** The shared secret and any
  password can come from a file (refused if group/world-readable on unix), an
  environment variable, standard input, or a no-echo interactive prompt — the
  inline `--secret`/`user:pass` forms work but print a warning on a terminal,
  because they leak into shell history and `ps`. Precedence and details:
  [README — Where credentials come from](README.md#where-credentials-come-from).
- **Secrets are used only to build protocol messages.** The shared secret
  signs/validates RADIUS packets; passwords are hidden per RFC 2865 (PAP) or
  used inside the TLS tunnel (PEAP/TTLS) or as MSCHAPv2 responses — never
  transmitted in the clear outside the protocol that carries them.
- **Secrets never appear in output.** Not in text output, `--json`, hints,
  error messages, or panics. This is enforced by tests (including a dedicated
  leak test in `cmd/authhound-probe/leak_test.go`) and asserted again by the
  Docker smoke test, which greps every output surface for the secret.
- **The EAP-TLS/RadSec private key** is read from disk only to complete the
  TLS handshake; it is never transmitted (TLS never sends private keys) or
  logged.
- Environment variables are convenient but readable by other processes running
  as the same user — for hostile multi-user boxes, prefer a `chmod 600` file
  or the prompt.

## TLS and certificate posture — an honest note

The probe's TLS handshakes (PEAP/TTLS/EAP-TLS tunnels and RadSec) deliberately
run with certificate verification disabled at the TLS layer, because the probe
is a *diagnostic*: its job is to capture the certificate the server presents
and report on it — expiry, chain completeness, name — even (especially) when
that certificate is broken. A normal TLS client would abort on the broken cert
and tell you nothing.

What that means in practice:

- The dedicated certificate checks (`server-cert`, `radsec-cert`) do the
  verification *as reporting*: expiry and chain problems FAIL/WARN, and the
  certificate name is validated against `--server-name` — a mismatch is a
  FAIL. **If `--server-name` is omitted, name validation is skipped and the
  probe says so with a WARN** (`name_validation: "skipped"` in `--json`); it
  never reports an unqualified "valid" for a name it didn't check.
- The credential-carrying checks (PEAP/TTLS) therefore complete their exchange
  even against a server presenting an untrusted certificate. The inner
  credential is protected by the method itself (MSCHAPv2 challenge-response
  never sends the password; TTLS-PAP sends it only inside the tunnel), but a
  sufficiently positioned attacker who can intercept RADIUS *and* knows your
  shared secret could present their own tunnel endpoint. Use a dedicated
  least-privilege test account — the README says this everywhere credentials
  come up — and treat `--server-name` plus the server-cert check as your
  impersonation tripwire.

## Verify what you downloaded

Every release artifact is checksummed and keyless-signed with Sigstore cosign,
bound to this repo's tagged release workflow via OIDC and logged in the public
Rekor transparency log — you can prove a binary came from our CI and was not
tampered with, without trusting a long-lived key. Step-by-step commands
(including Windows): [README — Verify your download](README.md#verify-your-download).
Every archive also ships an SPDX SBOM, so when a CVE drops you can check your
exposure in seconds.

## Reporting a vulnerability

- Use GitHub private vulnerability reporting — [Security →
  "Report a vulnerability"](https://github.com/authhound/probe/security/advisories/new)
  on this repo. It reaches the maintainer privately and tracks the fix.
- Please don't open a public issue for anything you believe is exploitable.

You'll get an acknowledgement within 72 hours. Confirmed vulnerabilities get a
GitHub Security Advisory and a patch release; the SBOMs let you determine your
exposure without waiting on us. We won't take legal action against good-faith
research done against your own infrastructure.

## Dependencies & supply chain

**Minimal-dependency policy.** The probe is stdlib-first Go. The dependency
tree is one direct module — `golang.org/x/term`, for no-echo secret prompts —
plus its `golang.org/x/sys` transitive, both maintained by the Go team. Every
dependency we don't have is a CVE stream we never have to watch; proposals
that add a dependency need to explain why ~50 lines of stdlib code can't do
the job. (MD4, needed for MSCHAPv2 interop, is vendored from the frozen
`golang.org/x/crypto/md4` into `internal/md4` with its license and RFC 1320
test vectors rather than pulling in the whole module.)

**Detection.**
- Every PR runs [`govulncheck`](https://go.dev/security/vuln/) in CI and
  fails on findings that are *reachable* from our code — call-graph analysis,
  not just version matching, so a red check always means something real.
- A daily scheduled scan runs the same check against `main`, catching CVEs
  published against dependencies (or the Go standard library) we haven't
  touched in months. Findings automatically open a tracking issue.
- PRs that change the dependency manifest additionally run GitHub's
  dependency review, which flags newly introduced vulnerable versions and
  license changes.

**Updates.** Dependabot opens PRs for Go modules and GitHub Actions weekly;
security updates arrive immediately. Nothing auto-merges — every bump gets a
human review, because real supply-chain attacks ride *new* versions and Go's
checksum database already prevents tampered re-publishes of existing ones.
The full policy is in [RELEASING.md](RELEASING.md#dependency-update-policy).

**Build pipeline.** Every GitHub Action in our workflows is pinned to a full
commit SHA (a hijacked version tag on a popular action is the likeliest
supply-chain hole in a small repo), and the workflow `GITHUB_TOKEN` is
read-only except in the release job. Releases are built by GoReleaser in CI —
no artifacts are ever uploaded by hand — and every release ships:

- keyless (Sigstore) cosign signatures, so you can verify artifacts came from
  this repo's release workflow (see "Verify your download" in the README);
- an SPDX SBOM per archive, so when a CVE drops you can check in seconds
  whether a release you deployed contains the affected module.

**What we promise.** Not zero CVEs — nobody can promise that honestly. What
we promise is fast, loud handling: if a vulnerability ships in a release, we
publish a GitHub Security Advisory and a patch release, and the SBOMs let you
determine your exposure without waiting on us.
