# authhound-probe

**Test any RADIUS server — FreeRADIUS, Windows NPS, or cloud — from inside your network.**

[![CI](https://github.com/authhound/probe/actions/workflows/ci.yml/badge.svg)](https://github.com/authhound/probe/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/authhound/probe)](https://goreportcard.com/report/github.com/authhound/probe)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A RADIUS server only logs the requests that *reach* it. A huge class of 802.1X failures happens before that — a firewall eating UDP, a NAT rewriting the source, the wrong shared secret on one switch, an expired server certificate, EAP fragments dropped in the path. The dashboard (or your `radiusd -X` log) says "all good"; your users say "Wi-Fi is broken"; the ticket ping-pongs for days.

`authhound-probe` runs a **real** authentication against your RADIUS server from **inside your network**, acting as a NAS (switch/AP) would, and tells you in plain English which hop is broken. Works with self-hosted **FreeRADIUS** and **Windows NPS**, and with hosted/cloud RADIUS services. No account, no signup, no telemetry — everything you type stays on the host you run it on.

```console
$ export AUTHHOUND_SECRET='shared-secret'   # kept out of shell history and `ps`
$ authhound-probe radius test --server radius.corp.com --peap alice
Enter password for alice:

Testing RADIUS server radius.corp.com:1812 (as NAS "authhound-probe")

PASS  RADIUS server answered in 23ms
PASS  Shared secret is correct (reply signature verified)
PASS  PEAP-MSCHAPv2 authentication succeeded for alice
PASS  Server certificate valid for 214 more days, chain looks complete (TLS 1.2)

Verdict: 4 passed, 0 failed, 0 warnings
```

Like `eapol_test` or `radtest`, but the output is readable — one command, no `wpa_supplicant` config file. Add `--json` for scripting, `--nas-port-type ethernet|wireless|virtual` to match how your real NAS presents itself, and `--server-name` to set the expected certificate name.

## Step 0 — register the probe on your server (one time)

Because the probe acts as a NAS, your RADIUS server must know it as a client — otherwise the server **silently drops** its requests and every check times out. Add the probe's IP and a shared secret:

**FreeRADIUS** (`clients.conf`, then restart):

```
client authhound-probe {
    ipaddr = 10.20.0.50      # the probe's IP
    secret = <shared secret>
}
```

**Windows NPS** — PowerShell (elevated), or NPS console → RADIUS Clients → New:

```powershell
New-NpsRadiusClient -Name "authhound-probe" -Address "10.20.0.50" -SharedSecret "<shared secret>"
```

**Cloud/hosted RADIUS:** register the probe's IP and secret in the vendor's admin UI, per their documentation.

If NAT sits between the probe and the server, register the **post-NAT** source IP — the address the server actually sees. Use a dedicated secret and a least-privilege test account — never a real admin credential.

Skipped this step? The probe notices: on a first-run timeout it prints this exact snippet with your detected source IP already filled in, ready to paste.

## What it checks (v1)

| Check | What it proves |
|---|---|
| **Reachability** | The server answers on UDP/1812 — and how fast. A timeout means unreachable, not listening, **or the probe isn't whitelisted / the secret is wrong** (servers silently drop unverifiable requests). |
| **Shared secret** | Cryptographically verifies the server's reply signature. A pass *proves* the secret matches — no more guessing whether "everyone's getting rejected" is a secret problem or something else. |
| **PAP authentication** | A real login with credentials you supply → Accept or Reject, decoded. Also detects an **MFA/second-factor challenge** and reports it (the probe does not complete push/OTP — see below). |
| **PEAP-MSCHAPv2** | The method most enterprise 802.1X networks actually run: a real inner authentication inside the PEAP TLS tunnel. Reports success — and verifies the server's own MSCHAPv2 proof (mutual auth) — or the decoded reason on rejection. The "can my users actually log in?" test. |
| **EAP-TTLS (PAP)** | A real login inside the TTLS tunnel using inner PAP. Because the password is checked in cleartext (safe inside the tunnel), TTLS-PAP works against *any* backend — including hashed stores that MSCHAPv2 can't use. If PEAP-MSCHAPv2 fails but this passes, the directory can't produce an NT hash. |
| **EAP-TLS** | Certificate-based login (no password): presents a client certificate and reports whether the server accepts it — with a plain-English reason on failure (untrusted CA, expired cert, policy reject). See [EAP-TLS: preparing a client certificate](#eap-tls-preparing-a-client-certificate). |
| **Server certificate** | Establishes the PEAP/TLS tunnel over RADIUS, captures the server's certificate, and flags **expiry**, an incomplete intermediate chain, and the negotiated TLS version. The "Wi-Fi died overnight" outage, caught early. |
| **Path MTU / fragmentation** (`--mtu`) | Finds the largest RADIUS packet that survives the round trip. Pinpoints the invisible failure where a firewall or VPN drops large / IP-fragmented UDP, so the multi-kilobyte EAP-TLS certificate flight never arrives and 802.1X silently stalls — while every server-side log looks clean. |
| **RadSec** (`radsec test`) | Checks a RADIUS/TLS endpoint on TCP/2083: reachability, TLS handshake, server certificate, and a RADIUS exchange over the tunnel. For modern deployments and UDP→RadSec migration readiness. |

### A note on MFA / two-factor

If the server issues an MFA challenge after valid primary credentials, the probe reports that boundary — *"primary auth healthy, second factor required"* — but does **not** approve a push or submit an OTP. Completing a second factor from an unattended probe would mean storing a live MFA secret, which this tool refuses to do. For monitoring, point it at a **test account exempt from MFA** so the primary RADIUS path is validated cleanly.

### Machine auth (NPS)

Windows NPS shops authenticate **computers** as often as users — a domain PC does
802.1X with the identity `host/PC-NAME.domain` and its **machine-account
password**, not a person's credentials. The probe speaks this natively: pass the
`host/`-style identity to `--peap` exactly like a username. Set
`--nas-port-type ethernet` if you're modelling a wired switch port, so NPS
evaluates the same Connection Request / Network Policy your real switches hit:

```console
# a computer account, authenticated the way a domain PC does it
$ authhound-probe radius test --server nps.corp.local \
    --nas-port-type ethernet --peap 'host/PC-01.corp.local:<machine password>'
```

(The identity has no colon, so `host/PC-01.corp.local:<pw>` splits correctly on
the first `:` into identity + password. As always, prefer `AUTHHOUND_PASSWORD` or
`--password-file` over an inline password.)

**The honest boundary: getting a machine password.** A real computer account's
password is generated by the domain and rotated automatically (~every 30 days) —
it is *not* something an admin normally knows, so you usually can't type it in.
Two ways to still exercise this path end-to-end:

- **Provision a dedicated test computer object** in AD with a password you set and
  control (and exclude it from automatic rotation), then probe with that identity.
  This is the cleanest way to get a green "computers can authenticate" check on a
  schedule.
- **Reset a throwaway machine's password** to a known value for a one-off test
  (`Reset-ComputerMachinePassword` / `dsmod computer`), understanding the domain
  will rotate it again.

**What the probe verifies without a machine password.** Even with no computer
credential, it confirms everything *around* the machine-auth path — the parts that
actually break: the probe is reachable and registered as a RADIUS client
(NPS console → **RADIUS Clients**), the shared secret is correct, the NPS server
certificate is valid and its chain complete (what clients validate in PEAP), and —
with `--nas-port-type ethernet` — that the **Network Policy** for wired
authentication is reachable. Those cover the failures you'd otherwise chase blind;
the inner MSCHAPv2 step is the only piece that needs the password.

## Usage

The shared secret and any password are read from the environment, a file, or an
interactive prompt — never required on the command line, where they would land in
your shell history and be visible to every user on the box via `ps`. See
[Where credentials come from](#where-credentials-come-from) for all the options.
The examples below use the environment variable and prompt forms.

Reachability, shared-secret, and server-certificate checks run automatically — no
login credentials needed:

```console
$ export AUTHHOUND_SECRET='shared-secret'
$ authhound-probe radius test --server radius.corp.com
```

Add an authentication test with the method your network actually uses. Give
`--pap/--peap/--ttls` as just the username and you'll be prompted (no echo) for
the password:

```console
$ export AUTHHOUND_SECRET='shared-secret'

# PEAP-MSCHAPv2 — what most enterprise Wi-Fi / 802.1X runs
$ authhound-probe radius test --server radius.corp.com --peap alice

# PAP — VPNs, simple setups, or as a backend baseline
$ authhound-probe radius test --server radius.corp.com --pap alice

# EAP-TTLS with inner PAP — works even against hashed password backends
$ authhound-probe radius test --server radius.corp.com --ttls alice

# EAP-TLS — certificate-based login (see cert prep below), no password
$ authhound-probe radius test --server radius.corp.com \
    --client-cert client.pem --client-key client.key

# add the path-MTU / fragmentation probe (troubleshooting EAP-TLS stalls)
$ authhound-probe radius test --server radius.corp.com --mtu

# several at once — prompted once per method
$ authhound-probe radius test --server radius.corp.com \
    --pap alice --peap alice \
    --client-cert client.pem --client-key client.key --mtu
```

For non-interactive use (RMM, cron), supply the password without a prompt via
`AUTHHOUND_PASSWORD` or `--password-file`:

```console
$ AUTHHOUND_SECRET='shared-secret' AUTHHOUND_PASSWORD='pw' \
    authhound-probe radius test --server radius.corp.com --peap alice --json
```

**RadSec** (RADIUS/TLS on TCP/2083) is a separate subcommand — it checks
reachability, the TLS handshake, the server certificate, and a RADIUS exchange
over the tunnel. RadSec is usually mutual TLS, so supply a client cert if the
endpoint requires one:

```console
$ authhound-probe radsec test --server radius.corp.com
$ authhound-probe radsec test --server radius.corp.com \
    --client-cert client.pem --client-key client.key
```

**`radius test` flags:**

| Flag | Purpose |
|---|---|
| `--server HOST[:port]` | RADIUS server (default port 1812). **Required.** |
| `--secret SECRET` | Shared secret (**required**, but prefer `AUTHHOUND_SECRET` / `--secret-file` / `--secret-stdin` — see [below](#where-credentials-come-from)). |
| `--secret-file FILE` | Read the shared secret from a file (must not be world-readable on unix). |
| `--secret-stdin` | Read the shared secret from standard input (one line). |
| `--pap user[:pass]` | Run a PAP test. Give just `user` to be prompted for the password. |
| `--peap user[:pass]` | Run a PEAP-MSCHAPv2 test. Give just `user` to be prompted. |
| `--ttls user[:pass]` | Run an EAP-TTLS (inner PAP) test. Give just `user` to be prompted. |
| `--password-file FILE` | Password for a `user`-only `--pap/--peap/--ttls`, from a file (non-interactive). |
| `--client-cert FILE` `--client-key FILE` | Run an EAP-TLS test with this client certificate + key (PEM). |
| `--mtu` | Run the path-MTU / fragmentation probe (sends a few padded packets). |
| `--nas-port-type wireless\|ethernet\|virtual` | How the probe presents itself, so server policies match (default `wireless`). |
| `--server-name NAME` | Expected server-certificate name (TLS SNI). |
| `--nas-id NAME` | NAS-Identifier to send (default `authhound-probe`). |
| `--timeout DURATION` | Per-request timeout (default `5s`). |
| `--json` | Machine-readable output for scripts / RMM ([schema](docs/json-schema.md)). |
| `--strict` | Exit non-zero on **warnings** too (e.g. a soon-to-expire cert), for scheduled monitoring. |
| `--no-color` | Force plain output. Colour is auto-detected otherwise — see [Colour](#colour-and-windows-terminals). |

### Where credentials come from

This tool is meant to run on shared jump boxes, so it never *requires* a secret or
password on the command line — where it would be saved to `~/.bash_history` and
shown to any other user on the host by `ps -ef`. The shared secret and each auth
password can come from any of these, checked in this order (**first match wins**):

| Source | Shared secret | Password |
|---|---|---|
| Explicit flag file | `--secret-file FILE` | `--password-file FILE` |
| Standard input | `--secret-stdin` | *(pipe the secret; give the password another way)* |
| Inline on the command line | `--secret VALUE` | `--pap user:pass` (and `--peap`, `--ttls`) |
| Environment variable | `AUTHHOUND_SECRET` | `AUTHHOUND_PASSWORD` |
| Interactive prompt (no echo) | when stdin is a terminal and no source above is set | give `--pap/--peap/--ttls` as just `user` |

Notes:

- **`--secret`, `--secret-file`, and `--secret-stdin` are mutually exclusive** —
  giving more than one is an error, so there's no silent surprise about which won.
- **File sources must not be world-readable** on Linux/macOS: the probe refuses a
  secret/password file that group or others can read and tells you to `chmod 600`
  it. Files trim exactly one trailing newline, so `printf 'secret\n' > f` is fine.
- **Environment variables are convenient but not private from the same user.**
  Another process running as *you* can read `/proc/<pid>/environ`. For untrusted
  multi-user boxes, prefer a `chmod 600` file or the interactive prompt.
- **Standard input**, for pipelines that already hold the secret in a variable:

  ```console
  $ printf '%s' "$SECRET" | authhound-probe radius test --server radius.corp.com --secret-stdin --peap alice
  ```

  (Piping the secret into stdin means there's no terminal left to prompt on, so
  supply the password via `AUTHHOUND_PASSWORD` or `--password-file` in that case.)
- **The inline `--secret VALUE` and `--pap user:pass` forms still work** for a
  quick lab test, but on a terminal they print a one-line warning reminding you
  they leak into history and `ps`. Credential values are never echoed back, never
  written to `--json` or logs, and never appear in an error message.

### EAP-TLS: preparing a client certificate

EAP-TLS logs in with a **certificate instead of a password**, so the probe needs
a client cert + key in **PEM** format. You don't need to make anything new — reuse
what your devices already use, or issue one dedicated test cert:

**Already have a `.pfx` / `.p12`?** (a common Windows / MDM export) Convert it —
the export password is what you set when exporting:

```console
$ openssl pkcs12 -in device.p12 -clcerts -nokeys -out client.pem   # the certificate
$ openssl pkcs12 -in device.p12 -nocerts -nodes  -out client.key   # the private key
```

**Issuing a dedicated test cert?** Have your CA sign one for a throwaway identity
(e.g. `CN=authhound-probe`) the same way it signs device/user certs, and export it
as PEM. It must be a **client-authentication** cert whose chain is trusted by the
RADIUS server for EAP-TLS — that's the one requirement.

The key is read from disk only to complete the TLS handshake; it is never
transmitted or logged. If the cert is untrusted, expired, or rejected by policy,
the probe says exactly which — so you know whether to fix the cert, the CA trust,
or the server's authorization rules.

## Install

**Binary** (Linux, macOS, Windows — single static file, no runtime):

```console
$ curl -sSL https://github.com/authhound/probe/releases/latest/download/authhound-probe_linux_amd64.tar.gz | tar xz
$ ./authhound-probe radius test --server ... --secret ...
```

**Windows** — PowerShell (downloads the latest release zip and unpacks it to the
current directory):

```powershell
Invoke-WebRequest -Uri https://github.com/authhound/probe/releases/latest/download/authhound-probe_windows_amd64.zip -OutFile authhound-probe.zip
Expand-Archive -Path authhound-probe.zip -DestinationPath authhound-probe -Force
.\authhound-probe\authhound-probe.exe version
```

(Use `authhound-probe_windows_arm64.zip` on Arm. To run `authhound-probe` from
any directory, move the `.exe` somewhere on your `PATH` — e.g.
`C:\Windows\System32` for all users, or a folder you add to your user `Path`.)

Or via a package manager — see [`packaging/`](packaging/) for the manifests and
maintainer notes:

```powershell
# Scoop (from the AuthHound bucket)
scoop bucket add authhound https://github.com/authhound/scoop-bucket
scoop install authhound-probe

# winget
winget install authhound.probe
```

**Go:**

```console
$ go install github.com/authhound/probe/cmd/authhound-probe@latest
```

**Docker** (multi-arch: amd64 + arm64, distroless base):

```console
$ docker run --rm ghcr.io/authhound/probe radius test --server radius.corp.com --secret '••••'
```

Every release also ships `authhound-probe_linux_arm64.tar.gz` and macOS/Windows
archives — swap `linux_amd64` in the curl above for your platform
(`linux_arm64` for a Raspberry Pi, `darwin_arm64` for Apple Silicon,
`windows_amd64.zip` for Windows).

## Verify your download

Every release artifact is checksummed and **keyless-signed with [Sigstore](https://www.sigstore.dev/) cosign** — no long-lived signing key exists; the signature is bound to the GitHub Actions release workflow via a short-lived OIDC certificate, and logged in the public [Rekor](https://docs.sigstore.dev/logging/overview/) transparency log. You can prove an artifact was built by this repo's tagged release pipeline and was not tampered with:

```console
# 1. Download the archive, the checksums file, and its cosign signature + certificate.
$ base=https://github.com/authhound/probe/releases/latest/download
$ curl -sSLO $base/authhound-probe_linux_amd64.tar.gz
$ curl -sSLO $base/checksums.txt
$ curl -sSLO $base/checksums.txt.sig
$ curl -sSLO $base/checksums.txt.pem

# 2. Verify checksums.txt was signed by our release workflow (fails on any mismatch).
$ cosign verify-blob \
    --certificate checksums.txt.pem \
    --signature   checksums.txt.sig \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    --certificate-identity-regexp '^https://github.com/authhound/probe/\.github/workflows/release\.yml@refs/tags/v.*$' \
    checksums.txt
# -> Verified OK

# 3. checksums.txt is now trusted — verify the archive's hash against it.
$ sha256sum --ignore-missing -c checksums.txt
# -> authhound-probe_linux_amd64.tar.gz: OK
```

The `--certificate-identity-regexp` pins **who** signed it (the `release.yml` workflow in `authhound/probe`, running on a `v*` tag); the `--certificate-oidc-issuer` pins **how** they authenticated (GitHub's OIDC provider). Both must match or verification fails — a signature alone is not enough. The container image is signed the same way; verify it with:

```console
$ cosign verify ghcr.io/authhound/probe:latest \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    --certificate-identity-regexp '^https://github.com/authhound/probe/\.github/workflows/release\.yml@refs/tags/v.*$'
```

> **No `sha256sum` / `cosign` on Windows?** `cosign` ships as a single static `.exe` ([releases](https://github.com/sigstore/cosign/releases)); for the hash alone, `certutil -hashfile authhound-probe_windows_amd64.zip SHA256` prints a digest you can compare by eye against `checksums.txt`.

## Where to run it

The probe's whole value is that it tests from the **same place your clients live**. Common homes:

- **A container on a box you already run** — a utility Linux VM, a hypervisor host, or a Synology/QNAP NAS. `docker run` and you're done.
- **A tiny VM** (1 vCPU / 512 MB) on your existing Proxmox / ESXi / Hyper-V cluster, on the client VLAN.
- **A systemd service** on the jump box that already runs your monitoring — or a Windows Scheduled Task on an NPS-adjacent server.
- **A Raspberry Pi** at a branch site — a genuinely good way to probe a remote location.

> **Placement matters.** A probe on the *server* VLAN may not cross the same firewall path your *clients* do — and that path is exactly where the invisible failures hide. Put the probe where the users are.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed. **Warnings are allowed** unless `--strict`. |
| `1` | At least one check **failed** — or, under `--strict`, at least one **warning**. |
| `2` | Usage error (bad flags, missing `--server`). No JSON is emitted in this case. |

This `0`/`1`/`2` contract is stable — RMM scripts and Task Scheduler can rely on it. By default a **warning** (e.g. a certificate expiring soon) does not change the exit code — only a hard failure does. Add `--strict` to make warnings exit `1` too, so a scheduled monitor pages on "still working, but about to break," not just on outright breakage — a cert about to lapse is exactly what an RMM job should alarm on.

Pair with `--json` for monitoring scripts and RMM integrations: the same result is machine-readable, with per-status counts (`.summary.fail`, `.summary.warn`, always present even when zero) and per-check status (`.results[].status`). The full document is versioned and documented in **[docs/json-schema.md](docs/json-schema.md)** — the top-level `schema_version` lets you pin the shape you coded against.

## Running as a Windows Scheduled Task

The probe is a single `.exe` with no runtime, so it drops straight into Task Scheduler on an NPS-adjacent box. Run it non-interactively — secret and password from the environment (or a `chmod`-equivalent ACL'd file), `--json` for a machine-readable log, and `--strict` so a soon-to-expire cert trips the task's result too:

```powershell
# One-time: create a task that probes NPS every 15 minutes and logs JSON.
# Store the secret/password as task-level env or a locked-down file — never on
# the command line (it would be visible in the task definition).
$action = New-ScheduledTaskAction `
  -Execute 'C:\Tools\authhound-probe.exe' `
  -Argument 'radius test --server nps.corp.local --peap svc-radius-probe --json --strict' `
  -WorkingDirectory 'C:\Tools'
$trigger  = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'AuthHound RADIUS probe' -Action $action -Trigger $trigger -Principal $principal
```

Or the classic one-liner with `schtasks`, redirecting output to a rolling log:

```powershell
schtasks /Create /TN "AuthHound RADIUS probe" /SC MINUTE /MO 15 /RU SYSTEM /RL HIGHEST /TR ^
  "cmd /c C:\Tools\authhound-probe.exe radius test --server nps.corp.local --peap svc-radius-probe --json --strict >> C:\Tools\probe.log 2>&1"
```

Supply credentials via the environment for the task's account (`AUTHHOUND_SECRET`, `AUTHHOUND_PASSWORD`) or `--secret-file`/`--password-file` pointing at a file only that account can read — see [Where credentials come from](#where-credentials-come-from). Because the probe exits `1` on failure (or on a warning under `--strict`), Task Scheduler's **Last Run Result** reflects health directly: `0x0` healthy, `0x1` something needs attention. Point your existing task-result monitoring at that, or tail `probe.log`.

## Colour and Windows terminals

Output is colourised only when it's going to a real terminal that can render it, so logs and pipes stay clean:

- **Piped or redirected** (`> out.txt`, `| findstr`, `--json`): colour is off automatically — no escape codes end up in your files.
- **Windows Terminal, and modern conhost / PowerShell 5.1 and 7+** (Windows 10 1511+ / Server 2016+): the probe enables virtual-terminal processing itself, so colours render with no setup.
- **Legacy conhost** that can't do ANSI: the probe detects this and prints plain `PASS`/`FAIL` words instead of raw escape codes.
- **`--no-color`** forces plain output everywhere, and the [`NO_COLOR`](https://no-color.org) environment variable is honoured if set.

## Safety

Built to be safe to run against production, and to pass an enterprise security review:

- **Read-only.** Sends Access-Requests and reads the replies — it never changes anything on the server, and never captures packets.
- **Credentials stay local, and off the command line.** The shared secret and any password are used only to build the RADIUS packets. They are never written to output, `--json`, logs, or error messages, and nothing is ever sent anywhere (there is no telemetry). So they don't leak into shell history or `ps` on a shared box, they're read from a file (`--secret-file` / `--password-file`, refused if world-readable), an environment variable, standard input, or a no-echo prompt — see [Where credentials come from](#where-credentials-come-from). The plain `--secret`/`user:pass` forms still work but warn on a terminal.
- **Never completes a second factor** and never proxies authentication.
- **Hard-coded rate ceiling** the config cannot override — it cannot be turned into a load generator.
- **Verifiable releases.** Binaries and images are checksummed and keyless-signed (Sigstore cosign) by the tagged release workflow, and every release ships an SBOM per archive — [verify them](#verify-your-download) before you trust them on a shared jump box.
- **Minimal, scanned supply chain.** One direct dependency (`golang.org/x/term`), `govulncheck` on every PR plus a daily scheduled scan, Dependabot with mandatory human review, and SHA-pinned CI actions — the full posture is documented in [SECURITY.md](SECURITY.md).
- **Open source (Apache-2.0).** Read it — or run `./test/freeradius-smoke.sh` to watch it work against a throwaway FreeRADIUS in Docker.

## From spot-check to continuous monitoring

`authhound-probe radius test` answers "is it working **right now**?" But the failures that hurt most are the *intermittent* ones — the 3 a.m. blip, the cert that expires next Tuesday, the drift that only shows up under load. You can't catch those by running a command when you happen to suspect trouble.

That's what the paid tier is for. The **same binary**, pointed at the AuthHound service:

```console
$ authhound-probe connect <token>
```

...runs these checks on a schedule from every site, remembers the history, alerts you when something changes (a cert nearing expiry, latency creeping up, a new failure signature), and correlates across your whole fleet — so you hear about it before your users do. Join the waitlist at **[authhound.com](https://authhound.com)**.

## Testing

```console
$ go test ./...                   # unit tests
$ ./test/freeradius-smoke.sh      # full end-to-end vs a real FreeRADIUS in Docker
```

There's also a `docker compose` lab (classic RADIUS/UDP + RadSec/TLS) for poking
at the probe by hand, and instructions for testing against your own server. See
[test/README.md](test/README.md) — including how to prepare a client certificate
for the EAP-TLS and RadSec tests.

## Contributing

Interop reports are especially valuable: run the probe against your RADIUS — a specific NPS setup, a hosted RADIUS service, a particular FreeRADIUS version — and open an issue with what worked or didn't. It's how the tested-server list grows. Bug reports and PRs welcome.

## See also

Already have a log to read? Paste FreeRADIUS debug output or a Windows NPS event into the free [RADIUS log analyzer](https://authhound.com/analyzer) for a plain-English diagnosis.

## License

[Apache-2.0](LICENSE)
