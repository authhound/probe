# authhound-probe

**Test any RADIUS server — FreeRADIUS, Windows NPS, or cloud — from inside your network.**

[![CI](https://github.com/authhound/probe/actions/workflows/ci.yml/badge.svg)](https://github.com/authhound/probe/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/authhound/probe)](https://goreportcard.com/report/github.com/authhound/probe)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A RADIUS server only logs the requests that *reach* it. A huge class of 802.1X failures happens before that — a firewall eating UDP, a NAT rewriting the source, the wrong shared secret on one switch, an expired server certificate, EAP fragments dropped in the path. The dashboard (or your `radiusd -X` log) says "all good"; your users say "Wi-Fi is broken"; the ticket ping-pongs for days.

`authhound-probe` runs a **real** authentication against your RADIUS server from **inside your network**, acting as a NAS (switch/AP) would, and tells you in plain English which hop is broken. Works with self-hosted **FreeRADIUS** and **Windows NPS**, and with hosted/cloud RADIUS services. No account, no signup, no telemetry — everything you type stays on the host you run it on.

```console
$ authhound-probe radius test --server radius.corp.com --secret '••••' --peap 'alice:••••'

Testing RADIUS server radius.corp.com:1812 (as NAS "authhound-probe")

PASS  RADIUS server answered in 23ms
PASS  Shared secret is correct (reply signature verified)
PASS  PEAP-MSCHAPv2 authentication succeeded for alice
PASS  Server certificate valid for 214 more days, chain looks complete (TLS 1.2)

Verdict: 4 passed, 0 failed, 0 warnings
```

Like `eapol_test` or `radtest`, but the output is readable — one command, no `wpa_supplicant` config file. Add `--json` for scripting, `--nas-port-type ethernet|wireless|virtual` to match how your real NAS presents itself, and `--server-name` to set the expected certificate name.

## What it checks (v1)

| Check | What it proves |
|---|---|
| **Reachability** | The server answers on UDP/1812 — and how fast. A timeout means unreachable, not listening, **or the probe isn't whitelisted / the secret is wrong** (servers silently drop unverifiable requests). |
| **Shared secret** | Cryptographically verifies the server's reply signature. A pass *proves* the secret matches — no more guessing whether "everyone's getting rejected" is a secret problem or something else. |
| **PAP authentication** | A real login with credentials you supply → Accept or Reject, decoded. Also detects an **MFA/second-factor challenge** and reports it (the probe does not complete push/OTP — see below). |
| **PEAP-MSCHAPv2** | The method most enterprise 802.1X networks actually run: a real inner authentication inside the PEAP TLS tunnel. Reports success — and verifies the server's own MSCHAPv2 proof (mutual auth) — or the decoded reason on rejection. The "can my users actually log in?" test. |
| **Server certificate** | Establishes the PEAP/TLS tunnel over RADIUS, captures the server's certificate, and flags **expiry**, an incomplete intermediate chain, and the negotiated TLS version. The "Wi-Fi died overnight" outage, caught early. |

### A note on MFA / two-factor

If the server issues an MFA challenge after valid primary credentials, the probe reports that boundary — *"primary auth healthy, second factor required"* — but does **not** approve a push or submit an OTP. Completing a second factor from an unattended probe would mean storing a live MFA secret, which this tool refuses to do. For monitoring, point it at a **test account exempt from MFA** so the primary RADIUS path is validated cleanly.

## Usage

Reachability, shared-secret, and server-certificate checks run automatically — no credentials needed:

```console
$ authhound-probe radius test --server radius.corp.com --secret '••••'
```

Add an authentication test with the method your network actually uses:

```console
# PEAP-MSCHAPv2 — what most enterprise Wi-Fi / 802.1X runs
$ authhound-probe radius test --server radius.corp.com --secret '••••' --peap 'user:password'

# PAP — VPNs, simple setups, or as a backend baseline
$ authhound-probe radius test --server radius.corp.com --secret '••••' --pap 'user:password'

# both at once
$ authhound-probe radius test --server radius.corp.com --secret '••••' \
    --pap 'user:password' --peap 'user:password'
```

EAP-TLS (client-certificate) authentication is in progress — the TLS engine that already powers PEAP-MSCHAPv2 and certificate capture is the hard part, and it's done.

**All flags:**

| Flag | Purpose |
|---|---|
| `--server HOST[:port]` | RADIUS server (default port 1812). **Required.** |
| `--secret SECRET` | Shared secret for this probe on the server. **Required.** |
| `--pap user:pass` | Run a PAP authentication test. |
| `--peap user:pass` | Run a PEAP-MSCHAPv2 authentication test. |
| `--nas-port-type wireless\|ethernet\|virtual` | How the probe presents itself, so server policies match (default `wireless`). |
| `--server-name NAME` | Expected server-certificate name (TLS SNI). |
| `--nas-id NAME` | NAS-Identifier to send (default `authhound-probe`). |
| `--timeout DURATION` | Per-request timeout (default `5s`). |
| `--json` | Machine-readable output for scripts / RMM. |
| `--no-color` | Disable ANSI colour. |

## Install

**Binary** (Linux, macOS, Windows — single static file, no runtime):

```console
$ curl -sSL https://github.com/authhound/probe/releases/latest/download/authhound-probe_linux_amd64.tar.gz | tar xz
$ ./authhound-probe radius test --server ... --secret ...
```

**Go:**

```console
$ go install github.com/authhound/probe/cmd/authhound-probe@latest
```

**Docker:**

```console
$ docker run --rm authhound/probe radius test --server radius.corp.com --secret '••••'
```

## Where to run it

The probe's whole value is that it tests from the **same place your clients live**. Common homes:

- **A container on a box you already run** — a utility Linux VM, a hypervisor host, or a Synology/QNAP NAS. `docker run` and you're done.
- **A tiny VM** (1 vCPU / 512 MB) on your existing Proxmox / ESXi / Hyper-V cluster, on the client VLAN.
- **A systemd service** on the jump box that already runs your monitoring — or a Windows Scheduled Task on an NPS-adjacent server.
- **A Raspberry Pi** at a branch site — a genuinely good way to probe a remote location.

> **Placement matters.** A probe on the *server* VLAN may not cross the same firewall path your *clients* do — and that path is exactly where the invisible failures hide. Put the probe where the users are.

### One-time server setup

Because the probe acts as a NAS, your RADIUS server must know it as a client — add its IP and a shared secret:

**FreeRADIUS** (`clients.conf`):

```
client authhound-probe {
    ipaddr = 10.20.0.50      # the probe's IP
    secret = <shared secret>
}
```

**Windows NPS:** NPS console → RADIUS Clients → New → the probe's IP + a shared secret.

Use a dedicated secret and a least-privilege test account — never a real admin credential.

## Exit codes

`0` all checks passed · `1` at least one check failed · `2` usage error. Pair with `--json` for monitoring scripts and RMM integrations.

## Safety

Built to be safe to run against production, and to pass an enterprise security review:

- **Read-only.** Sends Access-Requests and reads the replies — it never changes anything on the server, and never captures packets.
- **Credentials stay local.** Secrets and passwords are used only to build the RADIUS packets. They are never written to output or logs, and nothing is ever sent anywhere (there is no telemetry).
- **Never completes a second factor** and never proxies authentication.
- **Hard-coded rate ceiling** the config cannot override — it cannot be turned into a load generator.
- **Open source (Apache-2.0).** Read it — or run `./test/freeradius-smoke.sh` to watch it work against a throwaway FreeRADIUS in Docker.

## From spot-check to continuous monitoring

`authhound-probe radius test` answers "is it working **right now**?" But the failures that hurt most are the *intermittent* ones — the 3 a.m. blip, the cert that expires next Tuesday, the drift that only shows up under load. You can't catch those by running a command when you happen to suspect trouble.

That's what the paid tier is for. The **same binary**, pointed at the AuthHound service:

```console
$ authhound-probe connect <token>
```

...runs these checks on a schedule from every site, remembers the history, alerts you when something changes (a cert nearing expiry, latency creeping up, a new failure signature), and correlates across your whole fleet — so you hear about it before your users do. Join the waitlist at **[authhound.com](https://authhound.com)**.

## Contributing

Interop reports are especially valuable: run the probe against your RADIUS — a specific NPS setup, a hosted RADIUS service, a particular FreeRADIUS version — and open an issue with what worked or didn't. It's how the tested-server list grows. Bug reports and PRs welcome.

## See also

Already have a log to read? Paste FreeRADIUS debug output or a Windows NPS event into the free [RADIUS log analyzer](https://authhound.com/analyzer) for a plain-English diagnosis.

## License

[Apache-2.0](LICENSE)
