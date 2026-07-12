# authhound-probe

**Test your RADIUS server from where your users actually are.**

A cloud RADIUS vendor can only see requests that *reach* it. A huge class of 802.1X failures happens before that — a firewall eating UDP, a NAT rewriting the source, the wrong shared secret on one switch, an expired server certificate, EAP fragments dropped in the path. The vendor's logs say "all good"; your users say "Wi-Fi is broken"; the ticket ping-pongs for days.

`authhound-probe` runs a **real** authentication against your RADIUS server from **inside your network**, acting as a NAS (switch/AP) would, and tells you in plain English which hop is broken. No account, no signup, no telemetry — everything you type stays on the host you run it on.

```console
$ authhound-probe test --server radius.corp.com --secret '••••' --pap 'alice:••••'

Testing RADIUS server radius.corp.com:1812 (as NAS "authhound-probe")

PASS  RADIUS server answered in 23ms
PASS  Shared secret is correct (reply signature verified)
PASS  PAP authentication accepted for alice
PASS  Server certificate valid for 214 more days, chain looks complete (TLS 1.2)

Verdict: 4 passed, 0 failed, 0 warnings
```

Add `--json` for scripting, `--nas-port-type ethernet|wireless|virtual` to match
how your real NAS presents itself, and `--server-name` to set the expected cert name.

## What it checks (v1)

| Check | What it proves |
|---|---|
| **Reachability** | The server answers on UDP/1812 — and how fast. A timeout means unreachable, not listening, **or the probe isn't whitelisted / the secret is wrong** (servers silently drop unverifiable requests). |
| **Shared secret** | Cryptographically verifies the server's reply signature. A pass *proves* the secret matches — no more guessing whether "everyone's getting rejected" is a secret problem or something else. |
| **PAP authentication** | A real login with credentials you supply → Accept or Reject, decoded. Also detects an **MFA/second-factor challenge** and reports it (the probe does not complete push/OTP — see below). |
| **Server certificate** | Establishes the PEAP/TLS tunnel over RADIUS, captures the server's certificate, and flags **expiry**, an incomplete intermediate chain, and the negotiated TLS version. The "Wi-Fi died overnight" outage, caught early. |

Every check is **read-only**. The probe never changes anything on your server, never captures packets, never completes a second factor, and rate-limits itself with a hard-coded ceiling that no flag can override — it cannot be turned into a load generator. PEAP-MSCHAPv2 and EAP-TLS authentication tests are in progress.

### A note on MFA (JumpCloud, Duo, Okta)

If the server issues an MFA challenge after valid primary credentials, the probe reports that boundary — *"primary auth healthy, second factor required"* — but does **not** approve a push or submit an OTP. Completing a second factor from an unattended probe would mean storing a live MFA secret, which this tool refuses to do. For monitoring, point it at a **test account exempt from MFA** so the primary RADIUS path is validated cleanly.

## Install

**Binary** (Linux, macOS, Windows — single static file, no runtime):

```console
$ curl -sSL https://github.com/authhound/probe/releases/latest/download/authhound-probe_linux_amd64.tar.gz | tar xz
$ ./authhound-probe test --server ... --secret ...
```

**Go:**

```console
$ go install github.com/authhound/probe/cmd/authhound-probe@latest
```

**Docker:**

```console
$ docker run --rm authhound/probe test --server radius.corp.com --secret '••••'
```

## Where to run it

The probe's whole value is that it tests from the **same place your clients live**. Common homes:

- **A container on a box you already run** — a utility Linux VM, a hypervisor host, or a Synology/QNAP NAS. `docker run` and you're done.
- **A tiny VM** (1 vCPU / 512 MB) on your existing Proxmox / ESXi / Hy-V cluster, on the client VLAN.
- **A systemd service** on the jump box that already runs your monitoring.
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

## From spot-check to continuous monitoring

`authhound-probe test` answers "is it working **right now**?" But the failures that hurt most are the *intermittent* ones — the 3 a.m. blip, the cert that expires next Tuesday, the drift that only shows up under load. You can't catch those by running a command when you happen to suspect trouble.

That's what the paid tier is for. The **same binary**, pointed at the AuthHound service:

```console
$ authhound-probe connect <token>
```

...runs these checks on a schedule from every site, remembers the history, alerts you when something changes (a cert nearing expiry, latency creeping up, a new failure signature), and correlates across your whole fleet — so you hear about it before your users do. Join the waitlist at **[authhound.com](https://authhound.com)**.

## Privacy

Standalone mode sends nothing anywhere. Shared secrets and credentials are used to build the RADIUS packets and are never written to output or logs. The diagnostic results contain only pass/fail, timings, and (later) certificate metadata — never secrets.

## License

[Apache-2.0](LICENSE)
