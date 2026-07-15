# FAQ

Answers to questions that come up in the field. Sections marked as
placeholders get filled as forum/issue feedback arrives — if your question
isn't here, [open an issue](https://github.com/authhound/probe/issues).

<!--
Maintainers: harvest Q&As from forum threads / issues into the matching
section below. Keep the format:

### The question, phrased the way the asker phrased it
The answer, 2–6 sentences, linking README/SECURITY sections instead of
duplicating them. Add the source thread as an HTML comment for provenance.
-->

## Getting started / timeouts

### Every check times out — is the server down?

Probably not. A RADIUS server **silently drops** requests from IPs it doesn't
know, so an unregistered probe looks identical to a dead server. Register the
probe's IP and secret as a RADIUS client first — see
[Step 0 in the README](../README.md#step-0--register-the-probe-on-your-server-one-time).
On a first-run timeout the probe prints the exact registration snippet with
your detected source IP filled in.

### The probe passes but my users still can't connect. How?

The probe ran from where *it* sits. If that's not the same VLAN/firewall path
your clients use, it didn't test their path — placement matters (see
[Where to run it](../README.md#where-to-run-it)). Also compare `--nas-port-type`
with what your real NAS sends: policies frequently branch on it.

<!-- PLACEHOLDER: more getting-started Q&As from forum feedback -->

## Windows / NPS

### Does it work against Windows NPS?

Yes — NPS is a first-class target: PEAP-MSCHAPv2 and machine (`host/…`)
authentication, `--nas-port-type ethernet` to hit wired policies, and a
PowerShell one-liner for client registration. See
[Machine auth (NPS)](../README.md#machine-auth-nps) and
[Running as a Windows Scheduled Task](../README.md#running-as-a-windows-scheduled-task).

<!-- PLACEHOLDER: NPS-specific Q&As (event IDs, CRP vs Network Policy, …) -->

## Credentials & security

### Is it safe to run against production?

It's designed to be: read-only, rate-capped by a ceiling no flag can raise,
no packet capture, no state, no telemetry. The one-page threat model is
[SECURITY.md](../SECURITY.md).

### Why does the probe warn that name validation was skipped?

Because you didn't pass `--server-name`, so the probe couldn't check the
certificate is one your clients would accept — and it refuses to print
"valid" for a name it never checked. Add `--server-name radius.corp.com`
(whatever name your client profiles trust) to turn the warning into a real
verdict either way.

<!-- PLACEHOLDER: credential-handling Q&As -->

## EAP methods & certificates

### Which EAP methods are supported?

PEAP-MSCHAPv2, EAP-TTLS (inner PAP), and EAP-TLS — plus non-EAP PAP. For
methods beyond that (EAP-FAST, EAP-PWD, SIM/AKA…), `eapol_test` is the right
tool; see the [comparison](COMPARISON.md).

<!-- PLACEHOLDER: method/cert Q&As (chain building, .pfx conversion edge cases, …) -->

## Scripting / RMM / monitoring

### How do I alarm on the output?

Exit codes are a stable contract: `0` pass, `1` any FAIL (or any WARN under
`--strict`), `2` usage error. Pair with `--json` — the schema is versioned and
documented in [json-schema.md](json-schema.md).

### Can it run on a schedule / as a daemon?

There is deliberately no daemon or watch mode (see SECURITY.md). Use your
scheduler — cron, systemd timers, Task Scheduler — to invoke one-shot runs;
recipes are in the README. Continuous scheduled monitoring with history and
alerting is what the paid [AuthHound](https://authhound.com) service does.

<!-- PLACEHOLDER: RMM/monitoring Q&As from integrator feedback -->
