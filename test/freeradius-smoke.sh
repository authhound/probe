#!/usr/bin/env bash
# Integration smoke test: run the probe against a real FreeRADIUS server in
# Docker. Verifies the wire format against the genuine article (the unit tests
# use an in-process fake server; this proves interop with real FreeRADIUS).
#
#   ./test/freeradius-smoke.sh
#
# Requires: docker, go. Uses --network host so the container sees the probe's
# requests from 127.0.0.1 (matching FreeRADIUS's default `localhost` client,
# secret `testing123`). Linux only (host networking).
set -euo pipefail
cd "$(dirname "$0")/.."

SECRET="testing123"
work="$(mktemp -d)"
trap 'rm -rf "$work"; docker rm -f ah-freeradius ah-freeradius-nc ah-freeradius-flaky ah-netem ah-unhardened ah-secondary >/dev/null 2>&1 || true' EXIT

# One test user for the PAP check, plus a machine identity for the NPS-style
# machine-auth check. This file replaces the default authorize file; a single
# Cleartext-Password line is all the pap module needs. FreeRADIUS treats the
# "host/PC-01.corp.local" identity like any other username — exactly the path a
# Windows computer account takes through PEAP-MSCHAPv2.
cat > "$work/authorize" <<'EOF'
alice Cleartext-Password := "pw"
      Fall-Through = Yes
host/PC-01.corp.local Cleartext-Password := "machinepw"
DEFAULT NAS-Port-Type == Ethernet
        Tunnel-Type := VLAN,
        Tunnel-Medium-Type := IEEE-802,
        Tunnel-Private-Group-ID := "30",
        Fall-Through = Yes
DEFAULT NAS-Port-Type == Wireless-802.11
        Tunnel-Type := VLAN,
        Tunnel-Medium-Type := IEEE-802,
        Tunnel-Private-Group-ID := "20"
EOF

# A minimal RadSec (RADIUS/TLS) listener on TCP/2083 so we can test 'radsec test'
# against a real server. Mutual TLS: the client must present a cert signed by the
# server's CA. (TLS sockets need threading, so we run radiusd -fxx, not -X.)
cat > "$work/radsec" <<'EOF'
listen {
	type = auth
	ipaddr = *
	port = 2083
	proto = tcp
	clients = radsec
	virtual_server = default
	tls {
		private_key_password = whatever
		private_key_file = ${certdir}/server.pem
		certificate_file = ${certdir}/server.pem
		ca_file = ${cadir}/ca.pem
		fragment_size = 8192
		require_client_cert = yes
	}
}

# A second RadSec listener on 2084 that presents a deliberately short-lived
# server certificate, so 'radsec test' produces a cert-expiry WARN. This is the
# fixture for the --strict exit-code flip: a WARN (not a FAIL) that scripts must
# be able to alarm on. Same clients/CA as above; only the server cert differs.
listen {
	type = auth
	ipaddr = *
	port = 2084
	proto = tcp
	clients = radsec
	virtual_server = default
	tls {
		private_key_file = ${certdir}/server-short.pem
		certificate_file = ${certdir}/server-short.pem
		ca_file = ${cadir}/ca.pem
		fragment_size = 8192
		require_client_cert = yes
	}
}
clients radsec {
	client 127.0.0.1 {
		ipaddr = 127.0.0.1
		proto = tls
		secret = radsec
	}
}
EOF

# The short-lived (10-day) self-signed server cert for the 2084 listener. Cert +
# unencrypted key concatenated into one PEM (what FreeRADIUS's *_file settings
# expect). 10 days is inside the probe's 21-day cert-expiry WARN window, and a
# lone self-signed leaf is NOT treated as an incomplete chain, so the only
# non-PASS result is the expiry WARN — a clean fixture for the --strict flip.
short_dir="$work/short"; mkdir -p "$short_dir"
# The SAN makes this cert also the fixture for --server-name validation: a
# matching name, a mismatching one, and the flag omitted are all deterministic.
openssl req -x509 -newkey rsa:2048 -keyout "$short_dir/key.pem" -out "$short_dir/cert.pem" \
  -days 10 -nodes -subj "/CN=radsec-short.corp.local" \
  -addext "subjectAltName = DNS:radsec-short.corp.local" >/dev/null 2>&1
cat "$short_dir/cert.pem" "$short_dir/key.pem" > "$work/server-short.pem"

echo "== starting FreeRADIUS (debug, threaded for RadSec) =="
# Enable copy_request_to_tunnel + use_tunneled_reply so that, for PEAP/TTLS, the
# request's NAS-Port-Type reaches the inner tunnel AND the inner reply's VLAN is
# copied out to the outer Access-Accept — exactly how real 802.1X VLAN assignment
# is configured, and what lets the probe read the VLAN over EAP.
docker run -d --rm --name ah-freeradius --network host \
  -v "$work/authorize:/etc/raddb/mods-config/files/authorize:ro" \
  -v "$work/radsec:/etc/raddb/sites-enabled/radsec:ro" \
  -v "$work/server-short.pem:/etc/raddb/certs/server-short.pem:ro" \
  --entrypoint sh freeradius/freeradius-server:latest -c \
  "sed -i -E 's/(use_tunneled_reply|copy_request_to_tunnel) = no/\1 = yes/' /etc/raddb/mods-available/eap && exec freeradius -fxx -l stdout" >/dev/null

# Wait for it to be listening.
for i in $(seq 1 30); do
  if docker logs ah-freeradius 2>&1 | grep -q "Ready to process requests"; then break; fi
  sleep 0.5
done

echo "== building probe =="
go build -o "$work/authhound-probe" ./cmd/authhound-probe

# Extract FreeRADIUS's own test client cert (signed by its CA) for EAP-TLS, and
# convert the .p12 to PEM — the same step an admin does with a real cert export.
docker exec ah-freeradius cat /etc/raddb/certs/client.p12 > "$work/client.p12" 2>/dev/null || true
if [ -s "$work/client.p12" ]; then
  openssl pkcs12 -in "$work/client.p12" -clcerts -nokeys -out "$work/cert.pem" -passin pass:whatever -legacy 2>/dev/null || true
  openssl pkcs12 -in "$work/client.p12" -nocerts -nodes   -out "$work/key.pem"  -passin pass:whatever -legacy 2>/dev/null || true
fi
# A self-signed cert the server does not trust, for the negative EAP-TLS case.
openssl req -x509 -newkey rsa:2048 -keyout "$work/bad.key" -out "$work/bad.pem" \
  -days 1 -nodes -subj "/CN=untrusted-test" >/dev/null 2>&1 || true

echo
echo "== correct secret + PAP + PEAP-MSCHAPv2 + EAP-TTLS + EAP-TLS + MTU (expect PASS) =="
"$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" \
  --pap 'alice:pw' --peap 'alice:pw' --ttls 'alice:pw' \
  --client-cert "$work/cert.pem" --client-key "$work/key.pem" --mtu --no-color || true

echo
echo "== Status-Server (RFC 5997): a server that supports it answers (expect PASS) =="
# FreeRADIUS answers Status-Server by default: a liveness ping that consumes no
# auth attempt. The probe runs it first and reports PASS + supported=true.
set +e
ss_out="$("$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" --no-color)"
ss_json="$("$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" --json)"
set -e
echo "$ss_out" | grep -i "Status-Server"
echo "$ss_out" | grep -qi "answered Status-Server" || { echo "FAIL: Status-Server should PASS on a server that supports it"; exit 1; }
echo "$ss_json" | grep -q '"check": "status-server"' || { echo "FAIL: --json missing the status-server result"; exit 1; }
echo "$ss_json" | grep -q '"supported": "true"' || { echo "FAIL: --json should mark status-server supported=true"; exit 1; }
if echo "$ss_out$ss_json" | grep -q "$SECRET"; then echo "FAIL: secret leaked into Status-Server output"; exit 1; fi
echo "OK: Status-Server answered -> PASS, supported=true (no auth attempt consumed)"

echo
echo "== BlastRADIUS posture: hardened FreeRADIUS signs replies (expect PASS) =="
# The probe always includes a Message-Authenticator in its request; a patched
# (post-CVE-2024-3596) FreeRADIUS echoes one in its reply. The posture check
# observes that and PASSes. This is observation only — a normal exchange.
set +e
bp_hard="$("$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" --no-color)"
bp_hard_json="$("$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" --json)"
set -e
echo "$bp_hard" | grep -qi "signs its replies with Message-Authenticator" || { echo "FAIL: hardened server should PASS the BlastRADIUS posture check"; exit 1; }
echo "$bp_hard_json" | grep -q '"blastradius_posture": "signed"' || { echo "FAIL: --json should report blastradius_posture=signed"; exit 1; }
if echo "$bp_hard$bp_hard_json" | grep -q "$SECRET"; then echo "FAIL: secret leaked into BlastRADIUS output"; exit 1; fi
echo "OK: hardened FreeRADIUS signs replies -> BlastRADIUS posture PASS (signed)"

echo
echo "== BlastRADIUS posture: unhardened FreeRADIUS does NOT sign (expect WARN) =="
# FreeRADIUS 3.2.3 predates the CVE-2024-3596 reply-signing fix: it accepts our
# signed request but replies WITHOUT a Message-Authenticator — the exposed state
# most un-upgraded servers are still in, and the one config a knob can't undo on
# a patched build. Same lab server, older (unhardened) build, on a published
# bridge port so it doesn't clash with the host-net one. Permissive client entry
# (any source IP) because requests arrive via the Docker bridge gateway.
# Throwaway lab secret, never production.
cat > "$work/clients-unhardened" <<'EOF'
client lab {
	ipaddr = 0.0.0.0/0
	secret = testing123
}
EOF
docker run -d --rm --name ah-unhardened -p 127.0.0.1:11813:1812/udp \
  -v "$work/authorize:/etc/freeradius/mods-config/files/authorize:ro" \
  -v "$work/clients-unhardened:/etc/freeradius/clients.conf:ro" \
  freeradius/freeradius-server:3.2.3 -fxx -l stdout >/dev/null
for i in $(seq 1 30); do
  if docker logs ah-unhardened 2>&1 | grep -q "Ready to process requests"; then break; fi
  sleep 0.5
done
# The BlastRADIUS check must WARN. (The old 3.2.3 image also ships an expired
# bootstrap server cert, so the run as a whole FAILs on server-cert — unrelated
# to this posture; the WARN-doesn't-flip-exit semantics are covered by the RadSec
# cert-expiry --strict test below, so we only assert the posture result here.)
set +e
bp_warn="$("$work/authhound-probe" radius test --server 127.0.0.1:11813 --secret "$SECRET" --no-color)"
bp_warn_json="$("$work/authhound-probe" radius test --server 127.0.0.1:11813 --secret "$SECRET" --json)"
set -e
echo "$bp_warn" | grep -A6 -i "BlastRADIUS-exposed"
echo "$bp_warn" | grep -qi "replied WITHOUT Message-Authenticator" || { echo "FAIL: unhardened server should WARN on the BlastRADIUS posture check"; exit 1; }
echo "$bp_warn" | grep -q "require_message_authenticator" || { echo "FAIL: WARN hint should point at require_message_authenticator"; exit 1; }
echo "$bp_warn" | grep -q "radsec test" || { echo "FAIL: WARN hint should point at radsec as the durable fix"; exit 1; }
echo "$bp_warn_json" | grep -q '"blastradius_posture": "unsigned"' || { echo "FAIL: --json should report blastradius_posture=unsigned"; exit 1; }
if echo "$bp_warn$bp_warn_json" | grep -q "$SECRET"; then echo "FAIL: secret leaked into BlastRADIUS output"; exit 1; fi
docker rm -f ah-unhardened >/dev/null 2>&1 || true
echo "OK: unhardened FreeRADIUS omits reply Message-Authenticator -> BlastRADIUS posture WARN (unsigned)"

echo
echo "== machine auth: host/ identity via PEAP-MSCHAPv2 (NPS-style, expect PASS) =="
# A computer account authenticates with a "host/NAME.domain" identity and the
# machine-account password — no colon in the identity, so it parses cleanly.
"$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" \
  --nas-port-type ethernet --peap 'host/PC-01.corp.local:machinepw' --no-color || true

echo
echo "== policy assertion: VLAN in Access-Accept, match vs mismatch (--expect-vlan) =="
# alice is assigned a VLAN that depends on NAS-Port-Type: wireless -> 20,
# ethernet -> 30. This is the "auth succeeds into the WRONG VLAN" case the
# assertion is built to catch. Uses PAP for a deterministic single exchange.
set +e
vlan_ok="$("$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" \
  --pap 'alice:pw' --expect-vlan 20 --no-color)"; vlan_ok_rc=$?
vlan_bad="$("$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" \
  --pap 'alice:pw' --expect-vlan 30 --no-color)"; vlan_bad_rc=$?
vlan_eth="$("$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" \
  --nas-port-type ethernet --pap 'alice:pw' --expect-vlan 30 --no-color)"; vlan_eth_rc=$?
set -e
echo "$vlan_ok"
echo "$vlan_ok" | grep -q "Tunnel-Private-Group-ID = 20" || { echo "FAIL: VLAN 20 not surfaced"; exit 1; }
echo "$vlan_ok" | grep -q "assert VLAN=20: OK" || { echo "FAIL: matching VLAN assertion should pass"; exit 1; }
[ "$vlan_ok_rc" -eq 0 ] || { echo "FAIL: matching VLAN should exit 0, got $vlan_ok_rc"; exit 1; }
echo "$vlan_bad" | grep -q "MISMATCH (got 20)" || { echo "FAIL: expected a VLAN mismatch line"; exit 1; }
echo "$vlan_bad" | grep -qi "expected 30" || { echo "FAIL: mismatch guidance missing the expected value"; exit 1; }
echo "$vlan_bad" | grep -q "NAS-Port-Type" || { echo "FAIL: mismatch guidance should mention NAS-Port-Type"; exit 1; }
[ "$vlan_bad_rc" -eq 1 ] || { echo "FAIL: VLAN mismatch should exit 1, got $vlan_bad_rc"; exit 1; }
echo "$vlan_eth" | grep -q "assert VLAN=30: OK" || { echo "FAIL: ethernet should assign VLAN 30"; exit 1; }
[ "$vlan_eth_rc" -eq 0 ] || { echo "FAIL: ethernet VLAN 30 should exit 0, got $vlan_eth_rc"; exit 1; }
if echo "$vlan_ok$vlan_bad$vlan_eth" | grep -q "$SECRET"; then echo "FAIL: secret leaked into output"; exit 1; fi
echo "OK: VLAN surfaced; match passes, mismatch FAILs (exit 1), NAS-Port-Type flips the assignment"

echo
echo "== policy assertion over PEAP-MSCHAPv2 + --json authorization block =="
# Proves the probe drives the PEAP exchange all the way to the Access-Accept and
# reads its VLAN — the marquee 802.1X method, not just PAP.
pjson="$("$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" \
  --peap 'alice:pw' --expect-vlan 20 --json || true)"
echo "$pjson" | grep -q '"authorization"' || { echo "FAIL: --json missing authorization block"; exit 1; }
echo "$pjson" | grep -q '"Tunnel-Private-Group-ID"' || { echo "FAIL: --json missing the VLAN attribute"; exit 1; }
echo "$pjson" | grep -q '"pass": true' || { echo "FAIL: PEAP VLAN 20 assertion should pass in JSON"; exit 1; }
if echo "$pjson" | grep -q "$SECRET"; then echo "FAIL: secret leaked into JSON"; exit 1; fi
echo "OK: PEAP-MSCHAPv2 surfaced the Access-Accept VLAN and the assertion passed over JSON"

echo
echo "== same, but secret via AUTHHOUND_SECRET + password via --password-file (expect PASS) =="
# Exercises the credential paths that keep secrets off the command line: the
# shared secret from the environment and the password from a chmod-600 file.
printf '%s' "pw" > "$work/pw.txt"; chmod 600 "$work/pw.txt"
AUTHHOUND_SECRET="$SECRET" "$work/authhound-probe" radius test --server 127.0.0.1 \
  --pap 'alice' --password-file "$work/pw.txt" --no-color || true

echo
echo "== wrong secret (expect shared-secret FAIL or no verify) =="
"$work/authhound-probe" radius test --server 127.0.0.1 --secret "wrongsecret" --no-color || true

echo
echo "== valid secret, bad password + untrusted client cert (expect FAILs) =="
"$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" \
  --pap 'alice:nope' --peap 'alice:nope' \
  --client-cert "$work/bad.pem" --client-key "$work/bad.key" --no-color || true

echo
echo "== RadSec (RADIUS/TLS 2083) with client cert (expect TLS + RADIUS PASS) =="
"$work/authhound-probe" radsec test --server 127.0.0.1 \
  --client-cert "$work/cert.pem" --client-key "$work/key.pem" --no-color || true

echo
echo "== --strict flips exit code on a cert-expiry WARN (RadSec 2084, 10-day cert) =="
# The 2084 listener presents a 10-day server cert -> the probe WARNs (no FAIL).
# Without --strict that is exit 0 (warning is not breakage); with --strict it is
# exit 1 (a scheduled monitor must alarm on a soon-to-expire cert). This is the
# MSP/RMM machine contract the task hinges on.
# set +e around the runs so the expected nonzero exit under --strict doesn't trip
# the script's own `set -e` before we can read $?.
set +e
warn_out="$("$work/authhound-probe" radsec test --server 127.0.0.1:2084 \
  --client-cert "$work/cert.pem" --client-key "$work/key.pem" --no-color)"; warn_rc=$?
"$work/authhound-probe" radsec test --server 127.0.0.1:2084 \
  --client-cert "$work/cert.pem" --client-key "$work/key.pem" --no-color --strict >/dev/null; strict_rc=$?
set -e
echo "$warn_out"
echo "$warn_out" | grep -qi "certificate expires in" || { echo "FAIL: expected a cert-expiry WARN"; exit 1; }
[ "$warn_rc" -eq 0 ] || { echo "FAIL: warning-only run should exit 0 without --strict, got $warn_rc"; exit 1; }
[ "$strict_rc" -eq 1 ] || { echo "FAIL: --strict should exit 1 on a WARN, got $strict_rc"; exit 1; }
echo "OK: exit 0 without --strict, exit 1 with --strict on the same cert-expiry WARN"

echo
echo "== --server-name: match, mismatch (FAIL, exit 1), and omitted (skipped) =="
# Against the 2084 listener whose cert carries SAN radsec-short.corp.local.
# Matching name: the run still WARNs (10-day expiry outranks the name verdict)
# but --json must record name_validation=match. Wrong name: a hard FAIL, exit 1,
# listing the names the cert is actually valid for. Omitted: name_validation=
# skipped — the probe must never imply the name was checked when it wasn't.
set +e
nv_match="$("$work/authhound-probe" radsec test --server 127.0.0.1:2084 --server-name radsec-short.corp.local \
  --client-cert "$work/cert.pem" --client-key "$work/key.pem" --json)"; nv_match_rc=$?
nv_bad="$("$work/authhound-probe" radsec test --server 127.0.0.1:2084 --server-name wrong.corp.local \
  --client-cert "$work/cert.pem" --client-key "$work/key.pem" --no-color)"; nv_bad_rc=$?
nv_skip="$("$work/authhound-probe" radsec test --server 127.0.0.1:2084 \
  --client-cert "$work/cert.pem" --client-key "$work/key.pem" --json)"; nv_skip_rc=$?
set -e
echo "$nv_match" | grep -q '"name_validation": "match"' || { echo "FAIL: matching --server-name should record name_validation=match"; exit 1; }
[ "$nv_match_rc" -eq 0 ] || { echo "FAIL: matching name (WARN-only run) should exit 0, got $nv_match_rc"; exit 1; }
echo "$nv_bad" | grep -qi "does not match the expected name" || { echo "FAIL: wrong --server-name should FAIL with a mismatch summary"; exit 1; }
echo "$nv_bad" | grep -q "radsec-short.corp.local" || { echo "FAIL: mismatch detail should list the names the cert is valid for"; exit 1; }
[ "$nv_bad_rc" -eq 1 ] || { echo "FAIL: a name mismatch should exit 1, got $nv_bad_rc"; exit 1; }
echo "$nv_skip" | grep -q '"name_validation": "skipped"' || { echo "FAIL: omitted --server-name should record name_validation=skipped"; exit 1; }
[ "$nv_skip_rc" -eq 0 ] || { echo "FAIL: skipped-name run (WARNs only) should exit 0, got $nv_skip_rc"; exit 1; }
echo "OK: name match recorded; mismatch FAILs (exit 1) and names the SANs; omitted flag is reported as skipped, never as valid"

echo
echo "== no --server-name on radius test: server-cert WARNs that the name check was skipped =="
# The EAP server-cert check must say so out loud in text, and never print the
# old unqualified "valid" line for a run that skipped name validation.
set +e
nv_radius="$("$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" --no-color)"
nv_radius_json="$("$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" --json)"
set -e
echo "$nv_radius_json" | grep -q '"name_validation": "skipped"' || { echo "FAIL: radius-test server-cert should record name_validation=skipped"; exit 1; }
if echo "$nv_radius" | grep -q "Server certificate valid .* chain looks complete"; then
  echo "$nv_radius" | grep -q "name matches" || { echo "FAIL: an unqualified 'valid' verdict without name validation"; exit 1; }
fi
echo "OK: server-cert without --server-name never claims an unqualified valid"

echo
echo "== --json exposes schema_version + always-present per-status counts =="
sjson="$("$work/authhound-probe" radsec test --server 127.0.0.1:2084 \
  --client-cert "$work/cert.pem" --client-key "$work/key.pem" --json)"
echo "$sjson" | grep -q '"schema_version": "1"' || { echo "FAIL: --json missing schema_version"; exit 1; }
echo "$sjson" | grep -q '"warn": 1' || { echo "FAIL: --json summary.warn should be 1"; exit 1; }
echo "$sjson" | grep -q '"fail": 0' || { echo "FAIL: --json summary.fail should be present as 0"; exit 1; }
echo "OK: schema_version present; per-status counts addressable (warn=1, fail=0)"

echo
echo "== multi-server comparison: two healthy servers, then one down =="
# A second FreeRADIUS on a bridge port (the host-net primary already owns 1812),
# so the probe can compare two servers. Split-brain between RADIUS servers is the
# classic hidden cause of "intermittent" auth tickets. Permissive client entry
# (any source IP) because requests arrive via the Docker bridge gateway.
# Throwaway lab secret, never production.
cat > "$work/clients-secondary" <<'EOF'
client lab {
	ipaddr = 0.0.0.0/0
	secret = testing123
}
EOF
docker run -d --rm --name ah-secondary -p 127.0.0.1:11814:1812/udp \
  -v "$work/authorize:/etc/raddb/mods-config/files/authorize:ro" \
  -v "$work/clients-secondary:/etc/raddb/clients.conf:ro" \
  freeradius/freeradius-server:latest -fxx -l stdout >/dev/null
for i in $(seq 1 30); do
  if docker logs ah-secondary 2>&1 | grep -q "Ready to process requests"; then break; fi
  sleep 0.5
done

# Both healthy and matching -> "no split-brain", exit 0, per-server JSON blocks.
set +e
ms_ok="$("$work/authhound-probe" radius test --server 127.0.0.1,127.0.0.1:11814 --secret "$SECRET" --no-color)"; ms_ok_rc=$?
ms_json="$("$work/authhound-probe" radius test --server 127.0.0.1,127.0.0.1:11814 --secret "$SECRET" --json)"
set -e
echo "$ms_ok" | grep -A3 "Comparison across servers"
echo "$ms_ok" | grep -q "=== Server 1/2: 127.0.0.1:1812 ===" || { echo "FAIL: missing per-server banner"; exit 1; }
[ "$ms_ok_rc" -eq 0 ] || { echo "FAIL: two healthy servers should exit 0, got $ms_ok_rc"; exit 1; }
# Assert the verdict against the JSON (its verdict string is single-line; the
# text one is word-wrapped for the terminal and would split the phrase).
echo "$ms_json" | grep -q '"servers"' || { echo "FAIL: --json missing the servers[] block"; exit 1; }
echo "$ms_json" | grep -q '"comparison"' || { echo "FAIL: --json missing the comparison block"; exit 1; }
echo "$ms_json" | grep -q "no split-brain" || { echo "FAIL: two healthy servers should report no split-brain"; exit 1; }
if echo "$ms_ok$ms_json" | grep -q "$SECRET"; then echo "FAIL: secret leaked into multi-server output"; exit 1; fi
echo "OK: two healthy servers -> no split-brain; servers[]/comparison in JSON; exit 0"

# Primary healthy, secondary (unused port) down -> the round-robin verdict, exit 1.
set +e
ms_down="$("$work/authhound-probe" radius test --server 127.0.0.1,127.0.0.1:11899 --secret "$SECRET" --timeout 2s --no-color)"; ms_down_rc=$?
set -e
echo "$ms_down" | grep -A3 "Comparison across servers"
echo "$ms_down" | grep -qi "round-robin" || { echo "FAIL: one-down comparison should name the round-robin risk"; exit 1; }
echo "$ms_down" | grep -q "50%" || { echo "FAIL: 1-of-2 down should read ~50%"; exit 1; }
[ "$ms_down_rc" -eq 1 ] || { echo "FAIL: a dead server should exit 1, got $ms_down_rc"; exit 1; }
echo "OK: primary healthy, secondary down -> ~50% round-robin verdict; exit 1"
docker rm -f ah-secondary >/dev/null 2>&1 || true

echo
echo "== unwhitelisted probe (fresh server, no client entry -> expect registration hint) =="
# A fresh FreeRADIUS whose clients.conf contains only a dummy client, so requests
# from 127.0.0.1 come from an UNKNOWN client and are silently dropped — the
# guaranteed worst first-run moment. The probe must turn the timeout into a
# paste-ready registration snippet with the real detected source IP filled in.
docker rm -f ah-freeradius >/dev/null 2>&1 || true
cat > "$work/clients-none" <<'EOF'
client dummy {
	ipaddr = 192.0.2.1
	secret = not-used
}
EOF
docker run -d --rm --name ah-freeradius-nc --network host \
  -v "$work/clients-none:/etc/raddb/clients.conf:ro" \
  freeradius/freeradius-server:latest -fxx -l stdout >/dev/null
for i in $(seq 1 30); do
  if docker logs ah-freeradius-nc 2>&1 | grep -q "Ready to process requests"; then break; fi
  sleep 0.5
done

out="$("$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" --timeout 2s --no-color || true)"
echo "$out"
echo "$out" | grep -q "ipaddr = 127.0.0.1" || { echo "FAIL: hint missing detected source IP"; exit 1; }
echo "$out" | grep -q "New-NpsRadiusClient" || { echo "FAIL: hint missing NPS one-liner"; exit 1; }
if echo "$out" | grep -q "$SECRET"; then echo "FAIL: secret leaked into text output"; exit 1; fi

json="$(AUTHHOUND_SECRET="$SECRET" "$work/authhound-probe" radius test --server 127.0.0.1 --timeout 2s --json || true)"
echo "$json" | grep -q '"hint"' || { echo "FAIL: --json missing hint field"; exit 1; }
echo "$json" | grep -q '"source_ip": "127.0.0.1"' || { echo "FAIL: --json missing source_ip field"; exit 1; }
# Status-Server degrades gracefully: an unanswered probe is INFO (supported=false),
# never a FAIL — the reachability FAIL above carries the actionable guidance.
echo "$json" | grep -q '"supported": "false"' || { echo "FAIL: unanswered Status-Server should degrade to supported=false"; exit 1; }
if echo "$json" | grep -q "$SECRET"; then echo "FAIL: secret leaked into JSON output"; exit 1; fi
echo "OK: registration hint present with detected IP; Status-Server degraded to INFO; secret not leaked"

echo
echo "== flaky server: --count against induced packet loss (tc netem) =="
# A second FreeRADIUS on a bridge network (so netem can shape just its traffic,
# published on 127.0.0.1:11812) with a sidecar dropping ~25% of its replies and
# adding 30ms±20ms delay. This is the fixture for `--count`: intermittent loss
# and jitter that a single-shot run can't see.
docker rm -f ah-freeradius-nc >/dev/null 2>&1 || true
cat > "$work/clients-flaky" <<'EOF'
client lab {
	ipaddr = 0.0.0.0/0
	secret = testing123
}
EOF
docker run -d --rm --name ah-freeradius-flaky -p 127.0.0.1:11812:1812/udp \
  -v "$work/authorize:/etc/raddb/mods-config/files/authorize:ro" \
  -v "$work/clients-flaky:/etc/raddb/clients.conf:ro" \
  freeradius/freeradius-server:latest -fxx -l stdout >/dev/null
docker run -d --rm --name ah-netem --network "container:ah-freeradius-flaky" \
  --cap-add NET_ADMIN alpine:3 sh -c \
  "apk add --no-cache iproute2 >/dev/null && tc qdisc replace dev eth0 root netem loss 25% delay 30ms 20ms && sleep infinity" >/dev/null
for i in $(seq 1 30); do
  if docker logs ah-freeradius-flaky 2>&1 | grep -q "Ready to process requests"; then break; fi
  sleep 0.5
done
for i in $(seq 1 30); do
  if docker exec ah-netem tc qdisc show dev eth0 2>/dev/null | grep -q netem; then break; fi
  sleep 0.5
done

echo
echo "== --count 10 with 25% loss (expect lost requests, jitter, exit 1) =="
set +e
count_out="$("$work/authhound-probe" radius test --server 127.0.0.1:11812 --secret "$SECRET" \
  --pap 'alice:pw' --count 10 --interval 1s --timeout 2s --no-color)"; count_rc=$?
set -e
echo "$count_out"
echo "$count_out" | grep -q "Aggregate over 10 runs" || { echo "FAIL: missing aggregate block"; exit 1; }
echo "$count_out" | grep -q "lost" || { echo "FAIL: expected lost requests under 25% packet loss"; exit 1; }
[ "$count_rc" -eq 1 ] || { echo "FAIL: lost requests should exit 1, got $count_rc"; exit 1; }
echo "OK: aggregate names the loss; exit 1"

echo
echo "== --count --json exposes repeat block (iterations + aggregate) =="
set +e
cjson="$("$work/authhound-probe" radius test --server 127.0.0.1:11812 --secret "$SECRET" \
  --pap 'alice:pw' --count 5 --interval 1s --timeout 2s --json)"
set -e
echo "$cjson" | grep -q '"repeat"' || { echo "FAIL: --json missing repeat block"; exit 1; }
echo "$cjson" | grep -q '"completed": 5' || { echo "FAIL: repeat.completed should be 5"; exit 1; }
echo "$cjson" | grep -q '"aggregate"' || { echo "FAIL: repeat.aggregate missing"; exit 1; }
echo "$cjson" | grep -q '"iterations"' || { echo "FAIL: repeat.iterations missing"; exit 1; }
echo "$cjson" | grep -q '"latency_ms"' || { echo "FAIL: aggregate latency stats missing"; exit 1; }
if echo "$cjson" | grep -q "$SECRET"; then echo "FAIL: secret leaked into --count JSON"; exit 1; fi
echo "OK: repeat block present with per-iteration results and aggregate stats"

echo
echo "== --interval below the safety floor gets stretched (expect a note) =="
stretch_note="$("$work/authhound-probe" radius test --server 127.0.0.1:11812 --secret "$SECRET" \
  --count 2 --interval 100ms --timeout 2s --no-color 2>&1 >/dev/null || true)"
echo "$stretch_note" | grep -q "safety floor" || { echo "FAIL: expected the interval-stretch note"; exit 1; }
echo "OK: sub-floor interval stretched and announced"

echo
echo "== done; tearing down FreeRADIUS =="
