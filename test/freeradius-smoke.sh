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
trap 'rm -rf "$work"; docker rm -f ah-freeradius ah-freeradius-nc ah-freeradius-flaky ah-netem >/dev/null 2>&1 || true' EXIT

# One test user for the PAP check, plus a machine identity for the NPS-style
# machine-auth check. This file replaces the default authorize file; a single
# Cleartext-Password line is all the pap module needs. FreeRADIUS treats the
# "host/PC-01.corp.local" identity like any other username — exactly the path a
# Windows computer account takes through PEAP-MSCHAPv2.
cat > "$work/authorize" <<'EOF'
alice Cleartext-Password := "pw"
host/PC-01.corp.local Cleartext-Password := "machinepw"
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
openssl req -x509 -newkey rsa:2048 -keyout "$short_dir/key.pem" -out "$short_dir/cert.pem" \
  -days 10 -nodes -subj "/CN=radsec-short.corp.local" >/dev/null 2>&1
cat "$short_dir/cert.pem" "$short_dir/key.pem" > "$work/server-short.pem"

echo "== starting FreeRADIUS (debug, threaded for RadSec) =="
docker run -d --rm --name ah-freeradius --network host \
  -v "$work/authorize:/etc/raddb/mods-config/files/authorize:ro" \
  -v "$work/radsec:/etc/raddb/sites-enabled/radsec:ro" \
  -v "$work/server-short.pem:/etc/raddb/certs/server-short.pem:ro" \
  freeradius/freeradius-server:latest -fxx -l stdout >/dev/null

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
echo "== machine auth: host/ identity via PEAP-MSCHAPv2 (NPS-style, expect PASS) =="
# A computer account authenticates with a "host/NAME.domain" identity and the
# machine-account password — no colon in the identity, so it parses cleanly.
"$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" \
  --nas-port-type ethernet --peap 'host/PC-01.corp.local:machinepw' --no-color || true

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
echo "== --json exposes schema_version + always-present per-status counts =="
sjson="$("$work/authhound-probe" radsec test --server 127.0.0.1:2084 \
  --client-cert "$work/cert.pem" --client-key "$work/key.pem" --json)"
echo "$sjson" | grep -q '"schema_version": "1"' || { echo "FAIL: --json missing schema_version"; exit 1; }
echo "$sjson" | grep -q '"warn": 1' || { echo "FAIL: --json summary.warn should be 1"; exit 1; }
echo "$sjson" | grep -q '"fail": 0' || { echo "FAIL: --json summary.fail should be present as 0"; exit 1; }
echo "OK: schema_version present; per-status counts addressable (warn=1, fail=0)"

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
if echo "$json" | grep -q "$SECRET"; then echo "FAIL: secret leaked into JSON output"; exit 1; fi
echo "OK: registration hint present with detected IP; secret not leaked"

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
