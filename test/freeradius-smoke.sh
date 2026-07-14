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
trap 'rm -rf "$work"; docker rm -f ah-freeradius ah-freeradius-nc >/dev/null 2>&1 || true' EXIT

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
clients radsec {
	client 127.0.0.1 {
		ipaddr = 127.0.0.1
		proto = tls
		secret = radsec
	}
}
EOF

echo "== starting FreeRADIUS (debug, threaded for RadSec) =="
docker run -d --rm --name ah-freeradius --network host \
  -v "$work/authorize:/etc/raddb/mods-config/files/authorize:ro" \
  -v "$work/radsec:/etc/raddb/sites-enabled/radsec:ro" \
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
echo "== done; tearing down FreeRADIUS =="
