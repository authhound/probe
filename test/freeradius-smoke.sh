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
trap 'rm -rf "$work"; docker rm -f ah-freeradius >/dev/null 2>&1 || true' EXIT

# One test user for the PAP check. This file replaces the default authorize
# file; a single Cleartext-Password line is all the pap module needs.
cat > "$work/authorize" <<'EOF'
alice Cleartext-Password := "pw"
EOF

echo "== starting FreeRADIUS (debug) =="
docker run -d --rm --name ah-freeradius --network host \
  -v "$work/authorize:/etc/raddb/mods-config/files/authorize:ro" \
  freeradius/freeradius-server:latest -X >/dev/null

# Wait for it to be listening.
for i in $(seq 1 20); do
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
echo "== correct secret + valid PAP + PEAP-MSCHAPv2 + EAP-TLS + MTU probe (expect PASS) =="
"$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" \
  --pap 'alice:pw' --peap 'alice:pw' \
  --client-cert "$work/cert.pem" --client-key "$work/key.pem" --mtu --no-color || true

echo
echo "== wrong secret (expect shared-secret FAIL or no verify) =="
"$work/authhound-probe" radius test --server 127.0.0.1 --secret "wrongsecret" --no-color || true

echo
echo "== valid secret, bad password + untrusted client cert (expect FAILs) =="
"$work/authhound-probe" radius test --server 127.0.0.1 --secret "$SECRET" \
  --pap 'alice:nope' --peap 'alice:nope' \
  --client-cert "$work/bad.pem" --client-key "$work/bad.key" --no-color || true

echo
echo "== done; tearing down FreeRADIUS =="
