# Testing authhound-probe

Three layers, fastest to most thorough:

| Layer | Command | Needs |
|---|---|---|
| Unit tests | `go test ./...` | Go |
| End-to-end (automated) | `./test/freeradius-smoke.sh` | Go, Docker, openssl, Linux |
| Manual lab | `docker compose -f test/lab/docker-compose.yml up` | Docker, Linux |

Nothing here is sensitive: it's a throwaway local container using FreeRADIUS's
well-known default test certificates (private-key password `whatever`), a fake
user (`alice` / `pw`), and the RFC-fixed RadSec secret `radsec`. Never point these
at production.

## Unit tests

```console
$ go test ./...
```

Covers the RADIUS/EAP packet layer, MSCHAPv2 crypto (RFC 2759 vectors), EAP-Message
fragmentation, and a RadSec exchange against an in-process TLS server — no Docker.

## End-to-end (automated)

```console
$ ./test/freeradius-smoke.sh
```

Spins up a real FreeRADIUS server in Docker, generates/extracts test certificates,
runs every check against it (reachability, shared secret, PAP, PEAP-MSCHAPv2,
EAP-TTLS, EAP-TLS, path-MTU, server certificate, and RadSec), prints the results,
and tears the container down. This is the canonical "does it actually work against
a real RADIUS server?" check. Linux only — it uses host networking.

## Manual lab

For poking at the probe interactively (or developing a new check), run the lab and
leave it up:

```console
$ docker compose -f test/lab/docker-compose.yml up        # Ctrl-C to stop
```

It serves classic RADIUS/UDP on `1812` and RadSec on `2083`.

With the `flaky` profile it also starts a second FreeRADIUS behind ~25% induced
packet loss and jitter (tc netem in a sidecar), published on `127.0.0.1:11812` —
the fixture for `radius test --count`:

```console
$ docker compose -f test/lab/docker-compose.yml --profile flaky up
$ go run ./cmd/authhound-probe radius test \
    --server 127.0.0.1:11812 --secret testing123 --pap alice:pw --count 10
```

The `unhardened` profile starts an **older FreeRADIUS (3.2.3)** that predates the
CVE-2024-3596 ("BlastRADIUS") reply-signing fix, published on `127.0.0.1:11813` —
the fixture for the BlastRADIUS posture check's **WARN** (unsigned reply). The
default `latest` server signs its replies and reports **PASS**:

```console
$ docker compose -f test/lab/docker-compose.yml --profile unhardened up
$ go run ./cmd/authhound-probe radius test \
    --server 127.0.0.1:11813 --secret testing123      # -> BlastRADIUS posture WARN
```

### Run the UDP checks

```console
$ go run ./cmd/authhound-probe radius test \
    --server 127.0.0.1 --secret testing123 \
    --pap alice:pw --peap alice:pw --ttls alice:pw --mtu
```

### Prepare a client certificate (for EAP-TLS and RadSec)

FreeRADIUS generates test certs on first boot, exported as a password-protected
`.p12`. Extract and convert it to PEM — the same step you'd do with a real device
cert export:

```console
$ CID=$(docker compose -f test/lab/docker-compose.yml ps -q freeradius)
$ docker cp "$CID:/etc/raddb/certs/client.p12" client.p12
$ openssl pkcs12 -in client.p12 -clcerts -nokeys -out client.pem -passin pass:whatever -legacy
$ openssl pkcs12 -in client.p12 -nocerts -nodes  -out client.key -passin pass:whatever -legacy
```

This client cert is signed by the same CA the lab server trusts, so EAP-TLS and
RadSec accept it.

### Run EAP-TLS and RadSec

```console
$ go run ./cmd/authhound-probe radius test \
    --server 127.0.0.1 --secret testing123 \
    --client-cert client.pem --client-key client.key

$ go run ./cmd/authhound-probe radsec test \
    --server 127.0.0.1 \
    --client-cert client.pem --client-key client.key
```

Tear down when done:

```console
$ docker compose -f test/lab/docker-compose.yml down
```

## Testing against your own server

The lab is only for development. To try the probe against a real RADIUS server,
add the probe host as a RADIUS client (see the main README's *One-time server
setup*), then point `--server` and `--secret` at it and run the same commands with
your own test account / certificate.

## Windows NPS

There is no Docker image for Windows NPS — it's a Windows Server role that depends
on Active Directory. To verify against NPS, run the probe from a machine that can
reach a real NPS server (add the probe's IP as a RADIUS Client in the NPS console
first). The probe already handles NPS's response framing; this is just confirmation
against the genuine article.
