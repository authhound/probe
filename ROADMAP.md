# authhound-probe roadmap

The probe is a thin, read-only diagnostic client. Everything below stays inside
two rules: **diagnose the auth path, never sit in it**, and **never become
security/attack detection** — the guardrails that keep this a low-ops tool.

## Shipped (v1)

- RADIUS protocol layer (RFC 2865/3579): Access-Request, PAP password hiding,
  Message-Authenticator, Response-Authenticator verification.
- **Reachability + latency** — is the server answering, how fast.
- **Shared-secret verification** — cryptographically proves the secret matches.
- **PAP authentication** — real login, Accept/Reject decoded.
- **Server certificate inspection** — establishes the PEAP outer TLS tunnel over
  RADIUS (EAP-Message fragmentation, State tracking), captures the server cert,
  reports expiry / chain completeness / TLS version. Read-only: stops before
  sending any credential or client cert.
- **MFA/second-factor boundary detection** — recognises an Access-Challenge after
  valid primary creds and reports it without completing the factor.
- `--json` output; realistic NAS attributes (`--nas-port-type`, etc.).

Verified end-to-end against real FreeRADIUS (`test/freeradius-smoke.sh`).

## The engine, and why the order below

PEAP, EAP-TTLS, EAP-TLS, and MSCHAPv2 are **not four separate features** — they
share one core, the EAP/TLS-over-RADIUS transport (shipped above for cert
capture). Each method is now an increment on that engine.

## Next

1. **PEAP-MSCHAPv2 auth test** — the method most enterprises actually run. Adds
   MSCHAPv2 inside the existing tunnel (MD4/DES/SHA1; `x/crypto/md4`). This is
   the real "can my users log in" test. Confirms the MFA-boundary path too.
2. **EAP-TLS full auth** — for cert-based deployments; user supplies a client
   cert + key. Small on top of the engine.
3. **Fragmentation / MTU probe** — binary-search `fragment_size` to find the hop
   that drops large EAP-TLS packets. A differential diagnostic no competitor
   offers; needs the engine (have it).
4. **RadSec (RADIUS/TLS, TCP 2083)** — handshake + cert check for modern /
   migration deployments.
5. **EAP-TTLS** — same tunnel, PAP/MSCHAPv2 inner. Completeness; lower demand.

## On MFA (JumpCloud / Duo / Okta)

The probe **detects and reports** the MFA boundary but does not complete push or
OTP — by design. Completing it would require either a human approving pushes for
a monitoring robot, or storing a live second-factor secret on the probe (an
attack surface that contradicts "credentials stay local, least privilege"). The
recommended pattern for monitoring is a **test account exempt from MFA**, so the
primary auth path is validated cleanly. Generating OTPs from a locally-stored
TOTP seed is possible later as an explicit, opt-in, clearly-disclosed capability
— not a default.

## Explicitly out of scope

CoA / Disconnect-Request, completing MFA, packet capture, and anything that
mutates server state. These are excluded to keep the "never in the auth path,
read-only, no pager" thesis intact.

## Premium seam (not in the free tool)

`authhound-probe connect <token>` flips the same binary from local one-shot to a
scheduled probe reporting to the AuthHound service (history, drift, cert-expiry
alerting, fleet correlation). The `PlanSource`/`ResultSink` interfaces and the
hard-coded rate ceiling already exist for this; the cloud side is gated behind
discovery passing its kill/build bar.
