# Security

You run this tool inside your network with your RADIUS shared secret. That
only works if you can trust what's in the binary — this page documents how we
keep that trust checkable rather than asking you to take our word for it.

<!-- Vulnerability reporting / disclosure contact section maintained
     separately (WS-10); the sections below cover supply chain. -->

## Dependencies & supply chain

**Minimal-dependency policy.** The probe is stdlib-first Go. The dependency
tree is one direct module — `golang.org/x/term`, for no-echo secret prompts —
plus its `golang.org/x/sys` transitive, both maintained by the Go team. Every
dependency we don't have is a CVE stream we never have to watch; proposals
that add a dependency need to explain why ~50 lines of stdlib code can't do
the job. (MD4, needed for MSCHAPv2 interop, is vendored from the frozen
`golang.org/x/crypto/md4` into `internal/md4` with its license and RFC 1320
test vectors rather than pulling in the whole module.)

**Detection.**
- Every PR runs [`govulncheck`](https://go.dev/security/vuln/) in CI and
  fails on findings that are *reachable* from our code — call-graph analysis,
  not just version matching, so a red check always means something real.
- A daily scheduled scan runs the same check against `main`, catching CVEs
  published against dependencies (or the Go standard library) we haven't
  touched in months. Findings automatically open a tracking issue.
- PRs that change the dependency manifest additionally run GitHub's
  dependency review, which flags newly introduced vulnerable versions and
  license changes.

**Updates.** Dependabot opens PRs for Go modules and GitHub Actions weekly;
security updates arrive immediately. Nothing auto-merges — every bump gets a
human review, because real supply-chain attacks ride *new* versions and Go's
checksum database already prevents tampered re-publishes of existing ones.
The full policy is in [RELEASING.md](RELEASING.md#dependency-update-policy).

**Build pipeline.** Every GitHub Action in our workflows is pinned to a full
commit SHA (a hijacked version tag on a popular action is the likeliest
supply-chain hole in a small repo), and the workflow `GITHUB_TOKEN` is
read-only except in the release job. Releases are built by GoReleaser in CI —
no artifacts are ever uploaded by hand — and every release ships:

- keyless (Sigstore) cosign signatures, so you can verify artifacts came from
  this repo's release workflow (see "Verify your download" in the README);
- an SPDX SBOM per archive, so when a CVE drops you can check in seconds
  whether a release you deployed contains the affected module.

**What we promise.** Not zero CVEs — nobody can promise that honestly. What
we promise is fast, loud handling: if a vulnerability ships in a release, we
publish a GitHub Security Advisory and a patch release, and the SBOMs let you
determine your exposure without waiting on us.
