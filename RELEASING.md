# Releasing authhound-probe

Releases are cut by pushing a semver **`v*` git tag**. That triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml), which runs
[GoReleaser](https://goreleaser.com) to build every platform binary, checksum
and keyless-sign them, and publish a GitHub Release plus a multi-arch container
image to `ghcr.io/authhound/probe`.

There is **no manual artifact upload** and **no signing key to guard** — signing
is keyless (Sigstore), so the trust root is the GitHub Actions OIDC identity of
this repo's release workflow, not a secret someone can leak.

## Prerequisites (one-time)

- **Nothing to configure for signing or ghcr.** The workflow uses the built-in
  `GITHUB_TOKEN` (for the Release + ghcr push) and GitHub's OIDC token (for
  cosign keyless signing). No repository secrets are required.
- After the **first** release, make the container image public so
  `docker run ghcr.io/authhound/probe` works without a login:
  GitHub → the `authhound` org → **Packages** → `probe` → **Package settings**
  → **Change visibility** → **Public**. (One-time; it stays public.)

## Cut a release

From a clean `main` that's green in CI:

```console
# 1. Pick the next version (semver, leading v). Example: v0.1.0.
$ git checkout main && git pull

# 2. (Optional) dry-run locally first — see "Dry run" below.

# 3. Tag and push. The tag is what triggers everything.
$ git tag -a v0.1.0 -m "authhound-probe v0.1.0"
$ git push origin v0.1.0
```

Then watch **Actions → Release**. On success you'll have:

- A GitHub Release at `releases/tag/v0.1.0` with:
  - `authhound-probe_{linux,darwin}_{amd64,arm64}.tar.gz`
  - `authhound-probe_windows_{amd64,arm64}.zip`
  - `checksums.txt`, `checksums.txt.sig`, `checksums.txt.pem`
- `ghcr.io/authhound/probe:0.1.0` and `:latest` (multi-arch amd64+arm64), signed.

The README's `releases/latest/download/authhound-probe_linux_amd64.tar.gz` link
resolves automatically once the release exists — the archive names are
intentionally version-less (`name_template` in `.goreleaser.yaml`) so the
`latest/download/` URLs never change between versions.

## Verify (do this after every release)

Run the exact commands from the README's
[Verify your download](README.md#verify-your-download) section against the new
release. If `cosign verify-blob` and `sha256sum -c` both pass, the published
artifacts match what the pipeline built. This is the acceptance check.

## Dry run (before tagging)

You can exercise the whole config locally without publishing anything.

```console
# Validate the config (also catches deprecations):
$ goreleaser check

# Build + archive + checksum everything into ./dist, no push, no signing:
$ goreleaser release --snapshot --clean --skip=sign,docker,publish
$ ls dist/            # inspect archive names + checksums.txt

# Full docker/sign path locally needs a running Docker daemon + cosign + an
# OIDC token, so those steps only truly run in CI. `--skip` them locally.
```

Snapshot builds stamp a version like `0.0.0-SNAPSHOT-<sha>`; a real tag stamps
the clean version (`v0.1.0` → `authhound-probe 0.1.0`).

## How signing works (for reviewers)

- `signs:` in `.goreleaser.yaml` signs **`checksums.txt`** with `cosign
  sign-blob` (keyless). Because that file contains the SHA256 of every archive,
  one verified signature over it authenticates every artifact.
- `docker_signs:` signs the pushed image manifests with `cosign sign` (keyless).
- Keyless signing needs `id-token: write` (OIDC) — already set in the workflow
  permissions. Certificates are issued by Fulcio and logged in Rekor; nothing is
  stored between runs.

## Maintenance notes

- **GoReleaser is pinned** to the `~> v2.17.0` patch line in the workflow for
  reproducibility. The Docker config uses the classic `dockers` /
  `docker_manifests` blocks, which that version supports but has flagged as
  eventually superseded by `dockers_v2`. When you bump the pin, run
  `goreleaser check` and, if the classic blocks are dropped, migrate to
  `dockers_v2` (single block: `images` / `tags` / `platforms`) and re-test the
  image build.
- **Distroless base is pinned by digest** in
  [`Dockerfile.goreleaser`](Dockerfile.goreleaser). To refresh it to the latest
  `nonroot` image, resolve the multi-arch digest and update the `FROM` line:
  ```console
  $ TOKEN=$(curl -s "https://gcr.io/v2/token?scope=repository:distroless/static:pull&service=gcr.io" \
      | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
  $ curl -sI -H "Authorization: Bearer $TOKEN" \
      -H "Accept: application/vnd.oci.image.index.v1+json" \
      https://gcr.io/v2/distroless/static/manifests/nonroot | grep -i docker-content-digest
  ```
- **Adding a Docker Hub mirror later** (if you claim `docker.io/authhound`): add
  `docker.io/authhound/probe` image templates + a manifest in
  `.goreleaser.yaml`, add a `docker/login-action` step for Docker Hub in the
  workflow using `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` secrets, and update the
  README's Docker line. ghcr stays primary either way.

## If a release fails

- **Re-running:** delete the tag locally and remotely, fix, re-tag:
  ```console
  $ git tag -d v0.1.0 && git push origin :refs/tags/v0.1.0
  ```
  If a partial GitHub Release was created, delete it in the UI first.
- **ghcr push denied:** confirm the workflow has `packages: write` (it does) and
  that the org allows Actions to publish packages
  (org → Settings → Actions → Workflow permissions).
