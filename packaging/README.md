# Windows packaging

Manifests for the Windows package managers. Both install the same
`authhound-probe_windows_<arch>.zip` that every GitHub release already ships —
nothing here changes the build. The version and the `InstallerSha256` /
`hash` fields are **per-release** and must be refreshed for each new tag; the
`0.1.0` and all-zero-hash values below are placeholders.

Where the hashes come from: every release publishes `checksums.txt` (SHA-256 of
each archive), and it's cosign-signed — see the README's *Verify your download*
section. Read the two Windows lines out of it:

```console
$ grep windows checksums.txt
<sha256>  authhound-probe_windows_amd64.zip
<sha256>  authhound-probe_windows_arm64.zip
```

## Scoop (`scoop/authhound-probe.json`)

Scoop installs from *buckets* (git repos of manifests). Easiest path is your own
bucket repo, e.g. `github.com/authhound/scoop-bucket`, with this manifest at its
root. Then users run:

```powershell
scoop bucket add authhound https://github.com/authhound/scoop-bucket
scoop install authhound-probe
```

The manifest has `checkver`/`autoupdate` wired to the GitHub releases, so once
the bucket is set up you keep it current with `scoop`'s own tooling instead of
editing hashes by hand:

```powershell
# in a clone of the bucket repo (needs the 'scoop' repo's bin/ on PATH)
.\bin\checkver.ps1 authhound-probe -Update   # bumps version + re-hashes from checksums.txt
```

To verify the manifest parses before publishing: `scoop install .\authhound-probe.json`.

## winget (`winget/`)

winget manifests live in the community repo
[`microsoft/winget-pkgs`](https://github.com/microsoft/winget-pkgs) under
`manifests/a/authhound/probe/<version>/`. The three files here (version,
installer, locale) are the complete manifest for one version.

**First submission, by hand:**

1. Fill in the real `PackageVersion`, `InstallerUrl`s, and both
   `InstallerSha256` values (from `checksums.txt` above). Set `ReleaseDate`.
2. Validate and test locally (Windows, with winget installed):
   ```powershell
   winget validate --manifest .\winget\
   winget install --manifest .\winget\      # installs from the local manifest
   ```
3. Fork `microsoft/winget-pkgs`, copy the three files to
   `manifests/a/authhound/probe/<version>/` (rename to
   `authhound.probe.yaml`, `authhound.probe.installer.yaml`,
   `authhound.probe.locale.en-US.yaml`), and open a PR. The repo's CI
   (`Azure Pipelines`) re-validates and smoke-installs in a sandbox; a reviewer
   merges it. Allow a day or two for the first one.

**Every release after that — automate it.** Add the
[`vedantmgoyal2009/winget-releaser`](https://github.com/vedantmgoyal2009/winget-releaser)
action to the release workflow; on each published release it regenerates these
manifests (pulling the SHA-256 from the release assets) and opens the
winget-pkgs PR for you:

```yaml
# in .github/workflows/release.yml, after the release is published
- uses: vedantmgoyal2009/winget-releaser@<pinned-sha>  # SHA-pin per our supply-chain policy
  with:
    identifier: authhound.probe
    installers-regex: '_windows_\w+\.zip$'
    token: ${{ secrets.WINGET_PAT }}   # a PAT with public_repo, to push the fork branch
```

Keep this directory as the source of truth for the manifest shape (identifier,
tags, nested-installer/portable settings); the action fills in version and
hashes from the release.
