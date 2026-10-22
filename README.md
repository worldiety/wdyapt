# wdyapt

wdyapt builds Debian packages from finished programs and publishes them,
signed, into an APT repository on SFTP storage. It is a standalone
command-line application for people and pipelines, written in Go with only
the standard library, without CGO and without other programs: it speaks SSH,
SFTP, OpenPGP, ar, tar and gzip itself. It needs neither `gpg` nor `ssh`,
`sftp` or `dpkg-deb`.

- **Build packages** from downloaded programs, units, configuration – via
  options or a JSON manifest, per architecture, reproducibly.
- **Publish** into a suite: pool, package lists, `Release`, `InRelease`,
  `Release.gpg`; signed with Ed25519 or RSA and SHA-512.
- **Carry on safely**: before every change, wdyapt verifies the published
  state against signature and checksums; it never replaces a published
  package; apt never sees a half-written state; two runs never overwrite each
  other.
- **Delete nothing**: wdyapt removes no packages and no entries.

Every command explains itself: `wdyapt` without arguments lists the commands,
`wdyapt help COMMAND` explains a command with all its options and environment
variables.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Describing packages](#describing-packages)
- [Pipelines](#pipelines)
- [Environment variables](#environment-variables)
- [Exit codes](#exit-codes)
- [How publishing works](#how-publishing-works)
- [Security](#security)
- [Operating with the existing repository](#operating-with-the-existing-repository)
- [Limits](#limits)
- [Development](#development)
- [License](#license)

## Installation

With Go:

```bash
go install github.com/worldiety/wdyapt/cmd/wdyapt@latest
```

Or a prebuilt program from the
[GitHub releases](https://github.com/worldiety/wdyapt/releases) (Linux and
macOS, amd64 and arm64, statically linked) together with its checksum:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

There is also a `.deb` each for Debian and Ubuntu.

## Quick start

**1. Generate a signing key** (once; the secret part belongs in a protected
CI variable, never in a repository):

```bash
WDYAPT_SIGNING_KEY_PASSPHRASE='…' wdyapt key generate \
  --user-id "Example APT <apt@example.com>" --out keys/apt
```

This writes `keys/apt.secret.asc` (mode 0600, never overwritten),
`keys/apt.gpg` (for `/etc/apt/keyrings/`) and `keys/apt.asc`. Keys from
GnuPG work as well; `wdyapt key show` shows what a key file contains.

**2. Fetch and check the host key of the SFTP server:**

```bash
wdyapt remote hostkey sftp.example.com:2222 > known_hosts
```

The fingerprints are printed on standard error. Compare them through a
second channel, such as the provider's documentation, before you trust the
file. wdyapt never accepts an unknown key.

**3. Check access without changing anything:**

```bash
export WDYAPT_SFTP_PASSWORD='…'
wdyapt remote check --remote sftp://deploy@sftp.example.com:2222/~/debian-repository \
  --known-hosts known_hosts
```

**4. Build a package:**

```bash
wdyapt deb build --name caddy --version 2.10.0-1 --arch amd64,arm64 \
  --maintainer "Example <dev@example.com>" --summary "Fast and extensible web server" \
  --file 'downloads/caddy_linux_{arch}:/usr/bin/caddy:0755' \
  --file caddy.service:/usr/lib/systemd/system/caddy.service \
  --out build/
```

**5. Publish** (a new suite only with `--create`):

```bash
wdyapt publish --create --suite stable --origin Example --label "Example APT" \
  --remote sftp://deploy@sftp.example.com:2222/~/debian-repository \
  --known-hosts known_hosts --signing-key keys/apt.secret.asc build/
```

With `--dry-run`, wdyapt first shows what it would upload and sign, and
writes nothing.

**6. Add it on a machine:**

```bash
sudo install -m 0644 keys/apt.gpg /etc/apt/keyrings/example.gpg
sudo tee /etc/apt/sources.list.d/example.sources <<'EOF'
Types: deb
URIs: https://deb.example.com/debian-repository/
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/example.gpg
EOF
sudo apt-get update && sudo apt-get install caddy
```

## Commands

| Command | Purpose |
|---|---|
| `wdyapt deb build` | Build Debian packages from files |
| `wdyapt deb info FILE...` | Show what packages contain (control data, files, checksums) |
| `wdyapt publish DEB\|DIR...` | Add packages to a suite, sign, upload |
| `wdyapt repo list` | List the packages of a suite |
| `wdyapt repo verify` | Check signatures, checksums and pool files |
| `wdyapt key generate` | Generate an OpenPGP signing key |
| `wdyapt key show FILE...` | Show fingerprint, user IDs, capabilities and protection of keys |
| `wdyapt key export` | Write the public key for apt |
| `wdyapt remote check` | Check access to the storage without changing anything |
| `wdyapt remote hostkey HOST[:PORT]` | Fetch host keys for known_hosts |

`--remote` takes `sftp://USER@HOST[:PORT]/PATH` (with `/~/PATH` relative to
the login directory), a local directory or `file:///PATH`; for reading
(`repo list`, `repo verify`) also `https://…`.

Many commands know `--json` (one JSON document on standard output),
`--quiet` and `--verbose` (negotiated algorithms, SFTP extensions).

## Describing packages

A package is described by options or a manifest (`--manifest`); options
override what the manifest says. Relative sources in the manifest are
resolved from its directory, unknown fields are an error.

```json
{
  "package": "caddy",
  "version": "2.10.0-1",
  "architectures": ["amd64", "arm64"],
  "maintainer": "worldiety GmbH <support@worldiety.de>",
  "summary": "Fast and extensible web server",
  "description": "First paragraph.\n\nSecond paragraph.",
  "homepage": "https://caddyserver.com",
  "section": "web",
  "depends": ["libc6 (>= 2.34)"],
  "files": [
    {"src": "downloads/caddy_linux_{arch}", "dst": "/usr/bin/caddy", "mode": "0755"},
    {"src": "caddy.service", "dst": "/usr/lib/systemd/system/caddy.service"},
    {"src": "share/", "dst": "/usr/share/caddy"}
  ],
  "directories": [{"path": "/var/lib/caddy", "mode": "0750"}],
  "symlinks": [{"path": "/usr/sbin/caddy", "target": "/usr/bin/caddy"}],
  "conffiles": ["/etc/caddy/Caddyfile"],
  "scripts": {"postinst": "scripts/postinst", "prerm": "scripts/prerm"},
  "fields": {"X-Origin-URL": "https://github.com/caddyserver/caddy/releases"}
}
```

- `{arch}` in sources becomes the Debian architecture (`amd64`, `arm64`,
  `armhf`, `i386`, `riscv64`, `ppc64el`, `s390x`), `{uname}` the name from
  `uname -m` (`x86_64`, `aarch64`, …). A source ending in `/` takes over a
  directory tree.
- Before building, wdyapt checks everything and reports all problems at
  once, including whether every ELF program matches the architecture
  (`--no-arch-check` turns that off). A dynamically linked program without
  `Depends` results in a warning.
- The same inputs and the same timestamp (`--epoch` or `SOURCE_DATE_EPOCH`)
  produce byte for byte the same package with the same Go version.

## Pipelines

wdyapt never asks. Everything can be set through environment variables,
secrets only through the environment or files.

**GitLab CI** (credentials as protected variables, files as variables of
type "File"):

```yaml
publish-tools:
  image: golang:1.27
  resource_group: apt-repository
  variables:
    WDYAPT_REMOTE: "sftp://${APT_REPOSITORY_SCP_USER}@${APT_REPOSITORY_SCP_HOST}:${APT_REPOSITORY_SCP_PORT}/~/${APT_REPOSITORY_SCP_ROOT}"
    WDYAPT_SFTP_PASSWORD: "${APT_REPOSITORY_SCP_PASSWORD}"
    WDYAPT_KNOWN_HOSTS: "${APT_REPOSITORY_SSH_KNOWN_HOSTS}"
    WDYAPT_SIGNING_KEY: "${APT_REPOSITORY_SIGNING_KEY}"
  script:
    - go install github.com/worldiety/wdyapt/cmd/wdyapt@v0.1.0
    - wdyapt deb build --manifest packages/caddy.json --out build/
    - wdyapt publish --suite stable build/
```

**GitHub Actions:**

```yaml
- name: Publish
  env:
    WDYAPT_REMOTE: sftp://deploy@sftp.example.com/~/debian-repository
    WDYAPT_SFTP_PASSWORD: ${{ secrets.APT_SFTP_PASSWORD }}
    WDYAPT_HOST_KEY: ${{ vars.APT_SFTP_HOST_KEY }}
    WDYAPT_SIGNING_KEY: ${{ runner.temp }}/apt.secret.asc
  run: |
    printf '%s' "${{ secrets.APT_SIGNING_KEY }}" > "$WDYAPT_SIGNING_KEY"
    go install github.com/worldiety/wdyapt/cmd/wdyapt@v0.1.0
    wdyapt publish --suite stable build/
```

Exit code 75 means "temporary" (lock held, suite changed in the meantime):
the pipeline may retry the job.

## Environment variables

| Variable | Option | Content |
|---|---|---|
| `WDYAPT_REMOTE` | `--remote` | Target: `sftp://user@host[:port]/path`, directory, `file:///path`; for reading also `https://…` |
| `WDYAPT_SFTP_PASSWORD` | – (secret) | Password of the SFTP user (password and keyboard-interactive) |
| `WDYAPT_SFTP_PASSWORD_FILE` | `--password-file` | File with the password |
| `WDYAPT_IDENTITY` | `--identity` | Private SSH key (OpenSSH format or PEM, unencrypted) |
| `SSH_AUTH_SOCK` | `--no-agent` turns it off | ssh-agent |
| `WDYAPT_KNOWN_HOSTS` | `--known-hosts` | known_hosts file; default `~/.ssh/known_hosts` |
| `WDYAPT_HOST_KEY` | `--host-key` | Expected fingerprints `SHA256:…`, comma-separated, instead of known_hosts |
| `WDYAPT_SUITE` | `--suite` | Suite, such as `stable` |
| `WDYAPT_COMPONENT` | `--component` | Component, default `main` |
| `WDYAPT_SIGNING_KEY` | `--signing-key` (repeatable) | Secret OpenPGP keys; several separated by `:` |
| `WDYAPT_SIGNING_KEY_PASSPHRASE` | – (secret) | Passphrase of the signing keys |
| `WDYAPT_SIGNING_KEY_PASSPHRASE_FILE` | `--passphrase-file` | File with the passphrase |
| `WDYAPT_TRUSTED_KEYS` | `--trusted-key` (repeatable) | Further public keys the state may be signed with; separated by `:` |
| `WDYAPT_MAINTAINER` | `--maintainer` | Maintainer of built packages |
| `SOURCE_DATE_EPOCH` | `--epoch` | Timestamp of all files in a built package |

An argument that is set beats the environment variable.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, including "nothing to do" |
| 1 | Error |
| 2 | Usage error (wrong or missing option); the message says what is missing |
| 75 | Temporary: lock held or suite changed during the run; retry |

## How publishing works

1. **Lock**: create `.wdyapt.lock` exclusively; if held: wait
   (`--wait-for-lock`) or exit 75. `--break-lock` removes an orphaned one.
2. **Read and verify the state**: the signature of `InRelease` or
   `Release.gpg` against the signing keys and `--trusted-key`, every package
   list against size and SHA256 in the Release. wdyapt never continues from
   an unverified state.
3. **Merge**: a package with the same name, version and architecture and the
   same bytes is "unchanged", with different bytes an error. Packages for
   `all` are in every list of the suite.
4. **Sign**: `InRelease` and `Release.gpg` with all signing keys, SHA-512;
   `Date` is always after the previous state.
5. **Upload**: pool files under a temporary name, check the size, rename;
   then lists and Release files under temporary names.
6. **Conflict check**: if `InRelease` changed since it was read: switch
   nothing, exit 75.
7. **Switching** by atomic rename (`posix-rename@openssh.com`):
   `Packages.gz`, `Packages`, `Release`, `Release.gpg`, `InRelease` last.

If a run aborts while switching, the next run completes the signed state of
the aborted one. `wdyapt repo verify` reports leftover temporary files and an
orphaned lock.

## Security

- Host keys are always checked against known_hosts (including hashed entries
  and `@revoked`) or `--host-key`, and never accepted blindly.
- SSH only with current algorithms: mlkem768x25519-sha256,
  curve25519-sha256, ECDH (NIST), DH groups 14/16 with SHA-2; AES-GCM,
  AES-CTR with HMAC-SHA2 (also encrypt-then-MAC); strict kex against
  Terrapin; no SHA-1, no CBC, no `ssh-rsa`.
- Before signing, wdyapt verifies the existing state. Someone who swaps lists
  on the storage without having the key does not get their state re-signed
  with the real key.
- Passwords, passphrases and keys come only from the environment or from
  files and appear in no output, no error, no JSON and not in the lock file.
- Data from the server is hostile: sizes are limited, `Filename` only under
  `pool/` without `..`.
- wdyapt starts no other programs.

## Operating with the existing repository

`https://deb.worldiety.org/debian-repository/` contains the suites `stable`
and `dev` of the hub applications, which wdyhub publishes with its own tool
(`cmd/internal/release` and `publish.sh`). wdyapt carries the state on
without machines noticing anything: it reads the wdyhub format, verifies the
signature, keeps `Origin`, `Label`, `Suite`, `Codename`, `Description` and
`Changelogs`, and takes over foreign entries unchanged. As long as wdyhub
still publishes with the old tool, the following applies:

- **In `stable` and `dev` only `main` and `amd64`/`arm64`/`all`.** The old
  tool hard-codes `Architectures: amd64 arm64` and `Components: main` and
  would drop additional lists from the Release on its next own run.
- **Prefer `stable` or a separate suite for foreign packages.** In `dev` the
  old tool keeps only five versions per package – also of packages that
  wdyapt added – and deletes their older pool files.
- **The same pool file not in `dev` and a third suite at once.** When
  cleaning up, the old tool only looks at `stable` and `dev`.
- **A shared `resource_group: apt-repository`** for both jobs in GitLab. The
  old tool does not know the lock file; the check before switching detects a
  run that switches during publishing, but not one that uploads an older
  state shortly afterwards.
- **The same signing key**: `APT_REPOSITORY_SIGNING_KEY` from the protected
  GitLab variables. It never belongs in this repository or its CI.

| wdyhub | wdyapt |
|---|---|
| `APT_REPOSITORY_SIGNING_KEY` (file) | `WDYAPT_SIGNING_KEY` |
| `APT_REPOSITORY_PREVIOUS_KEY` (file) | `WDYAPT_TRUSTED_KEYS` |
| `APT_REPOSITORY_SCP_HOST`, `_USER`, `_PORT`, `_ROOT` | `WDYAPT_REMOTE=sftp://USER@HOST:PORT/~/ROOT` |
| `APT_REPOSITORY_SCP_PASSWORD` | `WDYAPT_SFTP_PASSWORD` |
| `APT_REPOSITORY_SSH_KNOWN_HOSTS` (file) | `WDYAPT_KNOWN_HOSTS` |

A key rotation: sign with the old and the new key (`--signing-key` twice),
give machines the new key, then sign only with the new one and pass the old
one as `--trusted-key` until the first state signed with the new key has
been published.

## Limits

| Not included | Workaround |
|---|---|
| Deleting published packages, retention rules | Clean up by hand on the storage |
| Source packages, `Contents-*`, `Translation-*`, `Packages.xz`/`.zst` | Not needed for binary packages; xz and zstd are missing from the standard library |
| `Acquire-By-Hash`, `Valid-Until` | An existing `Valid-Until` is an error with an explanation |
| Foreign `.deb` with `control.tar.xz`/`.zst` | Repack with `dpkg-deb -Zgzip -b` or with `wdyapt deb build` |
| Encrypted OpenSSH private keys | ssh-agent or an unencrypted key in a protected CI variable |
| OpenPGP keys with AEAD or Argon2 protection, v5/v6 | Export with the default GnuPG protection or without a passphrase |
| `chacha20-poly1305@openssh.com` | AES-GCM and AES-CTR with ETM suffice |
| Windows | Not promised |
| Configuration file, `~/.ssh/config` | Options and environment variables |

## Development

Prerequisites: Go (version in `.github/workflows/ci.yml`), `just`, speclink
(`just tools`), Docker for the E2E tests.

| Recipe | Purpose |
|---|---|
| `just lint` | gofmt and go vet, including the E2E tests |
| `just test` | All tests with the race detector |
| `just verify` | Check with speclink, then an evidence run of all tests (`speclink.lock` must match) |
| `just spec` | Specification to `build/SPECIFICATION.md` |
| `just build`, `just build-cross` | Build wdyapt |
| `just release-check` | Build twice and compare |
| `just test-e2e`, `just test-e2e-all` | E2E tests in the Docker testbed (Ubuntu 26.04, or 24.04 and 26.04) |
| `just deps-check` | Only the standard library and `speclink/spec` |

The requirements are in `requirements/`, their sources
(`assignment.md`, `clarification-of-decisions.md`) in
`requirements/_sources/`; the implementation plan is in
`doc/implementation-plan.md`. Every normative requirement is bound in the
code and shown by a passing test. Only `speclink evidence` and
`speclink freeze` write `speclink.lock`.

The E2E tests (`e2e/`, build tag `e2e`) are the acceptance of the
interoperability with OpenSSH, GnuPG, gpgv, sqv, dpkg and apt; they run only
in the testbed because they create users, start sshd and install packages.

## License

BSD-2-Clause, see [LICENSE](LICENSE).
