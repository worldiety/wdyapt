# Implementation plan: wdyapt

Originally written in German on 21 October 2026 and translated to English on 23 October 2026; the requirement IDs were renamed in the translation.

wdyapt builds Debian packages from finished programs and publishes them,
signed, to an APT repository on an SFTP storage. It is a standalone
command-line application for humans and pipelines, written in Go, using only
the standard library, without CGO and without external programs.

State: 21 October 2026. Created in a session in the wdyhub repository, which
served only as a reference; nothing was changed there. This plan is written so
that a new session can carry it out in an empty repository without any further
prior knowledge.

---

## Contents

1. [Instructions for the executing session](#1-instructions-for-the-executing-session)
2. [Starting point: the release tool in wdyhub](#2-starting-point-the-release-tool-in-wdyhub)
3. [Goals and non-goals](#3-goals-and-non-goals)
4. [Decisions made](#4-decisions-made)
5. [Usage concept](#5-usage-concept)
6. [Architecture](#6-architecture)
7. [Domain and technical details per building block](#7-domain-and-technical-details-per-building-block)
8. [Security](#8-security)
9. [Interplay with the existing repository](#9-interplay-with-the-existing-repository)
10. [speclink in the new repository](#10-speclink-in-the-new-repository)
11. [Test strategy](#11-test-strategy)
12. [Build, CI and delivery of wdyapt](#12-build-ci-and-delivery-of-wdyapt)
13. [Milestones](#13-milestones)
14. [Risks and open points](#14-risks-and-open-points)
- [Appendix A: Source documents of the requirements](#appendix-a-source-documents-of-the-requirements)
- [Appendix B: Requirements catalog](#appendix-b-requirements-catalog)
- [Appendix C: CLAUDE.md of the new repository](#appendix-c-claudemd-of-the-new-repository)
- [Appendix D: Justfile](#appendix-d-justfile)
- [Appendix E: Protocol reference](#appendix-e-protocol-reference)

---

## 1. Instructions for the executing session

### Prerequisites

| What | How to check | Note |
|---|---|---|
| Empty repository `github.com/worldiety/wdyapt`, cloned locally | `git remote -v` | The user creates it. |
| Go 1.27.x | `go version` | 1.27.3 was installed locally. Fix one version for reproducible releases. |
| speclink | `speclink help` | Pin: `go install github.com/worldiety/speclink/cmd/speclink@v0.0.0-20261013170042-95355e973f31` (installed at the time of this plan). Newer versions are allowed; then pin the same one everywhere. |
| just | `just --version` | All workflows run through the Justfile (Appendix D). |
| Docker | `docker info` | For the E2E tests (M8). |
| gh | `gh auth status` | For the pull request at the end. |

### Procedure

1. Read this plan in full. Then read the speclink README before you write
   code: `github.com/worldiety/speclink`, file `README.md` (locally in the
   module cache under `$(go env GOMODCACHE)/github.com/worldiety/speclink@<version>/README.md`).
   Chapter 10 of this plan summarizes what of it applies here and what was
   tested in the experiment.
2. Copy this plan into the new repository as `doc/implementation-plan.md`. It is
   the working basis, not a source of requirements (those are in
   `requirements/_sources/`, see Appendix A).
3. Work through the milestones from chapter 13 **one at a time and in order**.
   Before each milestone, show the user in a few sentences what you intend to do.
4. If something deviates from this plan (an assumption is wrong, a protocol
   behaves differently, a requirement cannot be held this way), ask the user
   **about each deviation separately** instead of deciding silently.
5. After each milestone: `just lint` and `just verify` are green, then a
   local commit (Conventional Commits, in English).
6. An empty repository has no target branch for a pull request. Therefore only
   the initial commit from M0 (README skeleton, LICENSE, .gitignore) goes
   directly onto `main`; **ask the user first**. Everything else is created on
   the branch `feat/wdyapt-mvp` and only goes into **one** pull request at the end.
7. Never change `speclink.lock` by hand; only `speclink evidence` and
   `speclink freeze` write it.
8. Before you declare yourself done: check whether Docker is reachable, and then
   run all E2E tests for both Ubuntu versions (`just test-e2e-all`).

### Reference wdyhub

If wdyhub is on the same machine, these files are the template (read only,
change nothing):

| File | Content |
|---|---|
| `/Users/tschloemer/Developer/worldiety/wdyhub/cmd/internal/release/archive.go` | ar and tar.gz as dpkg expects them |
| `.../cmd/internal/release/control.go` | Reading/writing control files, dpkg version comparison |
| `.../cmd/internal/release/deb.go` | Package build, ELF check, control file |
| `.../cmd/internal/release/repo.go` | Reading and checking the repository, advancing a channel, upload order |
| `.../cmd/internal/release/publish.sh` | gpgv check, signing with gpg, sftp with password |
| `.../cmd/internal/release/*_test.go` | Tests: taking a package apart like dpkg, reproducibility, rejections |
| `.../foundation/cli/*.go` | Self-explaining command line with the check `Program.Check` |
| `.../cmd/internal/e2e/package_test.go`, `.../cmd/internal/e2e/testbed/` | E2E in the Docker testbed with sshd, gpg and apt |

If wdyhub is missing, this plan is enough: chapters 2 and 7 describe everything needed.

---

## 2. Starting point: the release tool in wdyhub

wdyhub contains `cmd/internal/release`, a Go program with two commands, and
the shell script `publish.sh`:

- **`release deb`** builds one package `wdyhub-<program>` for amd64 and arm64
  for each of the hub's six programs. The package contents are hard-wired:
  program, systemd unit, sysusers.d, tmpfiles.d, journald.conf.d,
  ufw profiles, template of the environment file, maintainer scripts. Packages are
  reproducible (all timestamps = `SOURCE_DATE_EPOCH`, root:root,
  sorted entries, gzip without name and time).
- **`release repo`** reads the published state over HTTP or from a
  directory, checks the package lists against the SHA256 sums in `Release`,
  adds the packages of a version to the channel `stable` or `dev`, keeps in
  `dev` only the five newest versions per package, remembers pool files that are
  no longer needed for deletion, and writes everything changed, together with a
  command file `upload.sftp` for `sftp -b`, into an output directory.
- **`publish.sh`** imports the secret key into a temporary `GNUPGHOME`,
  checks the read `Release` files with `gpgv`, signs the new `Release` with
  `gpg --clearsign` (InRelease) and `gpg --detach-sign --armor` (Release.gpg),
  each with SHA512, and uploads with `sftp -b`: password via `SSH_ASKPASS`,
  `StrictHostKeyChecking=yes` with its own known_hosts file,
  `PreferredAuthentications=password,keyboard-interactive`.

Upload order in wdyhub: new packages first, then package lists under
`.tmp` names, then `rename` (overwriting on the storage, i.e.
`posix-rename@openssh.com`), `Release` and signatures last, `InRelease`
at the very end, after that the deletion of old packages.

### What is carried over

- ar, tar and gzip generation as in `archive.go` (dpkg-compatible, reproducible).
- Reading and writing control files (paragraphs, continuation lines, field order is kept).
- dpkg version comparison (`verrevcmp`) including tests.
- Checking the package lists against `Release`, signature check **before** signing.
- Principle "a published package is never replaced"; identical bytes are not an error.
- `Date` in the Release always increases (apt discards an older state).
- Upload order, so that apt never sees a half state.
- The self-explaining command line (`foundation/cli`) with its check.
- Test ideas: taking a package apart like dpkg, reproducibility, rejections, detecting tampering.

### What is dropped

- Retention rule "dev keeps five versions" and any deletion (assignment).
- Channel rules (`dev` only `~dev.` versions, `stable` only releases) and fixed
  channel names: wdyapt knows arbitrary suites.
- The wdyhub-specific package contents (`programs.go`).
- `upload.sftp`, `gpg`, `gpgv`, `sftp`, `ssh`: everything happens in process.
- Reading the published state over HTTP when publishing: wdyapt reads
  through the same access through which it writes.

---

## 3. Goals and non-goals

### Goals

1. Build arbitrary finished programs and further files into `.deb` packages.
2. Publish `.deb` packages into a suite of an APT repository on an SFTP storage:
   pool, package lists, `Release`, `InRelease`, `Release.gpg`.
3. Everything in its own process: SSH-2, SFTP v3, OpenPGP, ar, tar, gzip. Only the
   Go standard library plus `github.com/worldiety/speclink/spec`, `CGO_ENABLED=0`.
4. Every command and every option explains itself on standard output.
5. For humans and pipelines alike: non-interactive, options also
   via environment variables, machine-readable output, clear exit codes.
6. The existing repository `https://deb.worldiety.org/debian-repository/`
   is continued without machines that have it configured noticing anything
   (chapter 9). apt on Ubuntu 24.04 and 26.04 accepts everything.
7. Requirements with speclink: every normative requirement bound and shown by
   a passing test.

### Non-goals (deliberately left out)

| Not included | Reason / way out |
|---|---|
| Deleting published packages, retention rules, removing from package lists | Assignment. Cleaning up remains manual work. |
| Source packages, `Sources`, `Contents-*`, `Translation-*`, `Packages.xz/.zst` | Not needed for binary packages; xz/zstd do not exist in the standard library. |
| `Acquire-By-Hash`, `Valid-Until` | Possible later. An existing `Valid-Until` is an error with an explanation. |
| Foreign `.deb` with `control.tar.xz` or `control.tar.zst` | No xz/zstd in the standard library. Error message with a way out (chapter 14). |
| Encrypted OpenSSH private keys (bcrypt-pbkdf) | Blowfish is missing from the standard library. Way out: ssh-agent or an unencrypted key in a protected CI variable. |
| OpenPGP keys with AEAD or Argon2 protection, v5/v6 keys | GnuPG generates v4 with iterated S2K and CFB by default. Clear error message. |
| `chacha20-poly1305@openssh.com` | Not in the standard library; AES-GCM and AES-CTR+ETM are sufficient. |
| Windows | Not promised; the ssh-agent would run over named pipes there. |
| Configuration file, `~/.ssh/config` | Options and environment variables are sufficient. |
| Migration from wdyhub to wdyapt | A separate follow-up step in wdyhub (chapter 9). |

---

## 4. Decisions made

"User" means: decided by the user in the planning session on 21 October 2026.
"Proposal" means: proposed in the plan; to be presented to the user for approval
in M0 together with the source documents (Appendix A).

| No. | Decision | Origin |
|---|---|---|
| E1 | Name `wdyapt`; repository and module path `github.com/worldiety/wdyapt`; program under `cmd/wdyapt`. | User |
| E2 | Dependencies: only the standard library and, as the only exception, `github.com/worldiety/speclink/spec` (itself standard library only). A test enforces this. The program `speclink` is **not** a `tool` directive in `go.mod`, otherwise `golang.org/x/tools` and further modules would enter the module graph; it is installed pinned via `go install`. | User |
| E3 | No external programs at runtime, so also no `gpg`, `gpgv`, `ssh`, `sftp`, `dpkg-deb`, `tar`, `ar`. OpenPGP and SSH/SFTP are implemented in-house. | Follows from the assignment ("must not use any existing UNIX tools") |
| E4 | No deletion of published packages, no retention rule. | Assignment |
| E5 | CI with GitHub Actions; wdyapt itself is delivered as a GitHub release (static programs, SHA256SUMS) and via `go install`. | Follows from the hosting |
| E6 | Texts: output and help of the program in English, documentation and comments in German, code in English. Requirement texts in German. | As in wdyhub |
| E7 | Platforms: linux and darwin on amd64 and arm64. | Proposal |
| E8 | When publishing, wdyapt reads the existing state through the same access (SFTP) through which it writes, not over HTTP: no cache in between, no second address. | Proposal |
| E9 | Concurrent runs: lock file on the storage plus a check shortly before switching whether `InRelease`/`Release` has changed in the meantime. | Proposal |
| E10 | Package description via options or a JSON manifest file; options take precedence. | Proposal |
| E11 | A suite is only newly created with `--create` (protects against typos in `--suite`). | Proposal |
| E12 | The fields `Origin`, `Label`, `Suite`, `Codename`, `Description` and unknown fields of an existing suite are preserved (unattended-upgrades selects by them). | Proposal |
| E13 | License of the public repository: **open**. speclink and nago carry a proprietary worldiety license ("Use requires a license agreement with worldiety GmbH"). Ask the user before the first push. | Open |

---

## 5. Usage concept

### 5.1 Commands

```
wdyapt                      Purpose and list of commands (exit 0)
wdyapt help [COMMAND...]    Explains the program or a command
wdyapt version              Version

wdyapt deb build            Build Debian packages from files
wdyapt deb info FILE...     Show what Debian packages contain

wdyapt publish DEB...       Add packages to a suite of a repository, sign and upload it

wdyapt repo list            List the packages of a suite
wdyapt repo verify          Check signatures, checksums and files of a published repository

wdyapt key generate         Create an OpenPGP signing key for a repository
wdyapt key show FILE...     Show fingerprint, user IDs and capabilities of OpenPGP keys
wdyapt key export           Write the public key for apt (Signed-By)

wdyapt remote check         Connect to the storage and check access, changing nothing
wdyapt remote hostkey HOST  Fetch the host keys of an SFTP server for known_hosts
```

Groups without a command (`wdyapt deb`) explain their subcommands on stderr and
end with exit 2; `wdyapt` with no argument at all explains itself on stdout with exit 0.

### 5.2 Common rules

- **Stdout** carries only results (written paths, lists, JSON). **Stderr**
  carries help on misuse, errors and one line per work step
  ("Connecting to …", "Host key SHA256:… matches known_hosts line 3",
  "Uploading pool/main/c/caddy/caddy_2.10.0-1_amd64.deb (12.3 MB)").
- `--json` (where sensible) writes the result as one JSON document to stdout.
- `--quiet` suppresses the progress lines, `--verbose` adds protocol details
  (negotiated algorithms, SFTP extensions).
- Never interactive: no questions, no password prompt on the terminal.
- Every option with a sensible environment value has an environment variable `WDYAPT_*`;
  the help names it. A given argument beats the environment variable.
- **Secrets** never as an argument value (would be visible in `ps`): only via
  environment variables or files.
- Exit codes: `0` success (also "nothing to do"), `1` error, `2` misuse,
  `75` temporary (lock taken, state changed in the meantime; the pipeline may
  retry).
- Cancelling with SIGINT/SIGTERM cancels the context; wdyapt cleans up its own
  temporary files and the lock.
- Every help line fits into 80 columns.

### 5.3 Environment variables

| Variable | Option | Content |
|---|---|---|
| `WDYAPT_REMOTE` | `--remote` | Target: `sftp://user@host[:port]/path`, directory, `file:///path`; for reading also `https://…` |
| `WDYAPT_SFTP_PASSWORD` | – (secret) | Password of the SFTP user |
| `WDYAPT_SFTP_PASSWORD_FILE` | `--password-file` | File with the password |
| `WDYAPT_IDENTITY` | `--identity` | File with a private SSH key (OpenSSH format or PEM, unencrypted) |
| `SSH_AUTH_SOCK` | `--no-agent` turns it off | ssh-agent |
| `WDYAPT_KNOWN_HOSTS` | `--known-hosts` | known_hosts file; default `~/.ssh/known_hosts` |
| `WDYAPT_HOST_KEY` | `--host-key` | expected fingerprint `SHA256:…`, several comma-separated |
| `WDYAPT_SUITE` | `--suite` | Suite, e.g. `stable` |
| `WDYAPT_COMPONENT` | `--component` | Component, default `main` |
| `WDYAPT_SIGNING_KEY` | `--signing-key` (repeatable) | File(s) with a secret OpenPGP key; list separated by `:` |
| `WDYAPT_SIGNING_KEY_PASSPHRASE` | – (secret) | Passphrase of the signing keys |
| `WDYAPT_SIGNING_KEY_PASSPHRASE_FILE` | `--passphrase-file` | File with the passphrase |
| `WDYAPT_TRUSTED_KEYS` | `--trusted-key` (repeatable) | further public keys by which the published state may be signed (key rotation) |
| `WDYAPT_MAINTAINER` | `--maintainer` | Maintainer of the built packages |
| `SOURCE_DATE_EPOCH` | `--epoch` | Timestamp of all files of a built package |

The help lists secret variables without an option in a separate section
"Environment:". The CLI framework gets a field `Secrets` for this (chapter 7.8).

### 5.4 `wdyapt deb build`

```
wdyapt deb build [options]
  --manifest FILE        JSON manifest (7.2); options take precedence
  --name NAME            package name
  --version VERSION      Debian version, e.g. 2.10.0-1
  --arch ARCHES          comma-separated: amd64,arm64,armhf,i386,riscv64,ppc64el,s390x,all
  --maintainer "N <m>"   (WDYAPT_MAINTAINER)
  --summary TEXT         first line of the description
  --description TEXT | --description-file FILE   long description, paragraphs separated by a blank line
  --homepage URL  --section NAME (misc)  --priority NAME (optional)
  --depends, --pre-depends, --recommends, --suggests, --conflicts, --breaks,
  --replaces, --provides LIST      repeatable, comma-separated
  --file SRC:DST[:MODE]  repeatable; placeholders {arch} and {uname} in SRC;
                         SRC as a directory with "/" at the end takes over the tree
  --dir DST[:MODE]       empty directory
  --symlink DST:TARGET   symbolic link
  --conffile DST         file under /etc as a conffile
  --preinst|--postinst|--prerm|--postrm FILE   maintainer scripts
  --field KEY:VALUE      further field of the control file
  --epoch SECONDS        (SOURCE_DATE_EPOCH); if both are missing: now, with a notice
  --no-arch-check        turn off the ELF check
  --out DIR              target directory (.)
  --json
```

Result: one line per package with the path on stdout
(`<out>/<name>_<version without epoch>_<arch>.deb`). Placeholders: `{arch}` is
the Debian name (amd64, arm64 …), `{uname}` the name according to `uname -m`
(x86_64, aarch64, armv7l, i686, riscv64, ppc64le, s390x).

Example (human):

```
wdyapt deb build --name caddy --version 2.10.0-1 --arch amd64,arm64 \
  --maintainer "worldiety GmbH <support@worldiety.de>" \
  --summary "Fast and extensible web server" \
  --file 'downloads/caddy_linux_{arch}:/usr/bin/caddy:0755' \
  --file caddy.service:/usr/lib/systemd/system/caddy.service \
  --out build/
```

### 5.5 `wdyapt deb info`

Outputs per file the control file, conffiles, maintainer scripts (names), the file list
with mode/size/target, as well as size, SHA256 and file name in the pool. `--json`.
With `data.tar.xz/.zst` the file list is missing, with a notice.

### 5.6 `wdyapt publish`

```
wdyapt publish [options] DEB|DIR...
  --remote URL (WDYAPT_REMOTE)                  required
  --suite NAME (WDYAPT_SUITE)                   required
  --component NAME (WDYAPT_COMPONENT)           main
  --create                                      allows creating the suite (and root)
  --architectures LIST                          architectures of a new suite;
                                                extends them for an existing one
  --origin, --label, --codename, --description  fields of a new suite;
                                                error for an existing suite if different
  --signing-key FILE (WDYAPT_SIGNING_KEY)       repeatable, required
  --passphrase-file FILE                        or WDYAPT_SIGNING_KEY_PASSPHRASE
  --trusted-key FILE (WDYAPT_TRUSTED_KEYS)      repeatable
  --password-file FILE                          or WDYAPT_SFTP_PASSWORD
  --identity FILE (WDYAPT_IDENTITY)  --no-agent
  --known-hosts FILE (WDYAPT_KNOWN_HOSTS)  --host-key SHA256:… (WDYAPT_HOST_KEY)
  --date SECONDS                                date of the new Release (now)
  --dry-run                                     only show what would happen
  --out DIR                                     additionally store the new state locally
  --wait-for-lock DURATION                      wait for a taken lock (0)
  --break-lock                                  remove a foreign lock first
  --timeout DURATION                            total duration (30m)
  --json --quiet --verbose
```

A directory as an argument stands for all `*.deb` in it (not recursive).

Example (pipeline, GitLab):

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

### 5.7 `wdyapt repo list` and `repo verify`

- `repo list --remote URL --suite NAME [--component] [--arch] [--package] [--trusted-key …] [--json]`:
  lists package, version, architecture, size, pool path. Without `--trusted-key`
  read unchecked, with a notice on stderr.
- `repo verify --remote URL [--suite NAME…] --trusted-key FILE… [--check-pool] [--json]`:
  checks signatures, checksums of the lists, presence and size of every
  pool file; with `--check-pool` also their SHA256 (downloads everything). Without `--suite`
  all suites under `dists/` (only with SFTP/directory, HTTP needs `--suite`).
  Reports all defects, exit 1 if there is at least one. Names leftover
  temporary files of its own runs and an orphaned lock.

### 5.8 `wdyapt key …`

- `key generate --user-id "worldiety APT <apt@worldiety.de>" [--expires DURATION] --out PREFIX`
  writes `PREFIX.secret.asc` (mode 0600, never overwriting),
  `PREFIX.gpg` (public, binary, for `/etc/apt/keyrings/*.gpg`) and
  `PREFIX.asc` (public, ASCII). With a passphrase (environment or
  `--passphrase-file`) the secret key is protected. Prints the
  fingerprint on stdout.
- `key show FILE...` shows fingerprint, key ID, algorithm and length,
  creation, expiry, user IDs, subkeys with capabilities, whether a
  secret part is present and whether it is protected. Also reads keys from
  GnuPG. `--json`.
- `key export --signing-key FILE [--format binary|armored] [--out FILE]`
  writes the public key (default binary to stdout).

### 5.9 `wdyapt remote …`

- `remote check --remote URL [access options] [--write-test]`: connects,
  names the host key and where it was confirmed, the authentication method, the SFTP version
  and extensions, `realpath` of the root, suites found. Changes nothing;
  `--write-test` creates a probe file and removes it again.
- `remote hostkey HOST[:PORT] [--type ed25519|ecdsa|rsa]`: fetches the
  host keys (one connection per algorithm up to after the key exchange,
  like `ssh-keyscan`), writes known_hosts lines to stdout and the
  fingerprints with the warning to stderr to compare them over a second channel
  (provider documentation).

### 5.10 Addresses in `--remote`

| Form | Meaning |
|---|---|
| `sftp://user@host:port/~/dir` | `dir` relative to the login directory (like curl) |
| `sftp://user@host/srv/repo` | absolute path on the server |
| `/path` or `file:///path` | local directory (tests, mirrors) |
| `https://host/path/` | read only (`repo list`, `repo verify`) |

Default port 22. A password in the URL is rejected ("put it into
WDYAPT_SFTP_PASSWORD"). Users with special characters URL-encoded.

---

## 6. Architecture

### 6.1 Layout

```
cmd/wdyapt/                   main.go (wiring), cmd_*.go per command, tests
internal/cli/                 self-explaining command line (port from wdyhub)
internal/debian/              control files (deb822), names, versions, architectures
internal/deb/                 writing and reading .deb, manifest, ELF check
internal/openpgp/             armor, packets, keys, S2K, signing, verifying, generating
internal/ssh/                 SSH-2: transport, key exchange, ciphers, authentication, channels
internal/ssh/knownhosts/      reading and checking known_hosts
internal/ssh/agent/           ssh-agent client
internal/ssh/sshtest/         SSH server for tests only
internal/sftp/                SFTP v3 client over io.ReadWriteCloser
internal/sftp/sftptest/       SFTP server for tests only (on a directory)
internal/store/               storage: SFTP, directory; HTTP for reading
internal/repo/                repository: read, check, merge, write lists and Release
internal/publish/             publishing workflow: lock, state, signature, upload, switching
internal/version/             version of the program
internal/depcheck/            doc.go + test of the dependency graph
e2e/                          E2E tests (build tag e2e) and testbed (Dockerfile, run.sh)
requirements/                 requirements (chapter 10, Appendix B)
```

`internal/`, because wdyapt promises no library API; the command line is
the interface (also for wdyhub later).

### 6.2 Allowed dependencies between packages

```
cmd/wdyapt ──> cli, deb, debian, openpgp, publish, repo, store, ssh, sftp, version
publish    ──> repo, store, openpgp, debian
repo       ──> debian, deb (only reading the control file), openpgp (verify, sign), store (interface)
store      ──> ssh, ssh/knownhosts, ssh/agent, sftp
deb        ──> debian
ssh        ──> (standard library only)
sftp       ──> (standard library only; does not know ssh)
openpgp    ──> (standard library only)
debian     ──> (standard library only)
cli        ──> (standard library only)
```

`sftp` works over `io.ReadWriteCloser`; `ssh` provides the channel. This way
SFTP can be tested without SSH and SSH without SFTP.

### 6.3 Central interfaces

```go
// store: what publishing needs from the storage.
type Store interface {
	ReadFile(ctx context.Context, name string) ([]byte, error)     // fs.ErrNotExist if it is missing
	Open(ctx context.Context, name string) (io.ReadCloser, error)  // stream large files
	Stat(ctx context.Context, name string) (fs.FileInfo, error)
	ReadDir(ctx context.Context, dir string) ([]fs.DirEntry, error)
	MkdirAll(ctx context.Context, dir string) error
	// WriteTemp writes r under a new temporary name next to name
	// (name + ".wdyapt-<run>.tmp"), syncs if possible, and returns it.
	WriteTemp(ctx context.Context, name string, r io.Reader) (string, error)
	// Rename atomically replaces to with from (posix-rename or os.Rename).
	Rename(ctx context.Context, from, to string) error
	// CreateExclusive creates name and fails with fs.ErrExist if it exists.
	CreateExclusive(ctx context.Context, name string, data []byte) error
	Remove(ctx context.Context, name string) error // only for own temporary files and the lock
	Describe() string                              // for messages, without secrets
	Close() error
}
```

```go
// repo: pure logic without input/output except via Store reads.
type SuiteState struct { /* Release bytes, signatures, header, lists per component/architecture */ }
func ReadSuite(ctx, st store.Reader, suite string, keyring *openpgp.Keyring) (SuiteState, error)
func Merge(state SuiteState, pkgs []Package, opts MergeOptions) (Plan, error)
type Plan struct {
	PoolUploads []PoolFile          // new pool files
	Indices     map[string][]byte   // dists/<suite>/<comp>/binary-<arch>/Packages(.gz)
	Release     []byte
	Added, Unchanged []PackageRef
}
```

```go
// openpgp
func ReadKeys(r io.Reader) ([]*Entity, error)                       // armored or binary
func (e *Entity) Unlock(passphrase []byte) error
func SignDetached(w io.Writer, data []byte, signers []*Entity, t time.Time) error // armored, type 0x00
func SignCleartext(w io.Writer, text []byte, signers []*Entity, t time.Time) error // type 0x01
func (k *Keyring) VerifyDetached(data, sig []byte) ([]Fingerprint, error)
func (k *Keyring) VerifyCleartext(msg []byte) (text []byte, signers []Fingerprint, err error)
func Generate(userID string, created time.Time, expires time.Duration) (*Entity, error)
```

```go
// ssh
type ClientConfig struct {
	User string
	Auth []AuthMethod                 // Password, KeyboardInteractive, PublicKeys(signers...), Agent
	HostKey HostKeyCallback           // knownhosts or fingerprint; never "accept everything"
	HostKeyAlgorithms []string        // order, e.g. preferred from known_hosts
	Logf func(format string, a ...any)
}
func Dial(ctx context.Context, addr string, cfg *ClientConfig) (*Client, error)
func (c *Client) Subsystem(ctx context.Context, name string) (io.ReadWriteCloser, error)
```

```go
// sftp
func NewClient(rwc io.ReadWriteCloser) (*Client, error)  // INIT/VERSION, extensions
// Stat, Lstat, ReadDir, MkdirAll, Open, Create(flags), Write (pipelined), Rename
// (posix-rename, otherwise a fallback), Remove, Fsync, RealPath, Limits
```

---

## 7. Domain and technical details per building block

### 7.1 `internal/debian`: control files, names, versions

**Paragraphs (deb822).** As in wdyhub `control.go`: a paragraph is an ordered
list of fields; continuation lines begin with a space or tab and stay in the
value including the indentation (separated by `\n`). Keys without spaces, before the
first `:`. An empty line ends a paragraph. `get` ignores case.
Writing: `Key: Value`; for a value that begins with `\n`, `Key:` directly followed
by the continuation lines. What was read is written back unchanged.

**Package names:** `^[a-z0-9][a-z0-9+.-]+$` (at least two characters).

**Versions:** `[epoch:]upstream[-revision]`.
- epoch: `^[0-9]+$`
- upstream: begins with a digit; `[A-Za-z0-9.+~]`, plus `-` only if there is a
  revision (the revision is everything after the **last** `-`), and `:` only
  with an epoch.
- revision: `^[A-Za-z0-9.+~]+$`
- Comparison: epoch numerically, then `verrevcmp` on upstream and revision.
  `verrevcmp`: alternating non-digit and digit sections; for
  non-digits `~` has rank −1 (before everything, even before the end), end and
  digits rank 0, letters their ASCII value, everything else ASCII+256;
  digit sections numerically without leading zeros. Test sequence from wdyhub:
  `0.9 < 1.0~dev.20260101120000.aaaaaaaa < 1.0~dev.20260102120000.0000aaaa < 1.0 < 1.0-1 < 1.0-2 < 1.0.1~rc1 < 1.0.1 < 1.9 < 1.10 < 1.10a < 1.10+b < 1:0.1`, and also `1.01 == 1.1`.
- File name in the pool: `<package>_<version without epoch>_<arch>.deb`.

**Architectures:** `amd64, arm64, armhf, i386, riscv64, ppc64el, s390x, all`.
ELF mapping: amd64 `EM_X86_64`, arm64 `EM_AARCH64`, armhf `EM_ARM`,
i386 `EM_386`, riscv64 `EM_RISCV` (64 bit), ppc64el `EM_PPC64` little endian,
s390x `EM_S390`. `uname -m`: x86_64, aarch64, armv7l, i686, riscv64, ppc64le, s390x.

### 7.2 `internal/deb`: building and reading packages

**Manifest (JSON, lowercase fields, all optional except the required ones):**

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
  "priority": "optional",
  "depends": ["libc6 (>= 2.34)"],
  "pre_depends": [], "recommends": [], "suggests": [],
  "conflicts": [], "breaks": [], "replaces": [], "provides": [],
  "files": [
    {"src": "downloads/caddy_linux_{arch}", "dst": "/usr/bin/caddy", "mode": "0755"},
    {"src": "caddy.service", "dst": "/usr/lib/systemd/system/caddy.service"}
  ],
  "directories": [{"path": "/var/lib/caddy", "mode": "0755"}],
  "symlinks": [{"path": "/usr/sbin/caddy", "target": "/usr/bin/caddy"}],
  "conffiles": ["/etc/caddy/Caddyfile"],
  "scripts": {"postinst": "scripts/postinst", "prerm": "scripts/prerm"},
  "fields": {"X-Origin-URL": "https://github.com/caddyserver/caddy/releases"}
}
```

Relative `src` paths are taken from the directory of the manifest. Unknown JSON fields
are an error (`json.Decoder.DisallowUnknownFields`).

**Checks before the build** (report all errors collected):
- Required: package, version, at least one architecture, maintainer, summary,
  at least one file or one directory.
- Name, version, architecture according to 7.1; maintainer in the form `Name <mail>`.
- `dst` absolute, `path.Clean(dst) == dst`, no `..`, not `/`, no duplicate targets.
- conffiles must be files of the package (usually under `/etc`).
- Maintainer scripts begin with `#!`.
- Mode octal `0000`–`0777`; setuid, setgid and sticky are rejected.
- ELF check: every regular file that begins with `\x7fELF` must match the
  architecture (`debug/elf`, machine and OSABI NONE or LINUX). With `all`
  an ELF program is an error. Can be turned off with `--no-arch-check`.
- Dynamically linked programs (`PT_INTERP`, `ImportedLibraries`): warning with
  the required libraries if `Depends` is empty.
- Source directory with `/`: files recursively, modes normalized (directory
  0755, file 0755 if an x bit is set, otherwise 0644), symbolic
  links in the source tree are an error.

**Structure** (the format dpkg requires; as in wdyhub `archive.go`):
- ar: `!<arch>\n`, per member a 60-byte header
  `%-16s%-12d%-6d%-6d%-8s%-10d` + `` "`\n" `` (name without `/`, mtime = epoch,
  uid 0, gid 0, mode `100644`, size), data padded to even length with `\n`.
  Order mandatory: `debian-binary` (`2.0\n`),
  `control.tar.gz`, `data.tar.gz`.
- tar (GNU format): root entry `./` (directory 0755), every name with
  `./`, directories with `/` at the end, parent directories automatically
  (0755), everything `root:root` (0/0), mtime = epoch, sorted by name,
  directory before content, symbolic links as `TypeSymlink`.
- gzip: `gzip.BestCompression`, without name and without time in the header.
- control.tar: `control`, `md5sums` (per regular file except conffiles:
  `<md5>  <path without ./>`), `conffiles` (if present, one line per path),
  maintainer scripts (0755).
- control: `Package, Version, Architecture, Maintainer, Installed-Size,
  [Pre-Depends, Depends, Recommends, Suggests, Conflicts, Breaks, Replaces,
  Provides], Section, Priority, [Homepage], [further fields], Description`.
  Installed-Size in KiB: 1 per entry, plus `ceil(size/1024)` per file.
  Description: first line summary, paragraphs wrapped at 72 characters,
  each line indented with a space, empty line as ` .`.
- Same inputs + same epoch = same bytes (with the same Go version;
  `compress/flate` may change between Go versions).
- Output atomic: first `<file>.tmp`, then rename. If the target file exists with
  different content: error; with the same content: do nothing.

**Reading** (for `deb info` and `publish`): check ar headers, accept members with and
without `/` at the end; read `control.tar.gz` and `control.tar`;
`control.tar.xz/.zst` → error with explanation. The control file must be exactly one
paragraph, Package/Version/Architecture valid.

### 7.3 `internal/repo`: format of the repository

```
<root>/
  pool/<component>/<prefix>/<source>/<package>_<version>_<arch>.deb
  dists/<suite>/Release
  dists/<suite>/InRelease
  dists/<suite>/Release.gpg
  dists/<suite>/<component>/binary-<arch>/Packages
  dists/<suite>/<component>/binary-<arch>/Packages.gz
  .wdyapt.lock                 only during a run
```

- `<source>` = field `Source` without `(version)`, otherwise `Package`. `<prefix>` =
  first letter, for names starting with `lib` the first four (`libf`). wdyhub always uses
  the first letter; for `wdyhub-*` that is the same.
- Package entry in `Packages`: all fields of the control file in their order,
  with `Filename`, `Size`, `MD5sum`, `SHA256` inserted **before** `Description` (as in
  wdyhub). Entries separated by an empty line, sorted by Package, then
  Version (dpkg order), then Architecture.
- Packages with `Architecture: all` appear in **every** `binary-<arch>/Packages`
  of the suite. A new suite with only `all` packages needs `--architectures`.
- For every architecture of the suite there are `Packages` and `Packages.gz`, even if empty.
- `Release` of a new suite:

```
Origin: <--origin>
Label: <--label>
Suite: <suite>
Codename: <--codename or suite>
Date: <RFC1123, UTC>
Architectures: <sorted, separated by spaces>
Components: <sorted>
Description: <--description>
Changelogs: no
MD5Sum:
 <md5> <size> <comp>/binary-<arch>/Packages
 …
SHA256:
 <sha256> <size> <comp>/binary-<arch>/Packages
 …
```

- Existing suite: header fields keep their order and value, unknown
  fields likewise; only `Date`, `Architectures` and
  `Components` (union) as well as the checksum blocks are set anew. Checksum lines
  of unchanged lists stay, changed ones are replaced. `Valid-Until` present
  → error with explanation.
- `Date`: `--date` or now, truncated to seconds, in UTC; if it is not after
  the old `Date`, old `Date` + 1 s applies (apt discards older states). If
  the result is more than one minute in the future: warning.
- Time format: `time.RFC1123` in UTC (`Mon, 02 Jan 2006 15:04:05 UTC`).

**Reading and checking the state** (`ReadSuite`):
1. Read `dists/<suite>/InRelease`; if it is missing, `Release` + `Release.gpg`.
   If both are missing: the suite counts as not existing; then there must also be no
   package lists under `dists/<suite>/` (otherwise error "repair by hand").
2. Check the signature with the keyring (signing keys + `--trusted-key`);
   at least one valid signature of a trusted key, no
   invalid one. If there are InRelease **and** Release, the texts must be equal.
3. Read every list named in `SHA256`, check size and SHA256; entries
   need Package, Version, Architecture, Filename, Size, SHA256.
   `Filename` must begin with `pool/` and must not contain `..`.
4. Errors name the file and what to do; never continue with an unchecked state.
   Exception `--create` for a suite without any file.

**Merging** (`Merge`):
1. Every new package: read the control file, compute size, MD5, SHA256.
   The same package/version/architecture twice in the input with different content
   → error.
2. If the entry already exists in the suite: same SHA256 → "unchanged", otherwise
   error "packages are never replaced; build a new version".
3. If the pool file already exists (other suite, aborted run): determine size and
   SHA256 of the existing file (from the lists of all suites under
   `dists/`, otherwise download it). Equal → do not upload. Different and named by
   a suite → error. Different and named by no suite
   (leftover) → upload again, with a message.
4. Insert entries, sort, generate lists and Release anew.
5. **No** removal of entries, **no** deletion of pool files.

### 7.4 `internal/publish`: workflow of a publication

```
 1. Check inputs: read .deb (7.2), load and unlock keys,
    keyring = public parts of the signing keys + --trusted-key.
    Warning if a signing key expires in < 30 days; error if expired.
 2. Open the storage (7.7), check the root (if it is missing: create only with --create).
 3. Lock: CreateExclusive("<root>/.wdyapt.lock", JSON{host, user, pid,
    started, version, suite}). Taken: retry every 5 s until --wait-for-lock,
    then exit 75 with owner and age; --break-lock removes it
    first (with a message). The lock is removed at the end in any case.
 4. Read and check the state of the suite (7.3), remember the Release bytes (R0).
    For step 3 of Merge read the lists of the other suites (checked where possible).
 5. Merge (7.3). Nothing to add: message, exit 0, write nothing.
 6. Sign Release: InRelease (cleartext signature) and Release.gpg (detached,
    ASCII) with all signing keys, SHA-512. Immediately cross-check own signatures
    with the own verifier.
 7. --dry-run: print the plan (and store it with --out), release the lock, end.
 8. Upload pool files: WriteTemp → check size via Stat → Rename to the
    final name. An aborted transfer never leaves a half
    file under the final name.
 9. Upload package lists, Release, Release.gpg, InRelease under temporary names.
10. Concurrency check: read InRelease (or Release) again and compare with R0.
    Different → remove own temporary files, exit 75
    ("the suite changed while publishing; run again"). Uploaded pool files
    stay (named by nothing, harmless, reused in the next run).
11. Switching via rename, in this order: Packages.gz and Packages per
    list, then Release, Release.gpg, InRelease last.
12. Remove the lock. Summary: suite, added, unchanged,
    uploaded bytes, new Date, fingerprints of the signatures.
```

Errors after step 8 remove own temporary files (best effort) and
name what was left behind. An abort in the middle of the renames of step 11
leaves a state in which the lists are already new and InRelease still old; apt then reports
checksum errors temporarily until the next run. The run reports this
explicitly ("run publish again to complete"); another run with the same
packages completes the state (the packages are then "unchanged", Release is
written anew). Later this can be avoided entirely with `Acquire-By-Hash`.

### 7.5 `internal/openpgp`

Basis RFC 9580 (replaces RFC 4880), only v4 keys and v4 signatures.

**Armor:** `-----BEGIN PGP <TYPE>-----`, optional header lines, empty line, Base64
in lines of 64 characters (GnuPG) or ≤ 76, checksum `=XXXX` (CRC-24, start
`0xB704CE`, polynomial `0x1864CFB`, always output when writing, check when reading
if present), `-----END PGP <TYPE>-----`. Types: PUBLIC KEY BLOCK,
PRIVATE KEY BLOCK, SIGNATURE, SIGNED MESSAGE (cleartext).

**Packet header:** read the new format (`0xC0 | tag`, length 1/2/5 bytes, partial lengths
only needed when reading data, not for keys) and the old format
(`0x80 | tag<<2 | lentype`); write only the new format.

**Packets:** Signature (2), Secret-Key (5), Public-Key (6), Secret-Subkey (7),
Marker (10, ignore), Trust (12, ignore), User ID (13),
Public-Subkey (14), User Attribute (17, skip).

**Key material v4:** version 4, creation time (4 bytes), algorithm, then:
- RSA (1, also read 3 = sign-only): MPI n, MPI e.
- EdDSALegacy (22): OID length + OID `2B 06 01 04 01 DA 47 0F 01`
  (1.3.6.1.4.1.11591.15.1), MPI with `0x40 || 32 bytes` public key.
- Ed25519 (27): 32 bytes raw.
- ECDSA (19), ECDH (18), Cv25519 (subkeys for encryption):
  read and skip (not usable for signing for us), still compute the
  fingerprint.
- Fingerprint v4 = SHA-1(`0x99` || 2-byte length || packet body up to the end
  of the public part); key ID = last 8 bytes. (SHA-1 here only as an
  identifier, as specified in the standard.)

**Secret part:** S2K usage byte:
- 0: unprotected; MPIs followed by a 2-byte checksum (sum of the bytes mod 65536).
- 254: symmetric algorithm, S2K specifier, IV, encrypted (MPIs || SHA-1 of the MPIs).
- 255: like 254, but with a 2-byte checksum instead of SHA-1.
- 253 (AEAD): error "not supported, export the key with GnuPG's default protection or without passphrase".
- S2K types: 0 simple, 1 salted, 3 iterated+salted (count byte c:
  `(16 + (c & 15)) << ((c >> 4) + 6)` bytes), 4 Argon2 → error,
  101 GNU extension (`GNU` + mode 1 = stub without secret part, e.g. with
  `--export-secret-subkeys`) → the key has no secret part.
- Hash in the S2K: SHA-1 (2), SHA-256 (8), SHA-384 (9), SHA-512 (10).
  Symmetric: AES-128 (7), AES-192 (8), AES-256 (9) in CFB mode with the
  IV read (`crypto/cipher.NewCFBDecrypter`; deprecated, but available).
- Secret MPIs: RSA d, p, q, u; EdDSALegacy: MPI of the 32-byte seed (pad at the
  front with zeros to 32 bytes); Ed25519 (27): 32 bytes raw.

**Selecting the signing key:** primary key or subkey with
key flag "sign" (0x02), valid binding (subkey binding signature
0x18 from the primary key; for subkeys with the sign flag additionally check the
embedded back-signature 0x19), not revoked, not expired, with
secret part. If there are several: the newest.

**Creating a v4 signature:**
- Header: version 4, type (0x00 binary for Release.gpg, 0x01 canonical text for
  InRelease), key algorithm, hash SHA-512 (10).
- Hashed subpackets: creation time (2), issuer fingerprint (33,
  `04 || 20 bytes`). Unhashed: issuer key ID (16).
- Hash over: data || signature header from version to the end of the hashed
  subpackets || trailer `04 FF` + 4-byte length of this header part.
- Then the left 2 bytes of the hash, then:
  RSA: MPI from `rsa.SignPKCS1v15(nil, key, crypto.SHA512, digest)`.
  EdDSALegacy: `ed25519.Sign` → MPI r (first 32 bytes), MPI s (last 32 bytes),
  omit leading zero bytes in MPIs. Ed25519 (27): 64 bytes raw.
- Type 0x01 (canonical text): line endings as CRLF, trailing spaces
  and tabs of every line removed.

**Cleartext signature (InRelease):**

```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

<Release text, lines with "-" at the beginning as "- -">
-----BEGIN PGP SIGNATURE-----

<Base64>
=CRC
-----END PGP SIGNATURE-----
```

What is signed is the text without the last line break before `-----BEGIN PGP
SIGNATURE-----`, in canonical form. A Release ends with `\n`; apt reads the
text back with this `\n`. Several signatures follow one another in the
signature block (key rotation).

**Verifying:** read signature packets, find the issuer via subpacket 33 or 16 in the
keyring (primary keys and subkeys with a checked binding), recompute the hash,
compare the left 2 bytes, verify the signature mathematically. Allowed
hashes: SHA-256, SHA-384, SHA-512, SHA-224; SHA-1 and MD5 rejected (like sqv).
Creation time not in the future (> 5 min), key valid at creation time.

**Generating (`key generate`):** v4 EdDSALegacy (22) Ed25519, primary key with
flags certify+sign (0x03). User ID packet, positive certification (0x13) with:
creation time, key flags, preferred hashes (10, 8), preferred symmetric algorithms
(9, 7), features (0x01), issuer fingerprint, optionally expiration time (9).
EdDSALegacy instead of 27 because gpgv on Ubuntu 24.04 (GnuPG 2.4) does not know
algorithm 27. Secret export: unprotected (usage 0) or with a passphrase:
usage 254, AES-256, S2K iterated+salted with SHA-256 and count byte `0xF0` or
higher. Public export binary and ASCII.

**Test fixtures:** `internal/openpgp/testdata/` with keys and signatures generated by
GnuPG (Ed25519 unprotected and with passphrase, RSA-3072,
`--export-secret-subkeys` stub, a Release with a gpg cleartext signature and a
detached signature, `fingerprints.txt` from `gpg --with-colons`). Generated
once with `testdata/generate.sh` in an Ubuntu container (gpg is only needed for
generating the fixtures, never for wdyapt); record the script and the version of gpg
in the README of the testdata.

### 7.6 `internal/ssh`

Basis RFC 4250–4254, RFC 8308 (ext-info), RFC 8709 (ed25519), RFC 8731
(curve25519), RFC 5656 (ECDH/ECDSA), RFC 8332 (rsa-sha2), RFC 5647 and
PROTOCOL of OpenSSH (aes-gcm, etm, strict kex), draft-ietf-sshm-mlkem-hybrid-kex.

**Version exchange:** send `SSH-2.0-wdyapt_<version>\r\n`. Reading: skip lines
before `SSH-` (at most 32 lines, each ≤ 255 bytes), accept only `SSH-2.0-`
or `SSH-1.99-`. Both identification strings without CRLF go into the exchange hash.

**Binary packet:** `uint32 packet_length, byte padding_length, payload, padding,
MAC`. Padding ≥ 4, total length a multiple of max(8, block size), random
padding. Incoming at most 256 KiB. Sequence numbers per direction, overflow
modulo 2³².

**Algorithms (order = client preference):**

| Kind | Algorithms |
|---|---|
| Key exchange | `mlkem768x25519-sha256`, `curve25519-sha256`, `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521`, `diffie-hellman-group16-sha512`, `diffie-hellman-group14-sha256`; plus `ext-info-c` and `kex-strict-c-v00@openssh.com` in the first KEXINIT |
| Host key | `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `rsa-sha2-512`, `rsa-sha2-256`; algorithms for which known_hosts already knows a key move to the front |
| Ciphers | `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256-ctr`, `aes192-ctr`, `aes128-ctr` |
| MAC (only with CTR) | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512`, `hmac-sha2-256` |
| Compression | `none` |

Deliberately not: SHA-1 (`diffie-hellman-group*-sha1`, `ssh-rsa`, `hmac-sha1`),
CBC, `chacha20-poly1305` (not in the standard library), `sntrup761x25519`.
Negotiation: the first algorithm of the client that the server also names.

**Key exchange:**
- curve25519 / ECDH: `SSH_MSG_KEX_ECDH_INIT (30)` with Q_C,
  `KEX_ECDH_REPLY (31)` with K_S, Q_S, signature. `crypto/ecdh`. Shared
  secret K as mpint; reject X25519 with result 0. Hash SHA-256
  (nistp384: SHA-384, nistp521: SHA-512).
  H = HASH(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K), each as an
  SSH string, K as mpint.
- mlkem768x25519-sha256: INIT (30) carries `C_INIT = ML-KEM-768 encapsulation key
  (1184 bytes) || X25519 public (32 bytes)`; REPLY (31) carries `S_REPLY =
  ML-KEM ciphertext (1088 bytes) || X25519 public (32 bytes)`. K =
  SHA-256(ML-KEM secret || X25519 secret), **as a string** (not mpint)
  in the exchange hash and in the key derivation. `crypto/mlkem`. Test with OpenSSH 10
  in the E2E (Ubuntu 24.04 with OpenSSH 9.6 does not know it).
- diffie-hellman-group14/16: primes from RFC 3526 (group 14: 2048 bits,
  group 16: 4096 bits), g = 2, `KEXDH_INIT (30)` e, `KEXDH_REPLY (31)` K_S, f,
  signature; check `1 < f < p-1`; `math/big`.
- Verify the host signature over H: ed25519; ecdsa (blob = mpint r, mpint s; hash
  of the curve over H); rsa-sha2-256/512 (PKCS#1 v1.5 over H). Then check the host key
  against known_hosts or the fingerprint (7.6.1). Only after that NEWKEYS.
- Key derivation: `HASH(K || H || X || session_id)` with X = "A" (IV C→S),
  "B" (IV S→C), "C"/"D" (keys), "E"/"F" (MAC); extend with
  `HASH(K || H || so far)`. session_id = H of the first exchange.

**Strict KEX (against Terrapin):** If both name `kex-strict-*-v00@openssh.com`:
in the first exchange KEXINIT must be the first packet, any packet other than
those of the exchange is an abort; after every NEWKEYS (sent or
received) the sequence number of that direction starts at 0.

**Ciphers:**
- aes-gcm@openssh.com: packet_length unencrypted as AAD, the rest
  encrypted, 16-byte tag, no MAC. Nonce = 12-byte IV from the derivation;
  the last 8 bytes are a counter that increases by 1 per packet. Length of
  padding_length + payload + padding a multiple of 16.
- aes-ctr + ETM: packet_length unencrypted, MAC over seq || length ||
  ciphertext; check before decrypting (`hmac.Equal`).
- aes-ctr + classic MAC: everything encrypted, MAC over seq || plaintext packet.

**New key exchange (rekey):** A KEXINIT from the server can arrive at any time:
send our own KEXINIT, carry out the exchange, NEWKEYS. Initiate it ourselves after
1 GiB per direction or 1 hour. During the exchange higher layers wait
with sending. session_id stays.

**Further messages:** accept IGNORE (2), DEBUG (4), UNIMPLEMENTED (3);
DISCONNECT (1) → error with reason; EXT_INFO (7) → remember `server-sig-algs`;
GLOBAL_REQUEST (80) with want_reply → REQUEST_FAILURE (82).

#### 7.6.1 Host keys

- known_hosts: lines `[marker] hosts keytype base64 [comment]`. hosts:
  comma-separated, `host` for port 22, otherwise `[host]:port`; support patterns with `*`/`?`
  and negation `!`; hashed `|1|base64(salt)|base64(HMAC-SHA1(salt,
  hostname))`. Marker `@revoked` → key rejected; ignore `@cert-authority`
  (with a notice in `--verbose`).
- Fingerprint: `SHA256:` + Base64 without padding of SHA-256(key blob).
- Match: key equal → continue, message with file and line.
  Host known, but a different key of the same type → abort with both
  fingerprints ("possible man-in-the-middle"). Host unknown → abort with
  a pointer to `wdyapt remote hostkey` and comparison over a second channel.
  Never accept automatically.
- `--host-key` instead of known_hosts: one of the given fingerprints must match.

#### 7.6.2 Authentication (RFC 4252, 4256)

1. `SERVICE_REQUEST "ssh-userauth"`, `USERAUTH_REQUEST` with method `none` to
   learn the allowed methods. `USERAUTH_BANNER (53)` on stderr (only
   with `--verbose`).
2. Order: publickey (keys from `--identity`, then from the agent),
   password, keyboard-interactive. Each only if allowed and credentials are present.
3. publickey: signature over `string session_id || byte 50 || string user ||
   string "ssh-connection" || string "publickey" || bool TRUE || string alg ||
   string blob`. RSA with `rsa-sha2-512`/`-256` according to `server-sig-algs`, never
   `ssh-rsa` with SHA-1. A query without signature (`PK_OK (60)`) beforehand is allowed.
4. password: `bool FALSE, string password`. `PASSWD_CHANGEREQ (60)` → error.
5. keyboard-interactive: `INFO_REQUEST (60)` with exactly one prompt without echo →
   answer with the password; without prompts → empty answer; otherwise abort.
6. Failure: the message names the attempted and the allowed methods, never
   credentials.

**Private keys:** OpenSSH format (`openssh-key-v1\0`, cipher `none`, kdf
`none`, two equal checkints, ed25519/ecdsa/rsa), PKCS#8, PKCS#1, SEC1 (PEM,
`crypto/x509`). Encrypted → error with a way out (agent, unencrypted
key in a protected variable). File readable by others → warning.

**ssh-agent:** Unix socket `SSH_AUTH_SOCK`; `REQUEST_IDENTITIES (11)` →
`IDENTITIES_ANSWER (12)`; `SIGN_REQUEST (13)` with flags `RSA_SHA2_256 (2)` /
`RSA_SHA2_512 (4)` → `SIGN_RESPONSE (14)`, `FAILURE (5)`.

#### 7.6.3 Channels (RFC 4254)

`CHANNEL_OPEN "session"` (own window 2 MiB, packet size 32 KiB),
`OPEN_CONFIRMATION (91)` / `OPEN_FAILURE (92)`, `CHANNEL_REQUEST "subsystem"
want_reply "sftp"` → `SUCCESS (99)` / `FAILURE (100)`. `CHANNEL_DATA (94)`,
`EXTENDED_DATA (95)` (stderr of the server, print with `--verbose`),
`WINDOW_ADJUST (93)`: sending blocks until the window of the other side suffices;
refill our own window as soon as half of it is used up. `EOF (96)`,
`CLOSE (97)`, ignore `exit-status`. The channel is an `io.ReadWriteCloser`.

### 7.7 `internal/sftp` and `internal/store`

**SFTP v3** (draft-ietf-secsh-filexfer-02 and PROTOCOL of OpenSSH):
`uint32 length, byte type, uint32 request-id, …` (INIT/VERSION without
request-id). INIT with version 3; VERSION delivers extensions; remembered are
`posix-rename@openssh.com`, `fsync@openssh.com`, `limits@openssh.com`,
`statvfs@openssh.com`.

Used: OPEN (3) with flags READ 0x01, WRITE 0x02, CREAT 0x08, TRUNC 0x10,
EXCL 0x20; CLOSE (4); READ (5); WRITE (6); LSTAT (7); FSTAT (8); SETSTAT (9);
OPENDIR (11); READDIR (12); REMOVE (13); MKDIR (14); REALPATH (16); STAT (17);
RENAME (18); EXTENDED (200). Responses: STATUS (101), HANDLE (102), DATA (103),
NAME (104), ATTRS (105), EXTENDED_REPLY (201). Attribute flags: SIZE 0x1,
UIDGID 0x2, PERMISSIONS 0x4, ACMODTIME 0x8, EXTENDED 0x80000000. Status:
OK 0, EOF 1, NO_SUCH_FILE 2 (→ `fs.ErrNotExist`), PERMISSION_DENIED 3
(→ `fs.ErrPermission`), FAILURE 4, BAD_MESSAGE 5, OP_UNSUPPORTED 8.

- Several requests at the same time (request IDs), responses assigned via a reader
  goroutine.
- Writing and reading pipelined: up to 64 outstanding requests of 32 KiB each
  (or `max-write-length`/`max-read-length` from `limits@openssh.com`).
- `posix-rename@openssh.com` (oldpath, newpath) replaces atomically. If it is missing:
  RENAME; if that fails because the target exists: REMOVE + RENAME, with the warning
  "the server cannot replace files atomically".
- `fsync@openssh.com` (handle) before CLOSE, if offered.
- Exclusive creation: OPEN with CREAT|EXCL|WRITE; OpenSSH reports an existing
  target as FAILURE, therefore STAT afterwards to distinguish `fs.ErrExist`.
- `MkdirAll`: STAT, otherwise MKDIR per level.

**Storage:**
- `sftpStore`: TCP connection with timeout, SSH, subsystem `sftp`, paths
  relative to the root from `--remote` (`~/…` relative to the login directory,
  otherwise absolute), REALPATH of the root for messages.
- `dirStore`: `os` functions, `os.Rename` atomic, fsync of file and
  directory, `O_CREATE|O_EXCL` for the lock.
- `httpSource` (read only): `net/http` with timeout, 404 → `fs.ErrNotExist`,
  other codes → error with status.
- Size limits when reading: package lists unpacked ≤ 512 MiB, Release ≤ 16 MiB.

### 7.8 `internal/cli`

Port of wdyhub `foundation/cli`, without the installation renaming and without the
`Call`/administration interface:

- `Program{Name, Summary, Description, Version, Commands}`,
  `Command{Name, Args, Summary, Description, Flags func(*flag.FlagSet),
  Env map[string]string /* option → variable */, Secrets []Secret /* variable
  without an option, with explanation */, Run, Commands}`,
  `Invocation{Program, Path, Flags, Args, Stdout, Stderr, Getenv, Say(...)}`,
  `Environment{Args, Stdout, Stderr, Getenv}`.
- Dispatch: group without arguments at the top level → help on stdout,
  exit 0; deeper → help on stderr, exit 2; `-h`/`--help` → help on stdout,
  exit 0; unknown command → stderr + help, exit 2. Options also after
  positional arguments (`parseInterspersed`), after `--` everything positional.
- Environment values only for options not given; invalid value → exit 2
  with the variable in the text.
- Help: `name - summary`, description (wrapped at 78, indented paragraphs
  unchanged for examples), `Usage:`, `Commands:` (tabwriter), `Options:` with
  placeholder from the backticks of the usage, `default:` and `environment:`,
  `Environment:` for secrets, notice `Run "wdyapt help COMMAND"`.
- Built in: `help [COMMAND...]` and `version`.
- New compared to wdyhub: repeatable options (`flag.Value` as a list),
  `ErrTemporary` → exit 75, `Secrets`, JSON output helper.
- `Program.Check()`: summary and description per command, help per
  option, every placeholder from `Args` explained in the description, every
  environment variable belongs to an option, every secret has an explanation,
  no own `help`/`version`. Test: Check is empty and no help line
  is longer than 80 characters, for every command.

### 7.9 Version

`internal/version.current` set via `-ldflags -X`; if it is missing,
`debug.ReadBuildInfo().Main.Version` applies (with `go install …@vX.Y.Z`), otherwise
`devel`. The version appears in the SSH identification string and in the lock file.

---

## 8. Security

- **Host keys** always checked, never accepted automatically (7.6.1).
- **Check the state before signing:** someone who swaps lists and Release on the storage
  without having the key must not get wdyapt to re-sign their
  state with the real key (as in publish.sh).
- **Secrets** (SFTP password, passphrase, secret keys) only from the
  environment or files; never in output, errors, `--json`, `--verbose` or in
  the lock file. Tests check that a known test password and a
  passphrase appear in no output.
- **No weak algorithms** (SHA-1 signatures, CBC, ssh-rsa, DH-SHA1);
  MAC comparisons with `hmac.Equal`, AEAD via `crypto/cipher`.
- **Input from the server is hostile:** limit packet sizes, check length fields,
  `Filename` only under `pool/` without `..`, limit unpacked sizes.
- **Paths from inputs** (targets in packages, names, versions) checked strictly;
  build remote paths only from checked components.
- **Randomness** only from `crypto/rand` (cookie, padding, names of temporary files,
  keys).
- **File permissions:** secret outputs with 0600, never overwrite.
- **No `os/exec`** in packages of the module outside of tests (checked).

---

## 9. Interplay with the existing repository

The repository `https://deb.worldiety.org/debian-repository/` today contains the
suites `stable` and `dev`, component `main`, architectures `amd64 arm64`, with
`Origin: worldiety`, `Label: worldiety Hub`, `Changelogs: no`. Machines select
with unattended-upgrades by `origin=worldiety,suite=stable`. wdyhub
continues to publish with its own tool (`cmd/internal/release` +
`publish.sh`). It follows that:

1. **Compatible format:** wdyapt writes lists and Release the way wdyhub
   reads them: Packages entries with `Package, Version, Filename, SHA256` (plus
   `Size, MD5sum`), Release with a `SHA256` block (plus `MD5Sum`), paths
   `main/binary-<arch>/Packages(.gz)`. wdyhub carries over foreign entries unchanged in its
   next own run.
2. **Fields preserved** (E12): wdyapt never changes `Origin`, `Label`, `Suite`,
   `Codename`, `Description`, `Changelogs` of existing suites.
3. **Only `main` and `amd64`/`arm64`/`all` in `stable` and `dev`** as long as
   wdyhub publishes with the old tool: it hard-codes `Architectures:
   amd64 arm64` and `Components: main` and would lose additional lists from
   Release. wdyapt deliberately contains no special knowledge about this
   repository; the rule is in the README in the section "Operation".
4. **wdyhub's retention affects foreign packages in `dev`:** the old tool
   keeps five versions per package in `dev` – also of packages that wdyapt
   added – and deletes their older pool files. Therefore preferably publish foreign packages
   in `stable` or a separate suite.
5. **Shared pool files:** if the same pool file is in `dev` and in a
   third suite, the old tool may delete it when cleaning up `dev`,
   because it only looks at `stable` and `dev`. Do not publish the same file in
   `dev` and a third suite at the same time.
6. **Concurrent runs:** the old tool does not know the lock file. The
   check before switching (7.4 step 10) detects a wdyhub run that switches
   *during* the publication, but not one that uploads its older read state shortly *after*
   wdyapt (lost update). In
   GitLab put both jobs into the same `resource_group: apt-repository`
   as long as both tools write.
7. **Same signing key:** wdyapt signs with the key from
   `APT_REPOSITORY_SIGNING_KEY` (machines only know this one). It never leaves the
   protected variables of GitLab; the CI of wdyapt on GitHub does not get
   it.
8. **Follow-up step (not part of this plan):** wdyhub switches publishing
   to `wdyapt publish` (`release repo` and `publish.sh` are dropped; the
   retention in `dev` is then dropped or deliberately solved differently). After that
   points 3 to 6 no longer apply.

Mapping of the existing CI variables:

| wdyhub | wdyapt |
|---|---|
| `APT_REPOSITORY_SIGNING_KEY` (file) | `WDYAPT_SIGNING_KEY` |
| `APT_REPOSITORY_PREVIOUS_KEY` (file) | `WDYAPT_TRUSTED_KEYS` |
| `APT_REPOSITORY_SCP_HOST`, `_USER`, `_PORT`, `_ROOT` | `WDYAPT_REMOTE=sftp://USER@HOST:PORT/~/ROOT` |
| `APT_REPOSITORY_SCP_PASSWORD` | `WDYAPT_SFTP_PASSWORD` |
| `APT_REPOSITORY_SSH_KNOWN_HOSTS` (file) | `WDYAPT_KNOWN_HOSTS` |

**Test fixture for compatibility:** `internal/repo/testdata/wdyhub/` with
a state in the format of wdyhub (Release with exactly these fields in this
order: `Origin, Label, Suite, Codename, Date, Architectures, Components,
Description, Changelogs, MD5Sum, SHA256`; Packages entries with the fields
of the wdyhub packages and `Filename, Size, MD5sum, SHA256` before `Description`),
signed with a test key. If wdyhub is available, generate it there with
`go run ./cmd/internal/release repo … --published none` (only
run it, change nothing) and sign with the test key using wdyapt; otherwise
by hand according to this description.

---

## 10. speclink in the new repository

### 10.1 What was tested in the experiment

In the planning session a throwaway module was tested with speclink
`v0.0.0-20261013170042-95355e973f31`:

- Profile `go_bare_ddd1` in `speclink.json` (`{ "profile": "go_bare_ddd1" }`).
- Layout without `app/` and without `foundation/`: only `cmd/<tool>/main.go` and
  packages under `internal/`. No architecture findings; `K8-MAIN-EXISTS` is
  satisfied by `cmd/<tool>`. speclink detects no constructs there ("0
  constructs"); coverage arises solely through bindings.
- Bindings in `<base>.annotation.go` next to `<base>.go`, both
  `spec.ForPackage(spec.Satisfies(…))` and `spec.ForDecl(function,
  spec.Satisfies(…))`; `ForDecl` also works on a function of another package.
- Tests with `spec.Verified(t, …)` as the **last** statement;
  `go test -json ./... | speclink evidence -root .` writes `speclink.lock`;
  then `speclink verify -root . ./...` with "100% demonstrated, 0 findings".
- A requirement with `Status: spec.Planned` covers its source section
  ("100% accounted"), but needs neither a binding nor a test. This way all
  requirements can be created in M0 and switched to `spec.Normative` per milestone.
- Heading anchors keep umlauts: `## Selbsterklärend` →
  `selbsterklärend`.
- (Rejected, but tested: annotation files with `//go:build !release`
  work with speclink; the user chose E2 instead.)

### 10.2 Setup (M0)

```
go mod init github.com/worldiety/wdyapt
go get github.com/worldiety/speclink/spec@<version that matches the installed speclink>
echo '{ "profile": "go_bare_ddd1" }' > speclink.json
```

At the time of the plan the installed speclink depended on
`github.com/worldiety/speclink/spec v0.0.0-20260909124605-a91968ddccb4`
(`go version -m $(which speclink)` shows it).

`go.mod` then contains exactly one `require` line. `speclink` itself comes
via `go install …@<pin>` (Justfile recipe `tools`, CI step), not via
a `tool` directive.

### 10.3 Layout

```
requirements/
  _sources/assignment.md                       assignment by the user (Appendix A.1)
  _sources/clarification-of-decisions.md       clarifications (Appendix A.2)
  cst/R-CST-<NAME>.spec.go                     Kind: Constraint
  dec/R-DEC-<NAME>.spec.go                     Kind: Decision (with Rationale and Consequences)
  nfr/R-NFR-<NAME>.spec.go                     Kind: NonFunctional
  fun/pkg/R-PKG-<NAME>.spec.go                 Kind: Functional, area pkg
  fun/repo/R-REPO-<NAME>.spec.go
  fun/key/R-KEY-<NAME>.spec.go
  fun/access/R-ACCESS-<NAME>.spec.go
```

Rules (speclink README chapters 3 and 4.1): one requirement per file, the file
is named like the ID, directory, ID prefix and `Kind` match; every
requirement via `spec.Declare(spec.Requirement{…})`; `Text` short and normative;
multi-line texts as a raw string starting at column 0, never with `+`; `DerivedFrom` and
`Supersedes` via Go identifiers; `Sources` with `Doc` and `Anchor`. Every
heading of a source document yields at least one requirement or carries
`<!-- speclink:informative -->`.

### 10.4 Bindings

- Per package one `<file>.annotation.go` next to the file with the central
  function. Prefer `spec.ForDecl(deb.Build, spec.Satisfies(pkg.RPkgBuildFromFiles))`,
  because `speclink impact` then answers precisely per file; `spec.ForPackage` for
  cross-cutting concerns (e.g. `internal/ssh` for R-DEC-SSH-AND-SFTP-IN-PROCESS).
- Annotation files contain only the package clause, imports and `var _ = spec.X(…)`.
- The binding per requirement is in Appendix B, column "Binding".

### 10.5 Evidence

- Every test that shows a requirement ends with `spec.Verified(t, req…)`.
- Only passing tests count; one run is the whole truth.
- E2E tests (`-tags e2e`) are **not** part of the evidence run (as in wdyhub);
  they are the acceptance of the interplay with OpenSSH, GnuPG, dpkg and apt.
  Every requirement therefore needs a hermetic test (test server,
  fixtures from GnuPG).
- What cannot sensibly be tested: `spec.Waive("K14-REQ-UNVERIFIED", "<reason>")`
  on a binding construct – only after asking the user.

### 10.6 Workflow

```
go build ./...                                # must be green before speclink
speclink requirements -root . ./requirements/...   # the tree alone, when creating
just verify                                   # speclink verify + evidence run
speclink impact -root . <ID|file|source#anchor>    # what a change reaches
speclink freeze                               # after a deliberate text change (K10/K13)
just spec                                     # build/SPECIFICATION.md
```

`just verify` (Appendix D) runs `speclink verify` and then all tests with
`go test -count=1 -json ./... | speclink evidence -root .`. After that
`speclink.lock` must not differ; if it differs, the new version, once checked, belongs
in the same commit. If tests fail, the recipe restores the old lock.

On `K10-REQ-CHANGED` or `K13-SOURCE-DRIFT`: read the named text, adjust
what needs adjusting, `speclink freeze`. Always check changes to requirements against
the others for contradictions; in case of conflicts ask the user.

---

## 11. Test strategy

| Level | Where | What |
|---|---|---|
| Unit | per package | control files, versions, manifest, ar/tar, Release/Packages, merge rules, S2K, signatures, armor/CRC, known_hosts, SSH packet format, SFTP encoding |
| Fixtures | `internal/openpgp/testdata`, `internal/repo/testdata/wdyhub` | Keys and signatures generated by GnuPG; state in the wdyhub format |
| Hermetic integration | `internal/ssh/sshtest`, `internal/sftp/sftptest` | Own SSH server (all algorithms, password, keyboard-interactive, publickey, forced rekey every N bytes, wrong host key, Terrapin packet before NEWKEYS, abort in the middle of an upload) with an SFTP server on a temp directory; end-to-end publishing over it |
| Command line | `cmd/wdyapt` | `Program.Check`, help width, exit codes, environment variables, JSON output, no secrets in output |
| Dependencies | `internal/depcheck` | `go list -deps -json ./cmd/wdyapt`: only the standard library and `speclink/spec`; `go.mod` with exactly this one requirement; no `os/exec` in module packages; `CGO_ENABLED=0 go build` for linux/darwin × amd64/arm64 |
| E2E | `e2e/` (build tag `e2e`, Docker) | Interplay with OpenSSH, GnuPG/gpgv/sqv, dpkg, apt on Ubuntu 24.04 and 26.04 |

Test cases carried over from wdyhub (in spirit): taking a package apart like
dpkg (ar headers, debian-binary, tar entries with `./`, root, epoch, gzip without
time), control lines ≤ 80 characters, reproducibility of two runs, rejections
(wrong architecture, invalid version), many versions in a row (here:
all stay), suites stay separate, the same version again = nothing
uploaded and Date not backdated, tampering with a list is detected,
missing list, list without Release, upload order (InRelease last),
no switching without a signature.

### 11.1 E2E testbed

`e2e/testbed/Dockerfile`: `ubuntu:${UBUNTU}` with `openssh-server
openssh-client gnupg gpgv ca-certificates` (on 26.04 additionally `sqv`, if
apt uses it), Go copied from `golang:<version>`. `e2e/testbed/run.sh` builds the
image and starts `go test -tags e2e -count=1 -v ./e2e/...` as root in the
container with the repository and the module cache mounted. No systemd needed.

| Test | Checks |
|---|---|
| `TestDpkgAcceptsPackages` | `wdyapt deb build` → `dpkg-deb --info/--contents`, `dpkg -i`, files and modes, maintainer scripts run, conffiles, `dpkg -r`/`--purge` |
| `TestPublishAndInstall` | sshd on 127.0.0.1:2222 (user with a password full of shell special characters, user with publickey), `remote hostkey` equal to `ssh-keyscan`, `key generate`, `publish --create` via password, HTTP server (`net/http` in the test) over the home directory, sources file with `Signed-By` (binary), `apt-get update -o APT::Update::Error-Mode=any`, `apt-get install`, second version via key file and via ssh-agent, `apt-get upgrade`, `all` package in both lists |
| `TestGnuPGInterop` | Keys generated with gpg (ed25519, rsa3072, with passphrase, subkeys only) sign via wdyapt; `gpgv` (and `sqv`) verifies Release.gpg and InRelease; wdyapt verifies states signed by gpg; gpg imports a wdyapt key |
| `TestAlgorithmMatrix` | sshd once each with `-o KexAlgorithms=`, `-o Ciphers=`, `-o MACs=`, `-o HostKeyAlgorithms=` for every supported algorithm; `remote check` succeeds (mlkem only on 26.04) |
| `TestRekeyDuringUpload` | sshd with `RekeyLimit 1M`; upload a 50 MB package; SHA256 on the server equal |
| `TestTamperingAndRefusals` | changed Packages on the server → abort before the upload; wrong host key → abort before authentication; foreign signing key → abort; lock taken → exit 75 |
| `TestWdyhubLayout` | load a state in the wdyhub format (9), add a package, fields unchanged, apt sees old and new packages |

`just test-e2e` (default `UBUNTU=26.04`) and `just test-e2e-all` (24.04 and 26.04).

---

## 12. Build, CI and delivery of wdyapt

### 12.1 Build

```
CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> go build -trimpath -buildvcs=false \
  -ldflags "-s -w -X github.com/worldiety/wdyapt/internal/version.current=<VERSION>" \
  -o build/bin/<os>_<arch>/wdyapt ./cmd/wdyapt
```

Version from the file `VERSION` (e.g. `0.1.0`); development builds
`<VERSION>~dev.<commit time>.<hash8>`, release builds exactly `<VERSION>`.
Same source state + same Go version = same bytes; the CI builds twice
and compares.

### 12.2 GitHub Actions

All actions pinned by commit SHA, Go version fixed (set `go-version: 1.27.x`
to an exact version), `permissions: contents: read` as the default.

`.github/workflows/ci.yml` (push and pull request):

| Job | Steps |
|---|---|
| lint | `just lint` |
| test | `go test -race -count=1 ./...` |
| verify | install speclink pinned, `just verify` |
| reproducible | `just release-check` (build twice, compare) |
| e2e | matrix `UBUNTU: [24.04, 26.04]`, `just test-e2e` |

`.github/workflows/release.yml` (tag `v*`): the tag must be `v$(cat VERSION)`,
build twice and compare, `SHA256SUMS`, `gh release create` with the
programs; `permissions: contents: write` only in this job. Optional:
wdyapt builds itself as a `.deb` (amd64, arm64) and attaches the packages to the
release; they get into the APT repository from a GitLab pipeline with the
protected variables (follow-up step).

### 12.3 Documentation

`README.md` (in German): purpose, installation (`go install`, release with
checksum), quick start for humans (generate a key, fetch and check the host key,
build a package, publish, configure it on a machine),
pipeline examples (GitLab CI, GitHub Actions), environment variables, exit codes,
security, operation with the existing repository (chapter 9), limits
(non-goals), development (just recipes, speclink).

---

## 13. Milestones

Every milestone ends with a green `just lint` and `just verify` and a
local commit. The item "Requirements" names which ones from Appendix B go to
`spec.Normative` in this milestone, are bound and shown by tests.

### M0 – Skeleton

- Ask the user: license (E13) and whether the initial commit may go directly onto `main`.
- Initial commit on `main`: README skeleton, LICENSE, `.gitignore` (`build/`).
  After that the branch `feat/wdyapt-mvp`.
- `go.mod`, `speclink.json`, `Justfile` (Appendix D), `CLAUDE.md` (Appendix C),
  `VERSION` (`0.1.0`), `doc/implementation-plan.md`.
- Show the source documents from Appendix A to the user for approval, then store them.
- Create **all** requirements from Appendix B, status `spec.Planned`;
  `speclink requirements -root . ./requirements/...` without findings.
- `internal/cli` (7.8) with tests, `internal/version`, `cmd/wdyapt` with all
  commands as a skeleton (help complete, `Run` reports "not implemented yet"
  with exit 1).
- `internal/depcheck` with doc.go and test.
- `.github/workflows/ci.yml` (lint, test, verify, reproducible; e2e follows in M8).
- Requirements: R-CST-STANDARD-LIBRARY-ONLY, R-CST-NO-EXTERNAL-PROGRAMS,
  R-NFR-SELF-EXPLAINING-CLI, R-NFR-PLATFORMS.
- Scope approx. 1,000 lines.

### M1 – Debian foundations

- `internal/debian`: reading/writing paragraphs, names, versions (validation and
  comparison), architectures, ELF mapping.
- Requirements: none of its own; foundation for M2/M4 (tests contribute there).
- Scope approx. 500 lines.

### M2 – Building and showing packages

- `internal/deb`: manifest, checks, build, reading; `deb build`, `deb info`.
- Requirements: R-PKG-BUILD-FROM-FILES, R-PKG-CONTROL-DATA,
  R-PKG-VALIDATE-INPUT, R-PKG-SHOW, R-NFR-REPRODUCIBILITY (packages part).
- Scope approx. 1,200 lines.

### M3 – OpenPGP

- Generate fixtures with GnuPG (`testdata/generate.sh` in the container), then
  `internal/openpgp` (7.5); `key generate`, `key show`, `key export`.
- Requirements: R-DEC-OPENPGP-IN-PROCESS, R-KEY-USE-GNUPG-KEYS,
  R-KEY-GENERATE, R-KEY-EXPORT-AND-SHOW,
  R-KEY-ROTATION (multiple signatures part).
- Ask the user to run `wdyapt key show` locally on the real
  signing key (confirm algorithm and protection; the
  key does not leave their computer).
- Scope approx. 2,000 lines.

### M4 – Repository and publishing into a directory

- `internal/store` (dirStore, httpSource), `internal/repo`, `internal/publish`;
  `publish` against directories, `repo list`, `repo verify`.
- Test fixture in the wdyhub format (chapter 9).
- Requirements: R-REPO-PUBLISH-PACKAGES, R-REPO-NEVER-REPLACE,
  R-REPO-CHECK-STATE, R-REPO-SIGN, R-REPO-KEEP-RELEASE-FIELDS,
  R-REPO-DRY-RUN, R-REPO-LIST, R-REPO-VERIFY, R-DEC-NO-DELETION,
  R-DEC-ATOMIC-PUBLISHING, R-DEC-LOCK-AND-CONFLICT-DETECTION,
  R-KEY-ROTATION (trusted keys part), R-NFR-HUMANS-AND-PIPELINES,
  R-NFR-REPRODUCIBILITY (lists and Release part).
- Scope approx. 1,800 lines.

### M5 – SSH transport

- `internal/ssh` transport, algorithms, rekey, strict KEX, host keys,
  `knownhosts`; `internal/ssh/sshtest` (server side of the same building blocks);
  `remote hostkey`.
- Requirements: R-DEC-SSH-AND-SFTP-IN-PROCESS (transport part),
  R-ACCESS-HOST-KEY.
- Scope approx. 2,200 lines.

### M6 – Authentication and channels

- Authentication (publickey, password, keyboard-interactive), private keys,
  `internal/ssh/agent`, channels with window, subsystem.
- Requirements: R-ACCESS-LOGIN, R-NFR-CONFIDENTIAL-CREDENTIALS.
- Scope approx. 1,200 lines.

### M7 – SFTP and publishing over SFTP

- `internal/sftp`, `internal/sftp/sftptest`, `sftpStore`; `publish` and
  `remote check` over SFTP; end-to-end over sshtest.
- Requirements: R-DEC-SSH-AND-SFTP-IN-PROCESS (complete), R-ACCESS-CHECK.
- Ask the user to run `wdyapt remote check` (without `--write-test`) against the
  real storage: confirm authentication method, extensions
  (posix-rename!), path.
- Scope approx. 1,500 lines.

### M8 – E2E testbed

- `e2e/testbed`, tests from 11.1, `just test-e2e(-all)`, CI job e2e.
- Clarify deviations that only show up here (mlkem encoding, apt/sqv strictness)
  with the user one by one.
- Scope approx. 1,000 lines.

### M9 – Delivery and completion

- Release workflow, `just release-check`, README complete,
  `just spec` generates the specification without gaps.
- All requirements normative, `just verify` with "100% demonstrated",
  `just test-e2e-all` green.
- Pull request according to CLAUDE.md (Appendix C): squash commits, rebase onto `main`,
  push, `gh pr create` with title and description as CLAUDE.md prescribes,
  assign the user, connect the session to the PR and rename it.

Dependencies: M1 → M2 → M4; M3 → M4; M5 → M6 → M7; M4 + M7 → M8 → M9.
M3 and M5 do not depend on each other.

---

## 14. Risks and open points

| Point | Handling |
|---|---|
| License of the public repository | Clarify before the first push (E13). |
| Unknown SFTP storage (provider, extensions, authentication methods) | `remote check` early against the real storage (M7). Only this is known: OpenSSH `sftp` with password or keyboard-interactive works, `rename` overwrites (so presumably posix-rename). A fallback without posix-rename is planned. |
| Type and protection of the real signing key | `key show` in M3 by the user. RSA and Ed25519 are both provided for. |
| Encoding of mlkem768x25519 | E2E against OpenSSH 10; until then curve25519 remains as a fallback. |
| apt 3 with sqv is stricter than gpgv | E2E on 26.04; signatures only with SHA-512. |
| Lost update with concurrent runs of the old wdyhub tool | Chapter 9 point 6: shared `resource_group`; follow-up step migration. |
| Foreign `.deb` with xz/zstd | Later: own decompressors for xz (LZMA2) and zstd (about 1,000 lines each), only for reading `control.tar`. Ask whether needed. |
| Reproducibility across Go versions | Pin the Go version; the promise applies per version. |
| Switching not atomic across several files | Order as in wdyhub; extension `Acquire-By-Hash` possible later. |
| Size of the in-house implementation (SSH, OpenPGP) | Hermetic test servers, GnuPG fixtures, algorithm matrix in the E2E. |

---

## Appendix A: Source documents of the requirements

Present both documents to the user for approval in M0. A.1 reproduces the
assignment, A.2 the clarifications of this planning session; sections marked
"Proposal" have not yet been explicitly confirmed by the user.

### A.1 `requirements/_sources/assignment.md`

```markdown
# Assignment for wdyapt

<!-- speclink:informative -->
Assignment by the user of 21 October 2026. To create the APT packages for the
Hub applications, the repository wdyhub contains a Go-based tool that creates
the files and directory structures needed for them. So far it produces a set of
FTP/SCP commands.

## Ship arbitrary programs

We also want to pack other applications into APT packages and put them into
our repository. In this case they are finished binaries that we have already
downloaded. The Go tool therefore becomes a complete CLI application that can
ship arbitrary binaries into an APT repository.

## No deletion of uploaded artifacts

We do not need the logic that deletes artifacts that were already uploaded so
that there are not too many of them.

## No dependencies

The new tool shall have no dependencies. It shall use only the Go standard
library and work without CGO. It must not use any existing UNIX tools either.

## SFTP in the tool

So far the Go tool produces a set of FTP/SCP commands. The new tool shall
actually implement the SFTP protocol and carry out the file operations itself.

## Self-explaining commands

The new tool shall be easy to use and explain all its commands and parameters
on standard output.

## Humans and pipelines

The new tool shall be usable by humans, but also by the CI in a pipeline.
```

### A.2 `requirements/_sources/clarification-of-decisions.md`

```markdown
# Clarification of the fundamental decisions for wdyapt

<!-- speclink:informative -->
Decisions recorded in the planning session of 21 October 2026.

## Name and location

<!-- speclink:informative -->
The tool is called wdyapt and is developed in the public repository
github.com/worldiety/wdyapt.

## speclink as the only exception

The tool uses speclink for its requirements. The package
github.com/worldiety/speclink/spec, which requirement and annotation files
need, is the only permitted dependency outside the standard library; it uses
only the standard library itself. A test ensures that it stays that way.

## Signing in the tool

Because no UNIX tools are allowed, wdyapt signs and verifies the repository
itself according to OpenPGP, without gpg and gpgv. It reads keys exported by
GnuPG and can create keys itself. For a key change it signs with several keys
and accepts further trusted keys for the published state.

## Continue the existing repository

wdyapt publishes into the existing repository
https://deb.worldiety.org/debian-repository/ without machines that use it
noticing anything. Fields such as Origin, Label and Suite of an existing suite
remain unchanged. Before wdyapt changes anything, it checks the published state
against the trusted keys and the checksums. A published package is never
replaced by another one with the same name, version and architecture. It
creates new suites only when explicitly asked to.

## Safe switching

Machines never see a half-written state. New packages come first, package
lists and Release under temporary names, and these are moved into place last.

## Concurrent publishing

Two concurrent runs must not overwrite each other. A lock on the storage and a
check shortly before switching prevent that; a run that cannot continue
because of this ends in a way that lets a pipeline repeat it.

## Trying without effect

Every publication can be previewed without anything being written.

## Describing packages

A package is described by command line options or a manifest file: name,
version, architectures, maintainer, description, package relations, files with
target path and mode, directories, symbolic links, configuration files and
maintainer scripts. Inputs are checked before building, including whether a
program fits the given architecture. A built package can be shown.

## Reproducibility

The same inputs and the same timestamp produce the same package byte for byte,
and the same state produces the same package lists.

## Platforms

wdyapt runs on Linux and macOS, each on amd64 and arm64.

## Access to the storage

wdyapt logs in with a password, keyboard-interactive, a key file or through the
ssh-agent. It always checks the host key against known_hosts or a given
fingerprint and never accepts an unknown one. It can fetch the host keys of a
server and check the access without changing anything. Passwords, passphrases
and keys never appear in any output.
```

---

## Appendix B: Requirements catalog

Short version per requirement; the full `Text` (one to three sentences), and for
decisions additionally `Rationale` and `Consequences`, is written in M0.
Source: `A` = assignment.md, `K` = clarification-of-decisions.md, with anchor.
MS = milestone in which it becomes normative.

| ID | Kind | Summary | Source | Binding | Tests (examples) | MS |
|---|---|---|---|---|---|---|
| R-CST-STANDARD-LIBRARY-ONLY | Constraint | Only the standard library + speclink/spec, without CGO; a test checks the graph | A#no-dependencies, K#speclink-as-the-only-exception | `cmd/wdyapt` ForPackage | depcheck: TestOnlyStandardLibrary, TestBuildsWithoutCgo | M0 |
| R-CST-NO-EXTERNAL-PROGRAMS | Constraint | Starts no other programs; everything in process | A#no-dependencies, A#sftp-in-the-tool | `cmd/wdyapt` ForPackage | depcheck: TestNoExec | M0 |
| R-NFR-SELF-EXPLAINING-CLI | NonFunctional | Without a command purpose and commands; help for every command, every option, every placeholder, every variable, on stdout, ≤ 80 columns | A#self-explaining-commands | `internal/cli` ForDecl(Program.Check), `cmd/wdyapt` | TestProgramExplainsItself, TestHelpFitsTheTerminal | M0 |
| R-NFR-HUMANS-AND-PIPELINES | NonFunctional | Non-interactive; options via the environment; secrets only from environment/file; stdout result, stderr progress; --json; exit 0/1/2/75 | A#humans-and-pipelines | `internal/cli`, `cmd/wdyapt` | TestEnvironmentOverridesDefaults, TestExitCodes, TestJSONOutput | M4 |
| R-NFR-REPRODUCIBILITY | NonFunctional | Same inputs + timestamp = same bytes (packages, lists, Release) | K#reproducibility | ForDecl(deb.Build), ForDecl(repo.Merge) | TestDebIsReproducible, TestIndicesAreReproducible | M2/M4 |
| R-NFR-PLATFORMS | NonFunctional | linux and darwin × amd64 and arm64 | K#platforms | `cmd/wdyapt` | depcheck: TestBuildsWithoutCgo (all four) | M0 |
| R-NFR-CONFIDENTIAL-CREDENTIALS | NonFunctional | Secrets never in output, errors, JSON, lock | K#access-to-the-storage | `internal/store`, `cmd/wdyapt` | TestSecretsNeverPrinted | M6 |
| R-DEC-SSH-AND-SFTP-IN-PROCESS | Decision | Own SSH-2 + SFTP v3; algorithm list (7.6); strict kex; posix-rename | A#sftp-in-the-tool | `internal/ssh`, `internal/sftp` ForPackage | TestKexAlgorithms, TestCiphers, TestRekey, TestStrictKexRejectsInjectedPackets, TestSFTPOperations | M5/M7 |
| R-DEC-OPENPGP-IN-PROCESS | Decision | Own OpenPGP v4: Ed25519, RSA; SHA-512; no gpg | K#signing-in-the-tool | `internal/openpgp` ForPackage | TestVerifiesGnuPGSignatures, TestSignaturesVerifyWithOwnVerifier, TestArmorCRC | M3 |
| R-DEC-NO-DELETION | Decision | Delete no published packages, remove no entries, no retention rule | A#no-deletion-of-uploaded-artifacts | ForDecl(publish.Run) | TestManyVersionsAreKept, TestUploadNeverRemovesPublishedFiles | M4 |
| R-DEC-ATOMIC-PUBLISHING | Decision | Order pool → lists/Release temporary → switching, InRelease last; no half files | K#safe-switching, A#sftp-in-the-tool | ForDecl(publish.Run) | TestUploadOrder, TestAbortLeavesNoPartialFile | M4 |
| R-DEC-LOCK-AND-CONFLICT-DETECTION | Decision | Lock file; reading again before switching; exit 75 | K#concurrent-publishing | ForDecl(publish.Run) | TestLockHeld, TestConcurrentChangeDetected | M4 |
| R-PKG-BUILD-FROM-FILES | Functional | .deb from files, options or manifest, several architectures, placeholders | A#ship-arbitrary-programs, K#describing-packages | ForDecl(deb.Build) | TestBuildFromFlags, TestBuildFromManifest, TestArchPlaceholders | M2 |
| R-PKG-CONTROL-DATA | Functional | control, md5sums, conffiles, maintainer scripts, relations, description | K#describing-packages | ForDecl(deb.Build) | TestControlFields, TestConffilesAndScripts, TestParseLikeDpkg | M2 |
| R-PKG-VALIDATE-INPUT | Functional | Check names, versions, paths, modes; ELF matches the architecture | K#describing-packages | ForDecl(deb.Validate) | TestRejectsInvalidInput, TestElfArchitectureCheck | M2 |
| R-PKG-SHOW | Functional | `deb info`: control data, files, checksums | K#describing-packages | ForDecl(deb.Read) | TestInfoShowsPackage | M2 |
| R-REPO-PUBLISH-PACKAGES | Functional | Add packages to suite/component, generate lists and Release, `all` in all lists, new suite only with --create | A#ship-arbitrary-programs, K#continue-the-existing-repository | ForDecl(publish.Run) | TestPublishIntoNewSuite, TestArchAllInEveryList, TestMissingSuiteNeedsCreate | M4 |
| R-REPO-NEVER-REPLACE | Functional | Never replace; same bytes = do nothing | K#continue-the-existing-repository | ForDecl(repo.Merge) | TestNeverReplaces, TestRepublishIsNoop | M4 |
| R-REPO-CHECK-STATE | Functional | Check signature and checksums of the state before every change | K#continue-the-existing-repository | ForDecl(repo.ReadSuite) | TestTamperedListIsRejected, TestUntrustedSignatureIsRejected | M4 |
| R-REPO-SIGN | Functional | InRelease + Release.gpg, all signing keys, SHA-512; Date increases | K#signing-in-the-tool | ForDecl(publish.Run) | TestReleaseIsSigned, TestDateNeverGoesBack | M4 |
| R-REPO-KEEP-RELEASE-FIELDS | Functional | Origin, Label, Suite, Codename, Description, unknown fields stay | K#continue-the-existing-repository | ForDecl(repo.Merge) | TestWdyhubLayoutIsPreserved | M4 |
| R-REPO-DRY-RUN | Functional | --dry-run shows the plan, writes nothing | K#trying-without-effect | ForDecl(publish.Run) | TestDryRunWritesNothing | M4 |
| R-REPO-LIST | Functional | `repo list` | A#humans-and-pipelines | ForDecl(repo.List) | TestListSuite | M4 |
| R-REPO-VERIFY | Functional | `repo verify`: signatures, checksums, pool, leftovers | K#continue-the-existing-repository | ForDecl(repo.Verify) | TestVerifyFindsProblems | M4 |
| R-KEY-USE-GNUPG-KEYS | Functional | Read keys exported by GnuPG: Ed25519/RSA, unprotected or iterated S2K, subkeys, stubs | K#signing-in-the-tool | ForDecl(openpgp.ReadKeys) | TestReadsGnuPGKeys, TestUnlocksProtectedKey, TestPicksSigningSubkey | M3 |
| R-KEY-GENERATE | Functional | `key generate` | K#signing-in-the-tool | ForDecl(openpgp.Generate) | TestGeneratedKeySignsAndVerifies | M3 |
| R-KEY-EXPORT-AND-SHOW | Functional | `key export`, `key show` | K#signing-in-the-tool | ForDecl(openpgp.Export) | TestExportBinaryAndArmored, TestShowKey | M3 |
| R-KEY-ROTATION | Functional | Several signing keys; further trusted keys | K#signing-in-the-tool | ForDecl(publish.Run) | TestSignsWithTwoKeys, TestAcceptsPreviousKey | M3/M4 |
| R-ACCESS-LOGIN | Functional | password, keyboard-interactive, publickey (file, agent) | K#access-to-the-storage | `internal/ssh` ForDecl(Dial) | TestPasswordAuth, TestKeyboardInteractive, TestPublicKeyFile, TestAgent | M6 |
| R-ACCESS-HOST-KEY | Functional | Check against known_hosts/fingerprint; never accept; `remote hostkey` | K#access-to-the-storage | `internal/ssh/knownhosts` ForPackage | TestKnownHostsMatching, TestHashedHosts, TestUnknownHostRefused, TestHostKeyCommand | M5 |
| R-ACCESS-CHECK | Functional | `remote check` without changes | K#access-to-the-storage | ForDecl(store.Check) | TestRemoteCheckChangesNothing | M7 |

Mapping of the source sections (every heading yields at least one
requirement): A#ship-arbitrary-programs → R-PKG-BUILD-FROM-FILES,
R-REPO-PUBLISH-PACKAGES; A#no-deletion-of-uploaded-artifacts →
R-DEC-NO-DELETION; A#no-dependencies → R-CST-*; A#sftp-in-the-tool →
R-DEC-SSH-AND-SFTP-IN-PROCESS; A#self-explaining-commands →
R-NFR-SELF-EXPLAINING-CLI; A#humans-and-pipelines →
R-NFR-HUMANS-AND-PIPELINES, R-REPO-LIST; the K sections as in the
table. Check the anchors with `speclink requirements` before creating them.

---

## Appendix C: CLAUDE.md of the new repository

```markdown
# wdyapt

wdyapt builds Debian packages from finished programs and publishes them,
signed, into an APT repository over SFTP. It uses only the Go standard library
(single exception: github.com/worldiety/speclink/spec), no CGO, and starts no
other programs.

## Information

- The source code is public on GitHub: https://github.com/worldiety/wdyapt
- Requirements are checked with speclink (installed locally, version in the Justfile).
  Documentation: README of https://github.com/worldiety/speclink
- The implementation plan is in doc/implementation-plan.md.
- The most important workflows are in the Justfile; `just` lists them.

## Rules

### General

- Everything is in English: source code, program output and help texts,
  documentation, comments and requirement texts. worldiety publishes all of its
  public programs in English.
- Commit messages are in English and follow Conventional Commits.
- Pull request titles and descriptions are in English.
- Do not write attribution into Git commits or pull request descriptions.
- No new dependencies outside the standard library; no os/exec in the program.
  Tests may use external programs only in e2e/.
- Signing keys and credentials of the real repository never belong in this
  repository or its CI.
- When you think you are done: check whether Docker is reachable, then run
  `just test-e2e-all`.

### speclink

- Never change the file speclink.lock yourself; only `speclink evidence` and
  `speclink freeze` write it.
- Before every commit: `just lint` and `just verify`.
- If a change modifies or adds requirements, check them against all others for
  contradictions. If there are conflicts, ask the user how to resolve them.

### Pull requests

When the user wants a pull request:
- Commit all changes, `git fetch`, squash the new commits into one with a
  message that summarises all changes and explains the reason.
- Rebase onto the current state of the target branch, resolve conflicts, push.
- Create the pull request with `gh pr create`: the title is the first line of
  the commit message, the description is in English, the current user is the
  assignee (`--assignee @me`).
- Then link the session to the pull request and rename it so that the number
  comes first: "ABC" becomes "#12 ABC".

## Glossary

| Term | Explanation |
|---|---|
| Suite | Part of an APT repository below dists/<suite>/, e.g. stable or dev (called "channel" in wdyhub). |
| Component | Subdivision of a suite, e.g. main. |
| Pool | Location of the .deb files below pool/. |
| Release | File with the header and checksums of a suite; signed as InRelease and Release.gpg. |
| Storage | The SFTP server or the directory that holds the repository. |
| Signing key | Secret OpenPGP key that wdyapt signs the Release with. |
| Trusted key | Public key the published state may be signed with. |
```

---

## Appendix D: Justfile

```just
# The recipes of wdyapt. `just` without a recipe lists them.
set shell := ["bash", "-eo", "pipefail", "-c"]
set script-interpreter := ["bash", "-euo", "pipefail"]
set lazy

BUILD := "build"
SPECLINK := env("SPECLINK", "speclink")
SPECLINK_VERSION := "v0.0.0-20261013170042-95355e973f31"
VERSION_PKG := "github.com/worldiety/wdyapt/internal/version"
BASE_VERSION := `cat VERSION`
COMMIT_TIMESTAMP := env("COMMIT_TIMESTAMP", `TZ=UTC git show -s --format=%cd --date=format-local:%Y%m%d%H%M%S HEAD 2>/dev/null || true`)
BUILD_COMMIT := env("BUILD_COMMIT", `git rev-parse --short=8 HEAD 2>/dev/null || true`)
FULL_VERSION := env("FULL_VERSION", BASE_VERSION + "~dev." + COMMIT_TIMESTAMP + "." + BUILD_COMMIT)
SOURCE_DATE_EPOCH := env("SOURCE_DATE_EPOCH", `git show -s --format=%ct HEAD 2>/dev/null || true`)
TEST_JSON := env("TEST_JSON", "")
UBUNTU := env("UBUNTU", "26.04")
OSES := "linux darwin"
ARCHES := "amd64 arm64"

[doc("Show all recipes with explanations")]
help:
    @"{{ just_executable() }}" --justfile "{{ justfile() }}" --list --unsorted

[doc("Install speclink in the pinned version")]
tools:
    go install github.com/worldiety/speclink/cmd/speclink@{{ SPECLINK_VERSION }}

[doc("gofmt and go vet, including the E2E tests")]
lint:
    @files="$(gofmt -l $(git ls-files --cached --others --exclude-standard '*.go'))"; \
    if [ -n "$files" ]; then printf 'not formatted with gofmt:\n%s\n' "$files"; exit 1; fi
    go vet ./...
    go vet -tags e2e ./e2e/...

[doc("All tests with the race detector")]
test:
    go test -race -count=1 ./...

[doc("Check the requirement tree alone")]
requirements:
    {{ SPECLINK }} requirements -root . ./requirements/...

[doc("Check the requirements, then an evidence run of all tests")]
verify: && evidence-check
    {{ SPECLINK }} verify -root . ./...

# As in wdyhub: back up the lock file, feed the tests to speclink, restore
# it on failure; afterwards the lock file must not differ.
[doc("Feed all tests to speclink; fails if speclink.lock differs afterwards")]
[script]
evidence-check:
    before=$(mktemp); run=$(mktemp); trap 'rm -f "$before" "$run"' EXIT
    json="{{ TEST_JSON }}"
    if [ -n "$json" ]; then mkdir -p "$(dirname "$json")"; fi
    if [ -f speclink.lock ]; then cp speclink.lock "$before"; else : > "$before"; fi
    if ! go test -count=1 -timeout 30m -json ./... | tee "$run" ${json:+"$json"} | {{ SPECLINK }} evidence -root .; then
        if [ -s "$before" ]; then cp "$before" speclink.lock; fi
        { grep '"Action":"fail"' "$run" || true; } | sed -E 's/.*"Package":"([^"]*)"(,"Test":"([^"]*)")?.*/FAIL \1 \3/' | sort -u >&2
        echo "the test run failed; speclink.lock stays as it was before" >&2
        exit 1
    fi
    if [ -s "$before" ] && ! cmp -s "$before" speclink.lock; then
        diff -u "$before" speclink.lock || true
        echo "speclink.lock does not match this test run; review the new version and commit it too" >&2
        exit 1
    fi

[doc("Specification as Markdown  (build/SPECIFICATION.md)")]
spec:
    @mkdir -p {{ BUILD }}
    {{ SPECLINK }} generate -root . -out {{ BUILD }}/SPECIFICATION.md ./...

[doc("Build wdyapt for this system  (build/bin/wdyapt)")]
build:
    CGO_ENABLED=0 go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X {{ VERSION_PKG }}.current={{ FULL_VERSION }}" -o {{ BUILD }}/bin/wdyapt ./cmd/wdyapt

[doc("For linux and darwin, amd64 and arm64  (build/bin/<os>_<arch>/)")]
[script]
build-cross:
    for os in {{ OSES }}; do for arch in {{ ARCHES }}; do
        out="{{ BUILD }}/bin/${os}_$arch/"; mkdir -p "$out"
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
            -ldflags "-s -w -X {{ VERSION_PKG }}.current={{ FULL_VERSION }}" -o "$out" ./cmd/wdyapt
    done; done

[doc("Build twice (second build with an empty cache) and compare")]
[script]
release-check:
    just build-cross && rm -rf {{ BUILD }}/first && mv {{ BUILD }}/bin {{ BUILD }}/first
    GOCACHE="$(mktemp -d)" just build-cross
    (cd {{ BUILD }}/first && find . -type f -exec sha256sum {} +) | sort > {{ BUILD }}/first.sha256
    (cd {{ BUILD }}/bin && sha256sum -c ../first.sha256)

[doc("E2E tests in the Docker testbed (UBUNTU=24.04 checks the older version)")]
test-e2e:
    UBUNTU="{{ UBUNTU }}" e2e/testbed/run.sh -tags e2e -count=1 -v ./e2e/...

[doc("E2E tests on Ubuntu 24.04 and 26.04")]
test-e2e-all:
    just UBUNTU=24.04 test-e2e
    just UBUNTU=26.04 test-e2e

[doc("Check dependencies against the allowed exception")]
deps-check:
    go test -count=1 ./internal/depcheck

[doc("Empty the build directory")]
clean:
    rm -rf {{ BUILD }}
```

(`sha256sum` exists on macOS as `shasum -a 256`; `release-check` runs in
the CI under Linux. Adjust locally on macOS if needed.)

---

## Appendix E: Protocol reference

| Topic | Source |
|---|---|
| Debian binary package, control fields, versions | deb(5), deb-control(5), Debian Policy chapters 5 and 7, dpkg `lib/dpkg/version.c` (verrevcmp) |
| Repository format | https://wiki.debian.org/DebianRepository/Format |
| OpenPGP | RFC 9580 (v4 parts as in RFC 4880), cleartext signature chapter 7, armor chapter 6, S2K chapter 3.7, EdDSALegacy chapter 5.5.5.5 |
| SSH | RFC 4250, 4251, 4252, 4253, 4254, 4256 (keyboard-interactive), 4344 (CTR), 5647 (GCM), 5656 (ECC), 8308 (ext-info), 8332 (rsa-sha2), 8709 (ed25519), 8731 (curve25519), 3526 (DH groups), 8268 (group14-sha256, group16-sha512) |
| OpenSSH extensions | `PROTOCOL` (aes-gcm, etm, strict kex, posix-rename, fsync, limits), `PROTOCOL.agent`, `PROTOCOL.key` (openssh-key-v1) in the OpenSSH source tree |
| ML-KEM hybrid | draft-ietf-sshm-mlkem-hybrid-kex; `crypto/mlkem` |
| SFTP | draft-ietf-secsh-filexfer-02 (version 3) |
| known_hosts | sshd(8) section SSH_KNOWN_HOSTS FILE FORMAT |

SSH message numbers: DISCONNECT 1, IGNORE 2, UNIMPLEMENTED 3, DEBUG 4,
SERVICE_REQUEST 5, SERVICE_ACCEPT 6, EXT_INFO 7, KEXINIT 20, NEWKEYS 21,
KEX 30/31 (ECDH/DH/hybrid INIT/REPLY), USERAUTH_REQUEST 50, FAILURE 51,
SUCCESS 52, BANNER 53, 60 (PK_OK / PASSWD_CHANGEREQ / INFO_REQUEST), 61
(INFO_RESPONSE), GLOBAL_REQUEST 80, REQUEST_SUCCESS 81, REQUEST_FAILURE 82,
CHANNEL_OPEN 90, OPEN_CONFIRMATION 91, OPEN_FAILURE 92, WINDOW_ADJUST 93,
DATA 94, EXTENDED_DATA 95, EOF 96, CLOSE 97, REQUEST 98, SUCCESS 99, FAILURE 100.
