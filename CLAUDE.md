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
