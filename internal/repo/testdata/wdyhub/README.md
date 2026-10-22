# State in the wdyhub format

A repository as the wdyhub tool (`cmd/internal/release`) writes it: suites
`stable` (version 1.4.0) and `dev` (1.5.0~dev…), component `main`,
architectures `amd64` and `arm64`, six `wdyhub-*` packages each. Generated
with `generate.sh` from a checkout of wdyhub (only run there, nothing
changed); the programs in the packages are ELF headers followed by the
version. Signed like `publish.sh` with gpg (InRelease and Release.gpg,
SHA512) with the test key in `key/`.

The tests use it to check that wdyapt reads, verifies and continues this
state without changing header fields or foreign entries (chapter 9 of the
implementation plan (doc/implementation-plan.md)).
