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
