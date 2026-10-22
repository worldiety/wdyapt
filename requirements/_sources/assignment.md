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
