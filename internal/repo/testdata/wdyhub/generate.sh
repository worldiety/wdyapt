#!/usr/bin/env bash
# Generates a repository state in the wdyhub format with the wdyhub tool
# itself (cmd/internal/release, only run, nothing changed) and signs it like
# publish.sh with gpg in an Ubuntu container.
#
#   WDYHUB=/path/to/wdyhub internal/repo/testdata/wdyhub/generate.sh
#
# The programs in the packages are only ELF headers followed by the version;
# "release deb" checks nothing more. The result is checked in.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
wdyhub="${WDYHUB:?set WDYHUB to a checkout of wdyhub}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

programs="controlplane managementplane runner proxy web builder"
epoch=1791000000

# fakebin ARCH VERSION: ELF header (64 bit, little endian), then the version.
fakebin() {
	local machine
	case "$1" in amd64) machine='\x3e\x00' ;; arm64) machine='\xb7\x00' ;; esac
	printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00'"$machine"'\x01\x00\x00\x00'
	printf '\x00%.0s' $(seq 1 40)
	printf '\x40\x00\x38\x00\x00\x00\x40\x00\x00\x00\x00\x00'
	printf 'version %s end' "$2"
}

build() { # CHANNEL VERSION PUBLISHED OUT
	rm -rf "$work/bin" "$work/env" "$work/pkg"
	for arch in amd64 arm64; do
		mkdir -p "$work/bin/linux_$arch"
		for p in $programs; do fakebin "$arch" "$2" > "$work/bin/linux_$arch/$p"; chmod 0755 "$work/bin/linux_$arch/$p"; done
	done
	mkdir -p "$work/env"
	for p in $programs; do printf '# Environment of "%s run".\n\n#WDYHUB_DATA=./%s.d\n' "$p" "$p" > "$work/env/$p.env"; done
	(cd "$wdyhub" && go run ./cmd/internal/release deb --version "$2" --epoch "$epoch" --bin "$work/bin" --env "$work/env" --out "$work/pkg" >/dev/null)
	(cd "$wdyhub" && go run ./cmd/internal/release repo --channel "$1" --version "$2" --epoch "$((epoch + $5))" --packages "$work/pkg" --published "$3" --out "$4" >/dev/null)
}

rm -rf "$here/repo" "$here/key"
mkdir -p "$here/repo"
build stable 1.4.0 none "$work/out1" 0
cp -R "$work/out1/pool" "$work/out1/dists" "$here/repo/"
build dev 1.5.0~dev.20261019120000.abcdef12 "$here/repo" "$work/out2" 60
cp -R "$work/out2/pool" "$work/out2/dists" "$here/repo/"

# Sign like publish.sh: InRelease and Release.gpg with SHA512.
docker run --rm -v "$here:/w" ubuntu:24.04 bash -c '
	set -e
	apt-get update -qq >/dev/null && apt-get install -y -qq gnupg >/dev/null
	export GNUPGHOME=$(mktemp -d)
	gpg --batch --passphrase "" --quick-gen-key "wdyhub fixture <fixture@example.com>" ed25519 sign never 2>/dev/null
	mkdir -p /w/key
	gpg --armor --export > /w/key/public.asc
	gpg --batch --pinentry-mode loopback --passphrase "" --armor --export-secret-keys > /w/key/secret.asc
	for d in /w/repo/dists/*; do
		gpg --batch --yes --digest-algo SHA512 --clearsign -o "$d/InRelease" "$d/Release"
		gpg --batch --yes --digest-algo SHA512 --detach-sign --armor -o "$d/Release.gpg" "$d/Release"
	done
	chmod -R a+rX /w/key /w/repo
'
