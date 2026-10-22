#!/usr/bin/env bash
# Generates the test data of internal/openpgp with GnuPG in an Ubuntu
# container. gpg is only needed here, never for wdyapt itself.
#
#   internal/openpgp/testdata/generate.sh            (from the repository)
#
# The generated files are checked in; the script only runs when the test
# data is to be regenerated. Keys and timestamps change in the process.
set -euo pipefail

UBUNTU="${UBUNTU:-24.04}"
here="$(cd "$(dirname "$0")" && pwd)"

if [ "${1:-}" != "--inside" ]; then
	exec docker run --rm -v "$here:/out" "ubuntu:$UBUNTU" bash -c \
		"apt-get update -qq >/dev/null && apt-get install -y -qq gnupg >/dev/null && bash /out/generate.sh --inside"
fi

export GNUPGHOME="$(mktemp -d)"
cd /out
pass="correct horse battery staple"
gpg() { command gpg --batch --pinentry-mode loopback --passphrase "${PASS:-}" "$@"; }

gpg --version | head -1 > gnupg-version.txt

# Ed25519 without passphrase, as GnuPG creates it for signatures.
PASS= gpg --quick-gen-key "Test Ed25519 <ed25519@example.com>" ed25519 sign never
ed=$(command gpg --list-keys --with-colons ed25519@example.com | awk -F: '/^fpr/{print $10; exit}')
# Ed25519 with passphrase.
PASS="$pass" gpg --quick-gen-key "Test Protected <protected@example.com>" ed25519 sign never
prot=$(command gpg --list-keys --with-colons protected@example.com | awk -F: '/^fpr/{print $10; exit}')
# RSA-3072 without passphrase.
PASS= gpg --quick-gen-key "Test RSA <rsa@example.com>" rsa3072 sign never
rsa=$(command gpg --list-keys --with-colons rsa@example.com | awk -F: '/^fpr/{print $10; exit}')
# Primary key for certification only, signing subkey; exported with
# --export-secret-subkeys only a stub of the primary key remains.
PASS= gpg --quick-gen-key "Test Subkey <subkey@example.com>" ed25519 cert never
sub=$(command gpg --list-keys --with-colons subkey@example.com | awk -F: '/^fpr/{print $10; exit}')
PASS= gpg --quick-add-key "$sub" ed25519 sign never
PASS= gpg --quick-add-key "$sub" cv25519 encr never
# An expired key: it expires one second after generation.
PASS= gpg --quick-gen-key "Test Expired <expired@example.com>" ed25519 sign seconds=1
exp=$(command gpg --list-keys --with-colons expired@example.com | awk -F: '/^fpr/{print $10; exit}')

PASS= gpg --armor --export-secret-keys "$ed" > ed25519.secret.asc
PASS= gpg --armor --export "$ed" > ed25519.public.asc
PASS= gpg --export "$ed" > ed25519.public.gpg
PASS="$pass" gpg --armor --export-secret-keys "$prot" > protected.secret.asc
echo -n "$pass" > protected.passphrase
PASS= gpg --armor --export-secret-keys "$rsa" > rsa3072.secret.asc
PASS= gpg --armor --export "$rsa" > rsa3072.public.asc
PASS= gpg --armor --export-secret-subkeys "$sub" > subkey.secret.asc
PASS= gpg --armor --export "$sub" > subkey.public.asc
PASS= gpg --armor --export-secret-keys "$exp" > expired.secret.asc

cat > Release <<'REL'
Origin: worldiety
Label: worldiety Hub
Suite: stable
Codename: stable
Date: Mon, 19 Oct 2026 10:00:00 UTC
Architectures: amd64 arm64
Components: main
Description: Test repository
Changelogs: no
MD5Sum:
 d41d8cd98f00b204e9800998ecf8427e 0 main/binary-amd64/Packages
SHA256:
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages
-dashed line that must be escaped:
REL

PASS= gpg --digest-algo SHA512 -u "$ed" --clearsign -o InRelease.ed25519 Release
PASS= gpg --digest-algo SHA512 -u "$ed" --armor --detach-sign -o Release.gpg.ed25519 Release
PASS= gpg --digest-algo SHA512 -u "$rsa" --clearsign -o InRelease.rsa3072 Release
PASS= gpg --digest-algo SHA256 -u "$rsa" --armor --detach-sign -o Release.gpg.rsa3072 Release
PASS= gpg --digest-algo SHA512 -u "$ed" -u "$rsa" --clearsign -o InRelease.both Release
PASS= gpg --digest-algo SHA512 -u "${sub}" --armor --detach-sign -o Release.gpg.subkey Release
PASS= gpg --digest-algo SHA1 -u "$ed" --armor --detach-sign -o Release.gpg.sha1 Release

command gpg --with-colons --fingerprint --fingerprint --list-keys > fingerprints.txt
cat > keys.txt <<KEYS
ed25519 $ed
protected $prot
rsa3072 $rsa
subkey $sub
expired $exp
KEYS
chmod 0644 ./*
