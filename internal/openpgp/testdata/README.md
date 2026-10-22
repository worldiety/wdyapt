# GnuPG test data

GnuPG generated these files so that the tests of `internal/openpgp` can
check that wdyapt reads keys and signatures from GnuPG and vice versa. gpg is
only needed to generate them, never for wdyapt itself.

Generated with `generate.sh` in an `ubuntu:24.04` container; the GnuPG
version is in `gnupg-version.txt`. Another run generates new keys and
timestamps; the tests must still pass afterwards.

| File | Content |
|---|---|
| `ed25519.*` | Ed25519 (EdDSA legacy), without passphrase; secret, public ASCII and binary |
| `protected.secret.asc`, `protected.passphrase` | Ed25519 with passphrase |
| `rsa3072.*` | RSA 3072, without passphrase |
| `subkey.*` | Primary key for certification only, signing and encryption subkeys; secret with `--export-secret-subkeys` (primary key as stub) |
| `expired.secret.asc` | Ed25519, expired one second after generation |
| `Release` | A Release with a line that starts with `-` |
| `InRelease.*`, `Release.gpg.*` | Cleartext and detached signatures from gpg; `both` with two keys, `sha1` with SHA-1 |
| `keys.txt` | Name and fingerprint per key |
| `fingerprints.txt` | `gpg --with-colons --fingerprint --fingerprint --list-keys` |

The keys are pure test keys without any value.
