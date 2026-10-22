# SSH test keys

Generated with `ssh-keygen` from OpenSSH 10.2 (Ubuntu 26.04), for tests only:

| File | Content |
|---|---|
| `k_ed25519`, `k_ecdsa` (P-384), `k_rsa` (3072) | OpenSSH format, unencrypted |
| `k_rsa_pem` | RSA as PKCS#1 (`-m PEM`) |
| `k_ecdsa_pkcs8` | ECDSA as PKCS#8 (`-m PKCS8`) |
| `k_encrypted` | Ed25519 with a passphrase; wdyapt rejects it with an explanation |
| `*.pub` | the public keys |

    ssh-keygen -t ed25519 -N "" -f k_ed25519
    ssh-keygen -t ecdsa -b 384 -N "" -f k_ecdsa
    ssh-keygen -t rsa -b 3072 -N "" -f k_rsa
    ssh-keygen -t ed25519 -N "secret phrase" -f k_encrypted
    cp k_rsa k_rsa_pem && ssh-keygen -p -N "" -m PEM -f k_rsa_pem
    cp k_ecdsa k_ecdsa_pkcs8 && ssh-keygen -p -N "" -m PKCS8 -f k_ecdsa_pkcs8
