# Security Policy

## Threat Model

`1password-passkey-export` handles your highest-sensitivity credentials: your 1Password Master Password, Secret Key, decrypted vault items, and WebAuthn passkey private keys.

### Design Principles

- **Offline-first & read-only:** In default `--source sqlite` mode, zero network connections are made and `1password.sqlite` is opened read-only (`mode=ro`, `query_only(1)`). If a non-empty `-wal` sidecar prevents direct read-only open, the database and sidecars are copied to a `0700` temporary directory for WAL replay and deleted immediately on exit.
- **No telemetry or external services:** The tool never phones home, logs analytics, or sends data anywhere except the configured 1Password sign-in host when `--source cloud` is explicitly used.
- **Strict host & transport validation (cloud mode):** `--source cloud` restricts sign-in hosts to `*.1password.com`, `*.1password.ca`, and `*.1password.eu` over HTTPS with redirects disabled and verified TLS, enforces a minimum PBKDF2 iteration floor (`100,000`) and upper bound (`10,000,000`), verifies mutual SRP-6a proofs, and requires AES-256-GCM encrypted server responses after authentication.
- **Exclusive file creation (`0600`):** Output files are created exclusively with `O_CREAT|O_EXCL` and `0600` permissions (refusing symlinks and refusing to overwrite existing files unless `--force` is explicitly passed).
- **Strong KDBX 4 encryption:** Generated `.kdbx` files use KDBX 4 with Argon2 KDF parameters (64 MiB memory, 3 iterations, parallelism 2) rather than weak defaults.
- **Best-effort memory wiping:** Derived symmetric keys, decrypted JSON buffers, RSA private components, and SRP exponents are zeroed after use. Note that Go's garbage collector and immutable `string` values mean memory zeroing in Go is best-effort rather than guaranteed against live memory forensics.

### Operational Warnings

1. **Plaintext exports (`bitwarden`, `cxf`):** Bitwarden unencrypted JSON and FIDO CXF JSON contain **raw passkey private keys, passwords, and TOTP seeds in plaintext**. Import them promptly and delete them immediately afterward.
2. **File permissions on Windows:** Unix `0600` permissions do not map to restrictive NTFS ACLs on Windows. Write exports to a private user directory and remove them immediately after import.
3. **Deleting files on SSDs / CoW filesystems:** Standard `rm` or `shred` does not guarantee physical erasure on SSDs, APFS, Btrfs, or ZFS due to wear-leveling and copy-on-write snapshots. Prefer full-disk encryption (FileVault / BitLocker / LUKS) and write temporary exports to a RAM-backed tmpfs (`/dev/shm` on Linux) when possible.
4. **CLI flags vs. environment variables / prompts:** Avoid passing `--password`, `--secret-key`, or `--kdbx-password` as command-line arguments — they appear in shell history and process lists (`ps` / `/proc/*/cmdline`). Use interactive hidden prompts or environment variables (`OP_PASSWORD`, `OP_SECRET_KEY`, `OP_TOTP`, `KDBX_PASSWORD`).
5. **Review `inspect` output before sharing:** `inspect` never outputs private keys, passwords, or TOTP secrets, but it does print vault names, item titles, and Relying Party IDs (`rpId`). Redact personal site names before posting in public bug reports.
6. **`--allow-any-host`:** Only for local testing. Because 1Password's SRP client sends its proof first, pointing cloud mode at an untrusted server hands over SRP material that enables offline password guessing.

## Reporting a Vulnerability

Please report security issues privately using **GitHub Private Vulnerability Reporting** on this repository's Security tab rather than opening a public issue. Never include real Secret Keys, passwords, `1password.sqlite` files, or passkey private keys in any report.
