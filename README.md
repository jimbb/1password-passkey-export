# 1password-passkey-export

Export WebAuthn passkeys (and optionally full logins/vault items) directly from **1Password** without needing an iPhone, Android device, or the `op` CLI.

> **Disclaimer:** This is an independent, unofficial open-source project and is **not** affiliated with, endorsed by, or supported by AgileBits Inc. (1Password), Bitwarden Inc., the KeePassXC Team, or the FIDO Alliance. All product names and trademarks belong to their respective owners. Provided "as is" under the MIT License without warranty — always verify imported credentials before removing your originals.

## Features

- **Two sources (desktop/CLI only — no phone required):**
  1. **Offline `1password.sqlite` (`--source sqlite`, default):** Reads 1Password 8's local SQLite cache read-only (supports both modern v61+ and pre-v61 schemas across Linux, macOS, and Windows), derives keys locally with 2SKD (`PBES2g-HS256` + AES-256-GCM + RSA-OAEP), with **zero network calls**.
  2. **Direct Cloud Login (`--source cloud`):** Talks directly to 1Password's API (`my.1password.com`, `my.1password.ca`, `my.1password.eu`, or `*.1password.{com,ca,eu}` team domains) via SRP-6a (`SRPg-4096`), `X-AgileBits-MAC`, and authenticator-app TOTP 2FA, then decrypts vaults locally and signs out. *(Unofficial API client — triggers a "new device sign-in" notification email and may violate 1Password's Terms of Service; prefer offline `--source sqlite` whenever possible.)*
- **Three export formats:**
  - **Bitwarden unencrypted JSON (`--format bitwarden`):** Bitwarden JSON with `login.fido2Credentials[]` (`b64.<base64url>` credential IDs, base64url PKCS#8 DER private keys, `rpId`, `userHandle`, `userName`, `creationDate`, folders, URIs, TOTP, custom fields). Multi-passkey items are split into one login per passkey because Bitwarden clients only use `fido2Credentials[0]`.
  - **FIDO CXF 1.0 JSON (`--format cxf`):** FIDO Credential Exchange Format 1.0 JSON (`passkey` credentials + optional PRF `hmacCredentials`, `basic-auth`, `totp`, `ssh-key`, `note`, `custom-fields`).
  - **KeePassXC KDBX 4 (`--format kdbx`):** Encrypted KDBX 4 database (Argon2 KDF: 64 MiB memory, 3 iterations, parallelism 2) using KeePassXC 2.7.7+'s native `KPEX_PASSKEY_*` entry attributes (PKCS#8 PEM private key, base64url credential ID and user handle, relying party, username, `BE`/`BS` flags, `Passkey` tag).
  - **`--format all`:** Builds all three outputs in memory and writes `<prefix>.bitwarden.json`, `<prefix>.cxf.json`, and `<prefix>.kdbx` in one pass.
- **Redacted `inspect` mode:** Check passkey detection, algorithms, and key encodings on your `1password.sqlite` without printing or writing private keys, passwords, or TOTP secrets.
- **Pure Go / zero CGo:** Cross-compiles to single static binaries for Linux, macOS, and Windows.

## Installation

Requires **Go 1.26+** (no C compiler or CGo required).

### Install via `go install`

```bash
go install github.com/jimbb/1password-passkey-export/cmd/1p-passkey-export@latest
```

### Build from source

```bash
git clone https://github.com/jimbb/1password-passkey-export.git
cd 1password-passkey-export
go build -o 1p-passkey-export ./cmd/1p-passkey-export
```

Cross-compile for macOS or Windows:

```bash
GOOS=darwin  GOARCH=arm64 go build -o 1p-passkey-export-macos ./cmd/1p-passkey-export
GOOS=windows GOARCH=amd64 go build -o 1p-passkey-export.exe   ./cmd/1p-passkey-export
```

## Quick Start (Offline `1password.sqlite`)

Default 1Password 8 `1password.sqlite` locations (auto-detected if `--db` is omitted):

- **Linux:** `~/.config/1Password/data/1password.sqlite`
- **macOS:** `~/Library/Group Containers/2BUA8C4S2C.com.1password/Library/Application Support/1Password/Data/1password.sqlite`
- **Windows:** `%LOCALAPPDATA%\1Password\data\1password.sqlite`

### 1. List accounts in the database (no password needed)

```bash
./1p-passkey-export list-accounts --db /path/to/1password.sqlite
```

### 2. Inspect passkeys safely (redacted — no secrets printed)

```bash
./1p-passkey-export inspect --db /path/to/1password.sqlite
```

> **Privacy note:** `inspect` never outputs private keys, passwords, or TOTP seeds, but it does print vault names, item titles, and Relying Party domains (`rpId`). Redact personal titles/domains before sharing output in bug reports.

### 3. Export passkeys to Bitwarden JSON

```bash
./1p-passkey-export export \
  --db /path/to/1password.sqlite \
  --format bitwarden \
  --out bitwarden-passkeys.json
```

Then in Bitwarden Web Vault / Desktop / Browser Extension: **Tools → Import Data → Bitwarden (json)** → select `bitwarden-passkeys.json`.

### 4. Export all formats at once (Bitwarden + CXF 1.0 + KeePassXC KDBX 4)

```bash
./1p-passkey-export export \
  --db /path/to/1password.sqlite \
  --format all \
  --out my-passkeys
```

Useful flags:
- `--all-items` (or `--passkeys-only=false`): Export non-passkey logins, secure notes, and SSH keys alongside passkeys.
- `--vault "<name or uuid>"`: Limit export to a single vault.
- `--account "<uuid, email, or url>"`: Select a specific account when `1password.sqlite` holds multiple accounts.
- `--include-trashed`: Include archived/trashed items.
- `--force`: Replace an existing output file safely (refuses symlinks; by default existing files are never overwritten).

## Direct Cloud Login (`--source cloud`)

```bash
./1p-passkey-export export \
  --source cloud \
  --sign-in-address my.1password.com \
  --email you@example.com \
  --format bitwarden \
  --out bitwarden-passkeys.json
```

You will be prompted (with hidden terminal input) for your Secret Key, Master Password, and 6-digit authenticator-app TOTP code if 2FA is enabled. To avoid repeated "new device" emails across runs, a random 26-character device UUID is saved to `<user-config-dir>/1p-passkey-export/device-uuid` (override with `--device-uuid`).

**Environment variables** (preferred over `--password` / `--secret-key` / `--kdbx-password` CLI flags, which expose secrets in shell history and process listings):

- `OP_PASSWORD` — 1Password Master Password
- `OP_SECRET_KEY` — 1Password Secret Key (`A3-...`)
- `OP_TOTP` — 6-digit TOTP code for cloud 2FA
- `KDBX_PASSWORD` — Master password for generated `.kdbx` output

## Supported Targets & Known Limitations

- **1Password SQLite:** 1Password 8 modern (`v61+`) and legacy (`pre-v61`) schemas. Older 1Password 7 `.opvault` / `.agilekeychain` formats are not supported.
- **Bitwarden JSON:** Compatible with Bitwarden Web Vault, Desktop, and Browser Extensions supporting `login.fido2Credentials[]`.
- **FIDO CXF 1.0 JSON:** Follows FIDO Credential Exchange Format 1.0 (compatible with Bitwarden and KeePassXC CXF importers).
- **KeePassXC KDBX 4:** Tested against KeePassXC **2.7.7+** (`KPEX_PASSKEY_*` attributes).
- **Cloud mode limitations:** Only password + Secret Key + authenticator-app TOTP 2FA is implemented. Enterprise SSO / Unlock with Okta/Entra/Duo, hardware security keys (WebAuthn 2FA), and passkey-based 1Password sign-in are not supported in `--source cloud` — use offline `--source sqlite` for those accounts.

## Security Notes

See [SECURITY.md](SECURITY.md) for the full threat model and vulnerability reporting instructions. Key points:

- `1password.sqlite` is always opened read-only (`mode=ro`, `query_only(1)`). If a non-empty `-wal` file blocks direct read-only opening, the DB and its `-wal`/`-shm` sidecars are copied to a `0700` temporary directory for WAL replay and removed on exit.
- Output files are created exclusively (`O_CREAT|O_EXCL`) with `0600` permissions and refuse symlinks.
- **Plaintext exports (`bitwarden`, `cxf`) contain raw passkey private keys.** Delete them immediately after importing.
- **Windows:** Unix `0600` mode bits do not apply restrictive NTFS ACLs; export to a private directory and delete promptly.
- **SSDs / Copy-on-Write filesystems (APFS, Btrfs, ZFS):** Standard deletion or `shred` does not guarantee physical erasure. Use full-disk encryption and write temporary exports to a RAM-backed tmpfs (e.g., `/dev/shm` on Linux) when possible.

## Repository Layout

```text
cmd/1p-passkey-export/   CLI entry point (list-accounts, inspect, export)
internal/opcrypto/       2SKD, AES-256-GCM, RSA-OAEP, and keyset unwrapping
internal/opsqlite/       Offline 1Password 8 SQLite reader (v61+ and pre-v61)
internal/opcloud/        Direct 1Password cloud client (SRP-6a + X-AgileBits-MAC)
internal/opmodel/        Item/passkey extraction and private key normalization (→ PKCS#8)
internal/exporter/       Bitwarden JSON, FIDO CXF 1.0 JSON, and KeePassXC KDBX 4 writers
docs/ARCHITECTURE.md     Detailed cryptographic and format documentation
```

## Running Tests

```bash
go test -v -race ./...
go vet ./...
```

## License & Notices

Released under the [MIT License](LICENSE). See [NOTICE](NOTICE) for third-party attributions, protocol references, and trademark notices, and [CONTRIBUTING.md](CONTRIBUTING.md) if you want to help keep schemas up to date.
