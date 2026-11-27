# Contributing

Contributions, bug reports, and schema updates (when 1Password evolves its local SQLite or passkey format) are welcome.

## Development Setup

- Go **1.26+** (pure Go — no CGo or C compiler required)

```bash
git clone https://github.com/jimbb/1password-passkey-export.git
cd 1password-passkey-export
go test -v -race ./...
go vet ./...
go build -o 1p-passkey-export ./cmd/1p-passkey-export
```

## Reporting a Passkey or SQLite Schema Issue

If `1p-passkey-export` fails to parse a passkey or database schema from a newer 1Password 8 release:

1. Run the redacted inspector first:
   ```bash
   ./1p-passkey-export inspect --db /path/to/1password.sqlite --json
   ```
2. **Review and redact personal item titles / `rpId` domains** before pasting the output into a GitHub issue. `inspect` never outputs private keys or passwords, but item titles and domains are still personal information.
3. Include your OS, 1Password version, and `schemaVersion` from `list-accounts --json` (redacting your email and account UUID).

## Security Rules for PRs

- Never commit `.sqlite`, `.kdbx`, `.json` exports, or real credentials — all test fixtures must use obviously synthetic values (e.g., `A3-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE-FFFFF`, `example.com`) or publicly attributed test vectors.
- Never print raw secret material or private key bytes in error messages, logs, or diagnostics.
- Keep `go test -race ./...` and `go vet ./...` passing on Linux, macOS, and Windows targets.
