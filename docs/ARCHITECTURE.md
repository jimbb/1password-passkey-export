# Architecture

`1password-passkey-export` reads 1Password vault items directly from either 1Password 8's local SQLite cache or 1Password's cloud API, decrypts them locally using 1Password's documented E2EE cryptography, normalizes WebAuthn passkeys, and emits standard target formats.

## High-Level Data Flow

```text
  ┌─────────────────────────┐       ┌────────────────────────────┐
  │  Offline 1password.sqlite│       │  1Password Cloud API       │
  │  (internal/opsqlite)     │       │  (internal/opcloud)        │
  │  v61+ & pre-v61 schemas  │       │  SRP-6a + X-AgileBits-MAC  │
  └────────────┬─────────────┘       └─────────────┬──────────────┘
               │ encrypted keysets, vaults, items  │
               └────────────────┬──────────────────┘
                                ▼
                  ┌──────────────────────────┐
                  │  1Password Cryptography   │
                  │  (internal/opcrypto)      │
                  │  2SKD → AUK → Keysets →  │
                  │  RSA-OAEP → Vault Keys → │
                  │  AES-256-GCM Items        │
                  └─────────────┬────────────┘
                                │ raw overview + details JSON
                                ▼
                  ┌──────────────────────────┐
                  │  Item & Passkey Model     │
                  │  (internal/opmodel)       │
                  │  overview.passkey +       │
                  │  details.passkey +        │
                  │  Key Normalization→PKCS#8 │
                  └─────────────┬────────────┘
                                │ canonical opmodel.AccountExport
               ┌────────────────┼────────────────┐
               ▼                ▼                ▼
       ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
       │  Bitwarden   │ │  FIDO CXF    │ │  KeePassXC   │
       │  JSON        │ │  1.0 JSON    │ │  KDBX 4      │
       └──────────────┘ └──────────────┘ └──────────────┘
```

## 1. 1Password Cryptography (`internal/opcrypto`)

- **Two-Secret Key Derivation (2SKD):**
  1. `p = NFKD(trim(password))`
  2. `email_norm = lower(NFKD(trim(email)))`
  3. `stretched_salt = HKDF-SHA256(ikm=salt, salt=email_norm, info=label, len=32)`
  4. `k_m = PBKDF2-HMAC-SHA256(p, stretched_salt, iterations, 32)`
  5. `k_A = HKDF-SHA256(ikm=secret, salt=accountID, info=format, len=32)`
  6. `key = k_m XOR k_A`
  Used with `label = "PBES2g-HS256"` for the Account Unlock Key (AUK) and `label = "SRPg-4096"` for cloud SRP-x.
- **Keyset Chain:** Primary keysets (`encryptedBy == "mp"`) encrypt a symmetric JWK (`encSymKey`) with AUK via AES-256-GCM; that symmetric key decrypts an RSA private JWK (`encPriKey`). Chained keysets are unwrapped iteratively using their parent's symmetric or RSA key.
- **Vaults & Items:** Each vault's `enc_vault_key` is unwrapped with the matching keyset's RSA-OAEP (`SHA-1` or `SHA-256`) or symmetric key. Item `overview` and `details` blobs are decrypted with the vault key via AES-256-GCM.

## 2. Offline SQLite Reader (`internal/opsqlite`)

1Password 8's `1password.sqlite` has two main layout eras, both auto-detected via `sqlite_master` / `pragma_table_info`:

- **Modern schema (v61+):**
  - `accounts (account_uuid, data)`
  - `objects_associated (type=36, account_uuid, key_name, data)` for keysets
  - `vaults (account_uuid, vault_uuid, data)`
  - `items (account_uuid, vault_uuid, item_uuid, data)` (overview + details embedded)
- **Legacy 1Password 8 schema (pre-v61):**
  - `accounts (id, account_uuid, data)`
  - `objects_associated (associated_account, type=36)` or `account_objects (object_type='keyset')` (with JSON-stringified envelopes)
  - `account_objects (object_type='vault')`
  - `item_overviews` joined with `item_details`

The database is always opened read-only (`mode=ro`, `query_only(1)`). If a non-empty `-wal` file prevents direct read-only opening, the DB and sidecars are copied into a private `0700` temp directory so WAL-resident passkeys are preserved without modifying the original database.

## 3. Cloud Client (`internal/opcloud`)

Implements 1Password's current SRP-6a flow (`SRPg-4096` over RFC 5054 4096-bit Group 16, `g = 5`):
1. `POST v3/auth/start` (handling `device-not-registered` → `POST v1/device` and `device-deleted` → `PUT v1/device/{uuid}/reauthorize`).
2. `POST v2/auth` (`userA` → `userB`) and `POST v2/auth/confirm-key` (mutual proof verification).
3. Subsequent requests are AES-256-GCM encrypted under the SRP session key and signed with `X-AgileBits-MAC` (`HMAC-SHA256` with derived MAC key).
4. `POST v2/auth/complete` (+ `POST v1/auth/mfa` for authenticator-app TOTP 2FA).
5. `GET v1/account/keysets`, `GET v1/account?attrs=me,vaults`, paginated `GET v1/vault/{uuid}/{batch}/items`, and `PUT v1/session/signout` on exit.

## 4. 1Password Passkey Storage & Normalization (`internal/opmodel`)

1Password stores WebAuthn passkeys across two decrypted JSON blobs on each item:

- **`overview.passkey`:** `credentialId` (base64url), `rpId`, `userHandle` (base64url), optional `prf.numCreds`.
- **`details.passkey`:** `type` (`"webauthn"`), `createdAt` (unix timestamp), `privateKey` (base64url), `alg` (e.g. `"ES256"`), `userHandle` (base64url), optional `prf` (`{ alg: "HMAC_SHA256", credWithUv }`).

`NormalizePrivateKey` converts any supported encoding (PKCS#8 DER, SEC1 EC DER, PKCS#1 RSA DER, RFC 9052 CBOR COSE Key, JSON JWK, raw EC/Ed25519 scalar, or PEM) into canonical **PKCS#8 DER** and **PKCS#8 PEM**, strictly validating EC scalar ranges and public point consistency without ever leaking key bytes into error messages.

## 5. Target Exporters (`internal/exporter`)

| Target | Credential ID | Private Key | Extra Notes |
|---|---|---|---|
| **Bitwarden JSON** | `"b64." + base64url(raw)` | `base64url(PKCS#8 DER)` | `login.fido2Credentials[]`, string `counter`/`discoverable`, `.000Z` UTC timestamps; multi-passkey items split so each sits at index `0` |
| **FIDO CXF 1.0 JSON** | `base64url(raw)` | `base64url(PKCS#8 DER)` | `version: {1, 0}`, `accounts`, `collections`, `passkey` + `fido2Extensions.hmacCredentials`, `basic-auth`, `totp`, `ssh-key`, `note`, `custom-fields` |
| **KeePassXC KDBX 4** | `KPEX_PASSKEY_CREDENTIAL_ID` (`base64url(raw)`) | `KPEX_PASSKEY_PRIVATE_KEY_PEM` (PKCS#8 PEM) | KDBX 4 encrypted with Argon2 (64 MiB), `KPEX_PASSKEY_RELYING_PARTY`, `KPEX_PASSKEY_USERNAME`, `KPEX_PASSKEY_USER_HANDLE`, `BE`/`BS = "1"`, `Passkey` tag |
