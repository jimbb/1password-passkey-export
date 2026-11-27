package opsqlite

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
	"github.com/jimbb/1password-passkey-export/internal/opmodel"
)

type syntheticFixture struct {
	email       string
	password    string
	secretKey   string
	accountUUID string
	vaultUUID   string
	itemUUID    string
	credID      []byte
	userHandle  []byte
	ecKey       *ecdsa.PrivateKey
	ksUUID      string
	encKsSym    *opcrypto.EncryptedObject
	encKsPri    *opcrypto.EncryptedObject
	encVaultKey *opcrypto.EncryptedObject
	encAttrs    *opcrypto.EncryptedObject
	encOverview *opcrypto.EncryptedObject
	encDetails  *opcrypto.EncryptedObject
}

func makeFixture(t *testing.T) *syntheticFixture {
	t.Helper()
	email := "test@example.com"
	password := "Test-Master-Pass-123!"
	skStr := "A3-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE-FFFFF"
	sk, err := opcrypto.ParseSecretKey(skStr)
	if err != nil {
		t.Fatal(err)
	}

	salt := bytes.Repeat([]byte{0x19}, 16)
	auk, err := opcrypto.Compute2SKD(sk, password, email, opcrypto.AlgPBES2gHS256, salt, 100)
	if err != nil {
		t.Fatal(err)
	}

	ksUUID := "keyset-uuid-1"
	ksSym := make([]byte, 32)
	_, _ = rand.Read(ksSym)
	ksRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ksSymJWK, _ := json.Marshal(opcrypto.JWK{Kty: "oct", Kid: ksUUID, Alg: "A256GCM", K: opcrypto.Base64URLEncode(ksSym)})
	encKsSym, _ := opcrypto.EncryptAESGCM("mp", auk, "b5+jwk+json", ksSymJWK)
	encKsSym.Alg = opcrypto.AlgPBES2gHS256
	encKsSym.P2s = opcrypto.Base64URLEncode(salt)
	encKsSym.P2c = 100

	ksPriJWK, _ := json.Marshal(opcrypto.JWK{
		Kty: "RSA", Kid: ksUUID, Alg: "RSA-OAEP",
		N: opcrypto.Base64URLEncode(ksRSA.N.Bytes()),
		E: opcrypto.Base64URLEncode(big.NewInt(int64(ksRSA.E)).Bytes()),
		D: opcrypto.Base64URLEncode(ksRSA.D.Bytes()),
		P: opcrypto.Base64URLEncode(ksRSA.Primes[0].Bytes()),
		Q: opcrypto.Base64URLEncode(ksRSA.Primes[1].Bytes()),
	})
	encKsPri, _ := opcrypto.EncryptAESGCM(ksUUID, ksSym, "b5+jwk+json", ksPriJWK)

	vaultUUID := "vault-uuid-private"
	vaultKey := make([]byte, 32)
	_, _ = rand.Read(vaultKey)
	vaultKeyJWK, _ := json.Marshal(opcrypto.JWK{Kty: "oct", Kid: vaultUUID, Alg: "A256GCM", K: opcrypto.Base64URLEncode(vaultKey)})
	vaultKeyCT, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &ksRSA.PublicKey, vaultKeyJWK, nil)
	encVaultKey := &opcrypto.EncryptedObject{Kid: ksUUID, Enc: "RSA-OAEP", Cty: "b5+jwk+json", Data: opcrypto.Base64URLEncode(vaultKeyCT)}
	encAttrs, _ := opcrypto.EncryptAESGCM(vaultUUID, vaultKey, "b5+json", []byte(`{"name":"Personal"}`))

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8DER, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	credID := []byte("1password-test-credential-id-32b")
	userHandle := []byte("user-handle-sqlite")

	ovJSON, _ := json.Marshal(map[string]any{
		"title": "WebAuthn Demo",
		"url":   "https://webauthn.io",
		"ainfo": "alice",
		"passkey": map[string]any{
			"credentialId": opcrypto.Base64URLEncode(credID),
			"rpId":         "webauthn.io",
			"userHandle":   opcrypto.Base64URLEncode(userHandle),
		},
	})
	detJSON, _ := json.Marshal(map[string]any{
		"fields": []map[string]any{
			{"designation": "username", "type": "T", "value": "alice"},
		},
		"passkey": map[string]any{
			"type":       "webauthn",
			"createdAt":  1732000000,
			"privateKey": opcrypto.Base64URLEncode(pkcs8DER),
			"alg":        "ES256",
			"userHandle": opcrypto.Base64URLEncode(userHandle),
		},
	})
	encOverview, _ := opcrypto.EncryptAESGCM(vaultUUID, vaultKey, "b5+json", ovJSON)
	encDetails, _ := opcrypto.EncryptAESGCM(vaultUUID, vaultKey, "b5+json", detJSON)

	return &syntheticFixture{
		email: email, password: password, secretKey: skStr,
		accountUUID: "acct-uuid-1", vaultUUID: vaultUUID, itemUUID: "item-uuid-1",
		credID: credID, userHandle: userHandle, ecKey: ecKey, ksUUID: ksUUID,
		encKsSym: encKsSym, encKsPri: encKsPri, encVaultKey: encVaultKey,
		encAttrs: encAttrs, encOverview: encOverview, encDetails: encDetails,
	}
}

func TestExportModernV61SQLite(t *testing.T) {
	fx := makeFixture(t)
	dbPath := filepath.Join(t.TempDir(), "1password.sqlite")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE config (name TEXT PRIMARY KEY, value TEXT)`,
		`INSERT INTO config VALUES ('version', '63')`,
		`CREATE TABLE accounts (account_uuid TEXT PRIMARY KEY, data BLOB)`,
		`CREATE TABLE objects_associated (type INT, account_uuid TEXT, key_name TEXT, data BLOB, vault_uuid TEXT, item_uuid TEXT)`,
		`CREATE TABLE vaults (account_uuid TEXT, vault_uuid TEXT, data BLOB)`,
		`CREATE TABLE items (account_uuid TEXT, vault_uuid TEXT, item_uuid TEXT, local_edit_count INT, rejection_reason INT, version INT, data BLOB)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}

	acctData, _ := json.Marshal(map[string]any{
		"account_uuid": fx.accountUUID, "user_email": fx.email, "user_name": "Alice",
		"sign_in_url": "https://my.1password.com", "account_type": "I",
	})
	_, _ = db.Exec(`INSERT INTO accounts VALUES (?, ?)`, fx.accountUUID, acctData)

	ksData, _ := json.Marshal(map[string]any{
		"sn": 1, "encryptedBy": "mp", "encSymKey": fx.encKsSym, "encPriKey": fx.encKsPri,
	})
	_, _ = db.Exec(`INSERT INTO objects_associated VALUES (36, ?, ?, ?, NULL, NULL)`, fx.accountUUID, fx.ksUUID, ksData)

	vData, _ := json.Marshal(map[string]any{
		"vault_type": "P", "enc_vault_key": fx.encVaultKey, "enc_attrs": fx.encAttrs,
	})
	_, _ = db.Exec(`INSERT INTO vaults VALUES (?, ?, ?)`, fx.accountUUID, fx.vaultUUID, vData)

	iData, _ := json.Marshal(map[string]any{
		"category_uuid": "001", "created_at": 1732000000, "updated_at": 1732000500,
		"is_favorite": true, "state": 0, "overview": fx.encOverview, "details": fx.encDetails,
	})
	_, _ = db.Exec(`INSERT INTO items VALUES (?, ?, ?, 0, 0, 1, ?)`, fx.accountUUID, fx.vaultUUID, fx.itemUUID, iData)
	db.Close()

	accts, err := ListAccounts(dbPath)
	if err != nil || len(accts) != 1 || accts[0].SchemaVersion != 63 {
		t.Fatalf("ListAccounts: %+v, err=%v", accts, err)
	}

	exp, err := Export(Options{DBPath: dbPath, Password: fx.password, SecretKey: fx.secretKey})
	if err != nil {
		t.Fatalf("Export v61+: %v", err)
	}
	verifyFixtureExport(t, exp, fx)
}

func TestExportLegacyPreV60SQLite(t *testing.T) {
	fx := makeFixture(t)
	dbPath := filepath.Join(t.TempDir(), "1password-legacy.sqlite")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE config (name TEXT PRIMARY KEY, value TEXT)`,
		`INSERT INTO config VALUES ('version', '59')`,
		`CREATE TABLE accounts (id INTEGER PRIMARY KEY, account_uuid TEXT, data BLOB)`,
		`CREATE TABLE account_objects (id INTEGER PRIMARY KEY, account_id INTEGER, uuid TEXT, object_type TEXT, data BLOB)`,
		`CREATE TABLE item_overviews (id INTEGER PRIMARY KEY, vault_id INTEGER, uuid TEXT, created_at INT, updated_at INT, template_uuid TEXT, favorite INT, trashed INT, enc_overview BLOB)`,
		`CREATE TABLE item_details (id INTEGER PRIMARY KEY, enc_details BLOB)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}

	acctData, _ := json.Marshal(map[string]any{
		"account_uuid": fx.accountUUID, "user_email": fx.email, "sign_in_url": "https://my.1password.com",
		"account_type": "I",
		"sign_in_provider": map[string]any{
			"type": "password", "secret_key": fx.secretKey, // plaintext fallback test
		},
	})
	_, _ = db.Exec(`INSERT INTO accounts VALUES (1, ?, ?)`, fx.accountUUID, acctData)

	// Legacy format stores enc_sym_key/enc_pri_key/enc_vault_key/enc_attrs as JSON-encoded strings.
	symStr, _ := json.Marshal(fx.encKsSym)
	priStr, _ := json.Marshal(fx.encKsPri)
	ksData, _ := json.Marshal(map[string]any{
		"sn": 1, "encrypted_by": "mp", "enc_sym_key": string(symStr), "enc_pri_key": string(priStr),
	})
	_, _ = db.Exec(`INSERT INTO account_objects VALUES (10, 1, ?, 'keyset', ?)`, fx.ksUUID, ksData)

	vkStr, _ := json.Marshal(fx.encVaultKey)
	attrsStr, _ := json.Marshal(fx.encAttrs)
	vData, _ := json.Marshal(map[string]any{
		"vault_uuid": fx.vaultUUID, "vault_type": "P", "enc_vault_key": string(vkStr), "enc_attrs": string(attrsStr),
	})
	_, _ = db.Exec(`INSERT INTO account_objects VALUES (20, 1, ?, 'vault', ?)`, fx.vaultUUID, vData)

	ovBytes, _ := json.Marshal(fx.encOverview)
	detBytes, _ := json.Marshal(fx.encDetails)
	_, _ = db.Exec(`INSERT INTO item_overviews VALUES (100, 20, ?, 1732000000, 1732000500, '001', 1, 0, ?)`, fx.itemUUID, ovBytes)
	_, _ = db.Exec(`INSERT INTO item_details VALUES (100, ?)`, detBytes)
	db.Close()

	// Verify ListAccounts JSON serialization NEVER leaks PlaintextSecretKey.
	accts, err := ListAccounts(dbPath)
	if err != nil || len(accts) != 1 {
		t.Fatalf("ListAccounts legacy: %+v, err=%v", accts, err)
	}
	if !accts[0].HasPlaintextSecretKey {
		t.Fatal("expected HasPlaintextSecretKey=true")
	}
	marshaled, err := json.Marshal(accts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(marshaled), fx.secretKey) {
		t.Fatalf("AccountSummary JSON leaked PlaintextSecretKey: %s", string(marshaled))
	}

	// Omit SecretKey to verify automatic plaintext secret_key detection.
	exp, err := Export(Options{DBPath: dbPath, Password: fx.password})
	if err != nil {
		t.Fatalf("Export pre-v60: %v", err)
	}
	verifyFixtureExport(t, exp, fx)
}

func verifyFixtureExport(t *testing.T, exp *opmodel.AccountExport, fx *syntheticFixture) {
	t.Helper()
	if exp.TotalPasskeys() != 1 {
		t.Fatalf("expected 1 passkey, got %d", exp.TotalPasskeys())
	}
	pk := exp.Vaults[0].Items[0].Passkeys[0]
	if pk.RPID != "webauthn.io" || !bytes.Equal(pk.CredentialID, fx.credID) || !bytes.Equal(pk.UserHandle, fx.userHandle) {
		t.Fatalf("passkey metadata mismatch: %+v", pk)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(pk.PrivateKeyPKCS8DER)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	if !parsed.(*ecdsa.PrivateKey).Equal(fx.ecKey) {
		t.Fatal("decrypted sqlite passkey private key mismatch")
	}
}
