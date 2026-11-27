package exporter

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tobischo/gokeepasslib/v3"

	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
	"github.com/jimbb/1password-passkey-export/internal/opmodel"
)

func sampleExport(t *testing.T) (*opmodel.AccountExport, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}))
	credID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12}
	userHandle := []byte("uh-alice-001")
	prfBytes := bytes.Repeat([]byte{0xcd}, 32)
	ts := time.Date(2026, 6, 15, 10, 20, 30, 0, time.UTC)

	acct := &opmodel.AccountExport{
		AccountUUID: "acct-1",
		Email:       "alice@example.com",
		UserName:    "Alice",
		Source:      "sqlite",
		Vaults: []opmodel.Vault{
			{
				UUID: "vault-1",
				Name: "Personal",
				Items: []opmodel.Item{
					{
						UUID:         "item-pk",
						VaultUUID:    "vault-1",
						VaultName:    "Personal",
						CategoryUUID: opmodel.CategoryLogin,
						Title:        "GitHub",
						Username:     "alice",
						Password:     "super-secret-pw",
						URLs:         []string{"https://github.com", "https://gist.github.com"},
						Notes:        "Primary dev account",
						TOTP:         "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
						Tags:         []string{"dev"},
						Favorite:     true,
						CreatedAt:    ts,
						UpdatedAt:    ts,
						CustomFields: []opmodel.CustomField{
							{Name: "Recovery Code", Value: "REC-001", Concealed: true},
						},
						Passkeys: []opmodel.Passkey{
							{
								CredentialID:       credID,
								RPID:               "github.com",
								RPName:             "GitHub",
								UserHandle:         userHandle,
								UserName:           "alice",
								UserDisplayName:    "Alice Dev",
								Counter:            0,
								Discoverable:       true,
								CreatedAt:          ts,
								PrivateKeyPKCS8DER: pkcs8DER,
								PrivateKeyPEM:      pemStr,
								KeyAlgorithm:       "ECDSA",
								KeyCurve:           "P-256",
								SourceAlg:          "ES256",
								PRF:                &opmodel.PRFData{Algorithm: "HMAC_SHA256", CredWithUV: prfBytes},
							},
						},
					},
					{
						UUID:         "item-nopk",
						VaultUUID:    "vault-1",
						VaultName:    "Personal",
						CategoryUUID: opmodel.CategoryLogin,
						Title:        "Plain Login",
						Username:     "bob",
						Password:     "pw-only",
						CreatedAt:    ts,
						UpdatedAt:    ts,
					},
				},
			},
		},
	}
	return acct, ecKey, credID
}

func TestExportBitwardenJSON(t *testing.T) {
	acct, ecKey, credID := sampleExport(t)

	// 1. Passkeys-only mode
	raw, err := ExportBitwardenJSON(acct, Options{PasskeysOnly: true})
	if err != nil {
		t.Fatalf("ExportBitwardenJSON: %v", err)
	}
	var parsed struct {
		Encrypted bool              `json:"encrypted"`
		Folders   []bitwardenFolder `json:"folders"`
		Items     []bitwardenItem   `json:"items"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Encrypted {
		t.Fatal("expected encrypted=false")
	}
	if len(parsed.Folders) != 1 || parsed.Folders[0].Name != "Personal" {
		t.Fatalf("unexpected folders: %+v", parsed.Folders)
	}
	if len(parsed.Items) != 1 || parsed.Items[0].Name != "GitHub" {
		t.Fatalf("passkeys-only should export 1 item, got %d", len(parsed.Items))
	}
	fido := parsed.Items[0].Login.Fido2Credentials[0]
	wantCredID := "b64." + opcrypto.Base64URLEncode(credID)
	if fido.CredentialID != wantCredID {
		t.Fatalf("credentialId = %q, want %q", fido.CredentialID, wantCredID)
	}
	if fido.KeyType != "public-key" || fido.KeyAlgorithm != "ECDSA" || fido.KeyCurve != "P-256" || fido.Counter != "0" || fido.Discoverable != "true" {
		t.Fatalf("unexpected fido2 metadata: %+v", fido)
	}
	keyDER, err := opcrypto.Base64URLDecode(fido.KeyValue)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil || !priv.(*ecdsa.PrivateKey).Equal(ecKey) {
		t.Fatalf("Bitwarden keyValue does not round-trip to ECDSA key: err=%v", err)
	}

	// 2. Full vault mode
	rawAll, err := ExportBitwardenJSON(acct, Options{PasskeysOnly: false})
	if err != nil {
		t.Fatal(err)
	}
	var parsedAll struct {
		Items []bitwardenItem `json:"items"`
	}
	_ = json.Unmarshal(rawAll, &parsedAll)
	if len(parsedAll.Items) != 2 {
		t.Fatalf("all-items should export 2 items, got %d", len(parsedAll.Items))
	}
}

func TestExportBitwardenMultiPasskeyAndValidation(t *testing.T) {
	acct, _, _ := sampleExport(t)
	pk1 := acct.Vaults[0].Items[0].Passkeys[0]
	pk2 := pk1
	pk2.CredentialID = []byte("second-credential-id-xyz")
	acct.Vaults[0].Items[0].Title = ""
	acct.Vaults[0].Items[0].Password = "   " // whitespace password preserved
	acct.Vaults[0].Items[0].Passkeys = []opmodel.Passkey{pk1, pk2}

	raw, err := ExportBitwardenJSON(acct, Options{PasskeysOnly: true})
	if err != nil {
		t.Fatalf("ExportBitwardenJSON multi-passkey: %v", err)
	}
	var parsed struct {
		Items []bitwardenItem `json:"items"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Items) != 2 {
		t.Fatalf("expected 2 split Bitwarden items for 2 passkeys, got %d", len(parsed.Items))
	}
	if parsed.Items[0].ID == parsed.Items[1].ID {
		t.Fatal("split multi-passkey items must have distinct IDs")
	}
	if parsed.Items[0].Name != "github.com" || parsed.Items[1].Name != "github.com (Passkey 2)" {
		t.Fatalf("unexpected fallback/split names: %q, %q", parsed.Items[0].Name, parsed.Items[1].Name)
	}
	if parsed.Items[0].Login.Password == nil || *parsed.Items[0].Login.Password != "   " {
		t.Fatalf("whitespace-only password was not preserved: %v", parsed.Items[0].Login.Password)
	}

	// Empty PrivateKeyPKCS8DER must fail across ALL 3 exporters.
	badAcct, _, _ := sampleExport(t)
	badAcct.Vaults[0].Items[0].Passkeys[0].PrivateKeyPKCS8DER = nil
	if _, err := ExportBitwardenJSON(badAcct, Options{PasskeysOnly: true}); err == nil {
		t.Fatal("Bitwarden exporter must reject passkey with empty private key")
	}
	if _, err := ExportCXFJSON(badAcct, Options{PasskeysOnly: true}); err == nil {
		t.Fatal("CXF exporter must reject passkey with empty private key")
	}
	if _, err := ExportKDBX(badAcct, "pw", Options{PasskeysOnly: true}); err == nil {
		t.Fatal("KDBX exporter must reject passkey with empty private key")
	}
}

func TestExportCXFJSON(t *testing.T) {
	acct, ecKey, credID := sampleExport(t)
	// Add an SSH key item with zero timestamps to test ssh-key + zero timestamp omission.
	acct.Vaults[0].Items = append(acct.Vaults[0].Items, opmodel.Item{
		UUID:         "item-ssh",
		VaultUUID:    "vault-1",
		VaultName:    "Personal",
		CategoryUUID: opmodel.CategorySSHKey,
		Title:        "Deploy Key",
		SSHKey: &opmodel.SSHKey{
			PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nTEST\n-----END OPENSSH PRIVATE KEY-----",
			PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITEST deploy@example.com",
		},
	})

	raw, err := ExportCXFJSON(acct, Options{PasskeysOnly: false})
	if err != nil {
		t.Fatalf("ExportCXFJSON: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	ver := parsed["version"].(map[string]any)
	if ver["major"].(float64) != 1 || ver["minor"].(float64) != 0 {
		t.Fatalf("unexpected CXF version: %+v", ver)
	}
	cxfAcct := parsed["accounts"].([]any)[0].(map[string]any)
	items := cxfAcct["items"].([]any)
	if len(items) != 3 {
		t.Fatalf("expected 3 CXF items, got %d", len(items))
	}
	creds := items[0].(map[string]any)["credentials"].([]any)
	pk := creds[0].(map[string]any)
	if pk["type"] != "passkey" {
		t.Fatalf("expected passkey credential first, got %v", pk["type"])
	}
	// CXF credentialId must be raw base64url (NO "b64." prefix)
	if pk["credentialId"] != opcrypto.Base64URLEncode(credID) {
		t.Fatalf("unexpected CXF credentialId: %v", pk["credentialId"])
	}
	keyDER, err := opcrypto.Base64URLDecode(pk["key"].(string))
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil || !priv.(*ecdsa.PrivateKey).Equal(ecKey) {
		t.Fatalf("CXF key does not round-trip to ECDSA key: %v", err)
	}
	exts := pk["fido2Extensions"].(map[string]any)
	hmacExt := exts["hmacCredentials"].(map[string]any)
	if hmacExt["algorithm"] != "hmac-sha256" || hmacExt["credWithUV"] == "" {
		t.Fatalf("unexpected PRF extension: %+v", hmacExt)
	}

	// Verify custom-fields credential was emitted on item 0.
	hasCustomFields := false
	for _, c := range creds {
		if c.(map[string]any)["type"] == "custom-fields" {
			hasCustomFields = true
		}
	}
	if !hasCustomFields {
		t.Fatal("expected custom-fields credential in CXF output")
	}

	// Verify SSH item omits zero timestamps and contains ssh-key credential.
	sshItem := items[2].(map[string]any)
	if _, hasCreated := sshItem["creationAt"]; hasCreated {
		t.Fatalf("zero creationAt must be omitted from CXF item: %+v", sshItem)
	}
	sshCreds := sshItem["credentials"].([]any)
	if len(sshCreds) != 1 || sshCreds[0].(map[string]any)["type"] != "ssh-key" {
		t.Fatalf("expected ssh-key credential, got %+v", sshCreds)
	}

	// Verify empty collections serialize as [] rather than omitted.
	emptyRaw, err := ExportCXFJSON(&opmodel.AccountExport{Email: "empty@example.com"}, Options{PasskeysOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(emptyRaw), `"collections": []`) {
		t.Fatalf("expected explicit empty collections array in CXF JSON: %s", string(emptyRaw))
	}
}

func TestExportKDBXRoundTrip(t *testing.T) {
	acct, ecKey, credID := sampleExport(t)
	// Test raw TOTP normalization + colon sanitization + attribute collision disambiguation.
	acct.Vaults[0].Items[0].Title = "GitHub:Work"
	acct.Vaults[0].Items[0].TOTP = "jbsw-y3dp ehpk 3pxp"
	acct.Vaults[0].Items[0].CustomFields = append(acct.Vaults[0].Items[0].CustomFields,
		opmodel.CustomField{Name: "KP2A_URL_1", Value: "custom-collision", Concealed: false},
		opmodel.CustomField{Name: "Recovery Code", Value: "REC-002", Concealed: true},
	)

	pw := "kdbx-test-password"
	raw, err := ExportKDBX(acct, pw, Options{PasskeysOnly: true})
	if err != nil {
		t.Fatalf("ExportKDBX: %v", err)
	}

	// Wrong password must fail
	badDB := gokeepasslib.NewDatabase()
	badDB.Credentials = gokeepasslib.NewPasswordCredentials("wrong-pw")
	if err := gokeepasslib.NewDecoder(bytes.NewReader(raw)).Decode(badDB); err == nil {
		t.Fatal("expected KDBX decode error with wrong password")
	}

	// Correct password unlocks and exposes KPEX_PASSKEY_* attributes and strong Argon2 KDF.
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(pw)
	if err := gokeepasslib.NewDecoder(bytes.NewReader(raw)).Decode(db); err != nil {
		t.Fatalf("decode KDBX: %v", err)
	}
	kdf := db.Header.FileHeaders.KdfParameters
	if !bytes.Equal(kdf.UUID, gokeepasslib.KdfArgon2) || kdf.Memory != kdbxArgon2Memory || kdf.Iterations != kdbxArgon2Iterations || kdf.Parallelism != kdbxArgon2Parallelism {
		t.Fatalf("unexpected KDBX Argon2 KDF parameters: mem=%d iters=%d par=%d", kdf.Memory, kdf.Iterations, kdf.Parallelism)
	}

	if err := db.UnlockProtectedEntries(); err != nil {
		t.Fatalf("unlock KDBX protected entries: %v", err)
	}
	groups := db.Content.Root.Groups[0].Groups
	if len(groups) != 1 || groups[0].Name != "Personal" || len(groups[0].Entries) != 1 {
		t.Fatalf("unexpected KDBX group/entry layout")
	}
	entry := groups[0].Entries[0]
	if !strings.Contains(entry.Tags, "Passkey") {
		t.Fatalf("expected Passkey tag, got %q", entry.Tags)
	}
	if entry.GetContent(kpexCredentialID) != opcrypto.Base64URLEncode(credID) {
		t.Fatalf("KDBX credentialId mismatch: %q", entry.GetContent(kpexCredentialID))
	}
	if entry.GetContent(kpexRelyingParty) != "github.com" || entry.GetContent(kpexFlagBE) != "1" || entry.GetContent(kpexFlagBS) != "1" {
		t.Fatal("KDBX relying party or flags mismatch")
	}
	pemBlock, _ := pem.Decode([]byte(entry.GetContent(kpexPrivateKeyPEM)))
	if pemBlock == nil {
		t.Fatal("KDBX KPEX_PASSKEY_PRIVATE_KEY_PEM is not valid PEM")
	}
	priv, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil || !priv.(*ecdsa.PrivateKey).Equal(ecKey) {
		t.Fatalf("KDBX PEM key does not round-trip to original ECDSA key: %v", err)
	}

	// Verify TOTP URI normalization & sanitized issuer.
	otpURI, err := url.Parse(entry.GetContent("otp"))
	if err != nil {
		t.Fatalf("parse KDBX otp URI: %v", err)
	}
	if otpURI.Query().Get("secret") != "JBSWY3DPEHPK3PXP" || otpURI.Query().Get("issuer") != "GitHub_Work" {
		t.Fatalf("unexpected KDBX otp URI: %s", entry.GetContent("otp"))
	}

	// Verify KP2A_URL_1 reservation and duplicate custom-field disambiguation.
	if entry.GetContent("KP2A_URL_1") != "https://gist.github.com" {
		t.Fatalf("KP2A_URL_1 overwritten: %q", entry.GetContent("KP2A_URL_1"))
	}
	if entry.GetContent("KP2A_URL_1 (2)") != "custom-collision" {
		t.Fatalf("expected disambiguated KP2A_URL_1 (2), got %q", entry.GetContent("KP2A_URL_1 (2)"))
	}
	if entry.GetContent("Recovery Code") != "REC-001" || entry.GetContent("Recovery Code (2)") != "REC-002" {
		t.Fatalf("expected disambiguated Recovery Code fields, got %q / %q", entry.GetContent("Recovery Code"), entry.GetContent("Recovery Code (2)"))
	}
}
