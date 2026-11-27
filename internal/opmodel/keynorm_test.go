package opmodel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
)

func TestNormalizePrivateKeyAllFormats(t *testing.T) {
	// Generate one ECDSA P-256 key and test PKCS#8, SEC1, COSE CBOR, JWK, Raw scalar, and PEM.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantPKCS8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	// 1. PKCS#8 DER (base64url)
	nk, err := NormalizePrivateKey(opcrypto.Base64URLEncode(wantPKCS8), "ES256")
	if err != nil {
		t.Fatalf("PKCS#8 DER: %v", err)
	}
	assertECKeyMatches(t, nk, ecKey, "ECDSA", "P-256")

	// 2. SEC1 EC DER
	sec1DER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	nk, err = NormalizePrivateKey(opcrypto.Base64URLEncode(sec1DER), "ES256")
	if err != nil {
		t.Fatalf("SEC1 DER: %v", err)
	}
	assertECKeyMatches(t, nk, ecKey, "ECDSA", "P-256")

	// 3. COSE CBOR EC2
	dPadded := make([]byte, 32)
	ecKey.D.FillBytes(dPadded)
	xPadded := make([]byte, 32)
	ecKey.X.FillBytes(xPadded)
	yPadded := make([]byte, 32)
	ecKey.Y.FillBytes(yPadded)
	coseBytes, err := cbor.Marshal(map[int64]any{
		1:  2,  // kty = EC2
		3:  -7, // alg = ES256
		-1: 1,  // crv = P-256
		-2: xPadded,
		-3: yPadded,
		-4: dPadded,
	})
	if err != nil {
		t.Fatal(err)
	}
	nk, err = NormalizePrivateKey(opcrypto.Base64URLEncode(coseBytes), "ES256")
	if err != nil {
		t.Fatalf("COSE CBOR: %v", err)
	}
	assertECKeyMatches(t, nk, ecKey, "ECDSA", "P-256")

	// 4. JSON JWK
	jwkBytes, _ := json.Marshal(map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   opcrypto.Base64URLEncode(xPadded),
		"y":   opcrypto.Base64URLEncode(yPadded),
		"d":   opcrypto.Base64URLEncode(dPadded),
	})
	nk, err = NormalizePrivateKey(string(jwkBytes), "ES256")
	if err != nil {
		t.Fatalf("JWK: %v", err)
	}
	assertECKeyMatches(t, nk, ecKey, "ECDSA", "P-256")

	// 5. Raw 32-byte P-256 scalar
	nk, err = NormalizePrivateKey(opcrypto.Base64URLEncode(dPadded), "ES256")
	if err != nil {
		t.Fatalf("Raw scalar: %v", err)
	}
	assertECKeyMatches(t, nk, ecKey, "ECDSA", "P-256")

	// 6. PEM
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: wantPKCS8}))
	nk, err = NormalizePrivateKey(pemStr, "ES256")
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}
	assertECKeyMatches(t, nk, ecKey, "ECDSA", "P-256")

	// 7. Ed25519 COSE CBOR & Raw seed
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edCose, _ := cbor.Marshal(map[int64]any{1: 1, 3: -8, -1: 6, -4: edPriv.Seed()})
	nkEd, err := NormalizePrivateKey(opcrypto.Base64URLEncode(edCose), "EdDSA")
	if err != nil {
		t.Fatalf("Ed25519 COSE: %v", err)
	}
	if nkEd.KeyAlgorithm != "EdDSA" || nkEd.KeyCurve != "Ed25519" {
		t.Fatalf("unexpected Ed25519 metadata: %+v", nkEd)
	}
	parsedEd, err := x509.ParsePKCS8PrivateKey(nkEd.PKCS8DER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsedEd.(ed25519.PrivateKey), edPriv) {
		t.Fatal("Ed25519 key mismatch")
	}

	// 8. RSA PKCS#1 DER
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaKey)
	nkRSA, err := NormalizePrivateKey(opcrypto.Base64URLEncode(pkcs1), "RS256")
	if err != nil {
		t.Fatalf("RSA PKCS#1: %v", err)
	}
	if nkRSA.KeyAlgorithm != "RSA" {
		t.Fatalf("unexpected RSA alg: %s", nkRSA.KeyAlgorithm)
	}
}

func TestNormalizePrivateKeyHardening(t *testing.T) {
	// 1. Unrecognized key error must NEVER leak raw secret bytes.
	secretGarbage := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	_, err := NormalizePrivateKey(opcrypto.Base64URLEncode(secretGarbage), "ES256")
	if err == nil {
		t.Fatal("expected error for invalid key blob")
	}
	if strings.Contains(strings.ToLower(err.Error()), hex.EncodeToString(secretGarbage[:4])) {
		t.Fatalf("error leaked raw key prefix: %v", err)
	}

	// 2. Mismatched (x, y) in EC JWK must be rejected.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dPadded := make([]byte, 32)
	ecKey.D.FillBytes(dPadded)
	badX := bytes.Repeat([]byte{0x01}, 32)
	badY := bytes.Repeat([]byte{0x02}, 32)
	badJWK, _ := json.Marshal(map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": opcrypto.Base64URLEncode(badX),
		"y": opcrypto.Base64URLEncode(badY),
		"d": opcrypto.Base64URLEncode(dPadded),
	})
	if _, err := NormalizePrivateKey(string(badJWK), "ES256"); err == nil {
		t.Fatal("expected error for EC JWK with mismatched public coordinates")
	}

	// 3. Zero EC scalar must be rejected without panic.
	zeroScalar := make([]byte, 32)
	if _, err := NormalizePrivateKey(opcrypto.Base64URLEncode(zeroScalar), "ES256"); err == nil {
		t.Fatal("expected error for zero P-256 scalar")
	}

	// 4. Encrypted PEM returns clear error.
	encPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1, 2, 3, 4}}))
	if _, err := NormalizePrivateKey(encPEM, "ES256"); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("expected encrypted PEM error, got: %v", err)
	}
}

func assertECKeyMatches(t *testing.T, nk *NormalizedKey, want *ecdsa.PrivateKey, wantAlg, wantCurve string) {
	t.Helper()
	if nk.KeyAlgorithm != wantAlg || nk.KeyCurve != wantCurve {
		t.Fatalf("got %s/%s, want %s/%s (src=%s)", nk.KeyAlgorithm, nk.KeyCurve, wantAlg, wantCurve, nk.SourceFormat)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(nk.PKCS8DER)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey (%s): %v", nk.SourceFormat, err)
	}
	got, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
	if !got.Equal(want) {
		t.Fatalf("normalized key (%s) does not equal original", nk.SourceFormat)
	}
}

func TestExtractItemPasskey1PasswordSchema(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, _ := x509.MarshalPKCS8PrivateKey(ecKey)

	credID := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03}
	userHandle := []byte("user-handle-42")
	prfCred := bytes.Repeat([]byte{0xab}, 32)

	ovJSON, _ := json.Marshal(map[string]any{
		"title": "GitHub",
		"url":   "https://github.com/login",
		"URLs":  []map[string]any{{"l": "website", "u": "https://github.com/login"}},
		"ainfo": "octocat",
		"tags":  []string{"dev"},
		"passkey": map[string]any{
			"credentialId": opcrypto.Base64URLEncode(credID),
			"rpId":         "github.com",
			"userHandle":   opcrypto.Base64URLEncode(userHandle),
			"prf":          map[string]any{"numCreds": 1},
		},
	})
	detJSON, _ := json.Marshal(map[string]any{
		"notesPlain": "my note",
		"fields": []map[string]any{
			{"designation": "username", "type": "T", "value": "octocat"},
			{"designation": "password", "type": "P", "value": "hunter2"},
		},
		"sections": []map[string]any{
			{
				"title": "Security",
				"fields": []map[string]any{
					{"n": "TOTP_1234", "t": "one-time password", "k": "concealed", "v": "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP"},
					{"n": "TOTP_5678", "t": "backup totp", "k": "totp", "v": "otpauth://totp/GitHub:backup?secret=JBSWY3DPEHPK3PXQ"},
				},
			},
		},
		"passkey": map[string]any{
			"type":       "webauthn",
			"createdAt":  1730000000,
			"privateKey": opcrypto.Base64URLEncode(pkcs8DER),
			"alg":        "ES256",
			"userHandle": opcrypto.Base64URLEncode(userHandle),
			"prf": map[string]any{
				"alg":        "HMAC_SHA256",
				"credWithUv": opcrypto.Base64URLEncode(prfCred),
			},
		},
	})

	item, warns, err := ExtractItem("v1", "Private", "i1", CategoryLogin, 1720000000, 1730000100, true, ovJSON, detJSON)
	if err != nil {
		t.Fatalf("ExtractItem: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(item.Passkeys) != 1 {
		t.Fatalf("expected 1 passkey, got %d", len(item.Passkeys))
	}
	pk := item.Passkeys[0]
	if pk.RPID != "github.com" || !bytes.Equal(pk.CredentialID, credID) || !bytes.Equal(pk.UserHandle, userHandle) {
		t.Fatalf("passkey metadata mismatch: %+v", pk)
	}
	if pk.UserName != "octocat" || item.TOTP == "" || pk.PRF == nil || !bytes.Equal(pk.PRF.CredWithUV, prfCred) {
		t.Fatalf("expected username, totp, and PRF populated: %+v", pk)
	}
	if !bytes.Equal(pk.PrivateKeyPKCS8DER, pkcs8DER) {
		t.Fatal("PKCS#8 DER mismatch")
	}
	// Second TOTP custom field must be marked concealed.
	if len(item.CustomFields) != 1 || !item.CustomFields[0].Concealed {
		t.Fatalf("expected secondary TOTP custom field to be concealed: %+v", item.CustomFields)
	}
}

func TestExtractItemNumericCOSEAlgAndValidation(t *testing.T) {
	// Numeric COSE alg -8 (EdDSA) with raw 32-byte Ed25519 seed must normalize as EdDSA/Ed25519.
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := []byte("ed25519-cred-id-01")
	ovJSON, _ := json.Marshal(map[string]any{
		"title": "Ed25519 Site",
		"passkey": map[string]any{
			"credentialId": opcrypto.Base64URLEncode(credID),
			"rpId":         "ed25519.example",
		},
	})
	detJSON, _ := json.Marshal(map[string]any{
		"passkey": map[string]any{
			"type":       "webauthn",
			"createdAt":  1730000000000, // milliseconds
			"privateKey": opcrypto.Base64URLEncode(edPriv.Seed()),
			"alg":        -8,
		},
	})
	item, warns, err := ExtractItem("v1", "Private", "i2", CategoryLogin, 1720000000, 1730000100, false, ovJSON, detJSON)
	if err != nil {
		t.Fatalf("ExtractItem Ed25519: %v", err)
	}
	if len(warns) != 0 || len(item.Passkeys) != 1 {
		t.Fatalf("expected 1 passkey with 0 warnings, got %d passkeys, warns=%v", len(item.Passkeys), warns)
	}
	pk := item.Passkeys[0]
	if pk.KeyAlgorithm != "EdDSA" || pk.KeyCurve != "Ed25519" {
		t.Fatalf("expected EdDSA/Ed25519, got %s/%s", pk.KeyAlgorithm, pk.KeyCurve)
	}
	if pk.CreatedAt.Unix() != 1730000000 {
		t.Fatalf("millisecond createdAt not normalized: got %d", pk.CreatedAt.Unix())
	}

	// Missing rpId must be skipped with a warning rather than emitted broken.
	ovMissingRP, _ := json.Marshal(map[string]any{
		"title": "Broken Passkey",
		"passkey": map[string]any{
			"credentialId": opcrypto.Base64URLEncode(credID),
		},
	})
	itemBad, warnsBad, err := ExtractItem("v1", "Private", "i3", CategoryLogin, 1720000000, 1730000100, false, ovMissingRP, detJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(itemBad.Passkeys) != 0 || len(warnsBad) == 0 {
		t.Fatalf("expected broken passkey to be skipped with warning; got %d passkeys, warns=%v", len(itemBad.Passkeys), warnsBad)
	}
}
