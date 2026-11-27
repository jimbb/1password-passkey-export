package opcrypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"testing"
)

const (
	testSecretKey  = "A3-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE-FFFFF"
	testSecretKey2 = "A3-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE-FFFFG"
)

func TestNormalizePassword(t *testing.T) {
	// 1Password white paper §8.2.2: Å in different encodings normalizes to A + U+030A,
	// outer whitespace trimmed, inner whitespace preserved.
	for _, p := range []string{"\u212B", "\u00C5", "A\u030A"} {
		got := NormalizePassword("  " + p + " x\t")
		want := "A\u030A x"
		if got != want {
			t.Fatalf("NormalizePassword(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestParseSecretKey(t *testing.T) {
	sk, err := ParseSecretKey(testSecretKey)
	if err != nil {
		t.Fatalf("ParseSecretKey dashed: %v", err)
	}
	if sk.Format != "A3" || sk.AccountID != "AAAAAA" || sk.Secret != "BBBBBBCCCCCDDDDDEEEEEFFFFF" {
		t.Fatalf("unexpected parsed secret key: %+v", sk)
	}

	sk2, err := ParseSecretKey("  a3aaaaaabbbbbbcccccdddddeeeeefffff  ")
	if err != nil {
		t.Fatalf("ParseSecretKey undashed: %v", err)
	}
	if *sk != *sk2 {
		t.Fatalf("undashed mismatch: %+v vs %+v", sk2, sk)
	}

	badKeys := []string{
		"B3-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE-FFFFF",  // unsupported version
		"A3-AAAAAA-SHORT",                           // too short for A3
		"A3-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE-FFFFFF", // too long for A3
		"A3-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE-FFFF!",  // invalid punctuation
	}
	for _, bad := range badKeys {
		if _, err := ParseSecretKey(bad); err == nil {
			t.Fatalf("expected error for invalid secret key %q", bad)
		}
	}
}

func TestCompute2SKD(t *testing.T) {
	sk, err := ParseSecretKey(testSecretKey)
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := ParseSecretKey(testSecretKey2)
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{9}, 16)

	a, err := Compute2SKD(sk, "pw", "Patty@Dogs.Example", AlgPBES2gHS256, salt, 100)
	if err != nil {
		t.Fatalf("Compute2SKD: %v", err)
	}
	b, err := Compute2SKD(sk, "pw", "  patty@dogs.example  ", AlgPBES2gHS256, salt, 100)
	if err != nil {
		t.Fatalf("Compute2SKD lowercase/trimmed: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("email should be case-insensitive and trimmed")
	}
	c, _ := Compute2SKD(sk, "pw2", "patty@dogs.example", AlgPBES2gHS256, salt, 100)
	d, _ := Compute2SKD(sk2, "pw", "patty@dogs.example", AlgPBES2gHS256, salt, 100)
	e, _ := Compute2SKD(sk, "pw", "patty@dogs.example", SRPMethod4096, salt, 100)
	if bytes.Equal(a, c) || bytes.Equal(a, d) || bytes.Equal(a, e) {
		t.Fatal("2SKD must depend on password, secret key, and label")
	}

	if _, err := Compute2SKD(sk, "pw", "patty@dogs.example", AlgPBES2gHS256, salt, 0); err == nil {
		t.Fatal("expected error for zero iterations")
	}
	if _, err := Compute2SKD(sk, "pw", "patty@dogs.example", AlgPBES2gHS256, salt, MaxKDFIterations+1); err == nil {
		t.Fatal("expected error when iterations exceed MaxKDFIterations")
	}
}

func TestKeysetChainAndVaultUnwrap(t *testing.T) {
	sk, err := ParseSecretKey(testSecretKey)
	if err != nil {
		t.Fatal(err)
	}
	password := "correct-horse-battery-staple"
	email := "alice@example.com"
	salt := bytes.Repeat([]byte{0x42}, 16)
	iters := 100

	auk, err := Compute2SKD(sk, password, email, AlgPBES2gHS256, salt, iters)
	if err != nil {
		t.Fatal(err)
	}

	// Primary keyset (SN 1)
	ks1Sym := make([]byte, 32)
	_, _ = rand.Read(ks1Sym)
	ks1RSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ks1SymJWK, _ := json.Marshal(JWK{Kty: "oct", Kid: "ks1", Alg: "A256GCM", K: Base64URLEncode(ks1Sym)})
	encKs1Sym, err := EncryptAESGCM("mp", auk, "b5+jwk+json", ks1SymJWK)
	if err != nil {
		t.Fatal(err)
	}
	encKs1Sym.Alg = AlgPBES2gHS256
	encKs1Sym.P2s = Base64URLEncode(salt)
	encKs1Sym.P2c = iters

	ks1PriJWK := rsaToJWK("ks1", "RSA-OAEP", ks1RSA)
	encKs1Pri, err := EncryptAESGCM("ks1", ks1Sym, "b5+jwk+json", ks1PriJWK)
	if err != nil {
		t.Fatal(err)
	}

	// Child keyset (SN 2) encrypted by ks1's RSA key (RSA-OAEP SHA-1)
	ks2Sym := make([]byte, 32)
	_, _ = rand.Read(ks2Sym)
	ks2RSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks2SymJWK, _ := json.Marshal(JWK{Kty: "oct", Kid: "ks2", Alg: "A256GCM", K: Base64URLEncode(ks2Sym)})
	ks2SymCT, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &ks1RSA.PublicKey, ks2SymJWK, nil)
	if err != nil {
		t.Fatal(err)
	}
	encKs2Sym := &EncryptedObject{Kid: "ks1", Enc: "RSA-OAEP", Cty: "b5+jwk+json", Data: Base64URLEncode(ks2SymCT)}
	ks2PriJWK := rsaToJWK("ks2", "RSA-OAEP-256", ks2RSA)
	encKs2Pri, err := EncryptAESGCM("ks2", ks2Sym, "b5+jwk+json", ks2PriJWK)
	if err != nil {
		t.Fatal(err)
	}

	// Vault key wrapped by ks2 using RSA-OAEP-256 (SHA-256)
	vaultKey := make([]byte, 32)
	_, _ = rand.Read(vaultKey)
	vaultJWK, _ := json.Marshal(JWK{Kty: "oct", Kid: "vault1", Alg: "A256GCM", K: Base64URLEncode(vaultKey)})
	vaultCT, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &ks2RSA.PublicKey, vaultJWK, nil)
	if err != nil {
		t.Fatal(err)
	}
	encVaultKey := &EncryptedObject{Kid: "ks2", Enc: "RSA-OAEP-256", Cty: "b5+jwk+json", Data: Base64URLEncode(vaultCT)}

	kr, warns, err := UnlockKeysets([]RawKeyset{
		{UUID: "ks2", SN: 2, EncryptedBy: "ks1", EncSymKey: encKs2Sym, EncPriKey: encKs2Pri},
		{UUID: "ks1", SN: 1, EncryptedBy: "mp", EncSymKey: encKs1Sym, EncPriKey: encKs1Pri},
	}, sk, password, email)
	if err != nil {
		t.Fatalf("UnlockKeysets: %v", err)
	}
	defer kr.Wipe()
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}

	unwrapped, err := kr.UnwrapVaultKey(encVaultKey)
	if err != nil {
		t.Fatalf("UnwrapVaultKey: %v", err)
	}
	if !bytes.Equal(unwrapped.Key, vaultKey) {
		t.Fatal("unwrapped vault key mismatch")
	}

	// A retired/unreadable secondary mp keyset should warn rather than aborting when a valid keyset unlocks.
	badKey := make([]byte, 32)
	_, _ = rand.Read(badKey)
	badEncSym, _ := EncryptAESGCM("mp", badKey, "b5+jwk+json", ks1SymJWK)
	badEncSym.Alg = AlgPBES2gHS256
	badEncSym.P2s = Base64URLEncode(salt)
	badEncSym.P2c = iters
	kr2, warns2, err := UnlockKeysets([]RawKeyset{
		{UUID: "ks-retired", SN: 0, EncryptedBy: "mp", EncSymKey: badEncSym, EncPriKey: encKs1Pri},
		{UUID: "ks1", SN: 1, EncryptedBy: "mp", EncSymKey: encKs1Sym, EncPriKey: encKs1Pri},
	}, sk, password, email)
	if err != nil {
		t.Fatalf("UnlockKeysets should survive bad retired keyset: %v", err)
	}
	defer kr2.Wipe()
	if len(warns2) == 0 {
		t.Fatal("expected warning for unreadable retired keyset")
	}

	// Wrong password must fail cleanly when no primary keyset unlocks.
	if _, _, err := UnlockKeysets([]RawKeyset{
		{UUID: "ks1", SN: 1, EncryptedBy: "mp", EncSymKey: encKs1Sym, EncPriKey: encKs1Pri},
	}, sk, "wrong-password", email); err == nil {
		t.Fatal("expected error with wrong password")
	}
}

func rsaToJWK(kid, alg string, k *rsa.PrivateKey) []byte {
	j := JWK{
		Kty: "RSA",
		Kid: kid,
		Alg: alg,
		N:   Base64URLEncode(k.N.Bytes()),
		E:   Base64URLEncode(big.NewInt(int64(k.E)).Bytes()),
		D:   Base64URLEncode(k.D.Bytes()),
		P:   Base64URLEncode(k.Primes[0].Bytes()),
		Q:   Base64URLEncode(k.Primes[1].Bytes()),
	}
	b, _ := json.Marshal(j)
	return b
}
