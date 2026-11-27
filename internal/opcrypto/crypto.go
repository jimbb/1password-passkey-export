package opcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"math/big"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

const (
	AlgPBES2gHS256   = "PBES2g-HS256"
	SRPMethod4096    = "SRPg-4096"
	MaxKDFIterations = 10_000_000
)

// SecretKey represents a parsed 1Password Secret Key (e.g. A3-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX).
type SecretKey struct {
	Format    string // e.g. "A3"
	AccountID string // 6-char account ID
	Secret    string // remaining secret characters without dashes
}

// ParseSecretKey validates and parses a 1Password Secret Key string.
func ParseSecretKey(raw string) (*SecretKey, error) {
	cleaned := strings.ToUpper(strings.TrimSpace(raw))
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\u2010", "-")
	cleaned = strings.ReplaceAll(cleaned, "\u2011", "-")
	cleaned = strings.ReplaceAll(cleaned, "\u2013", "-")
	cleaned = strings.ReplaceAll(cleaned, "\u2014", "-")

	// Allow both dashed (A3-XXXXXX-...) and undashed (34 chars starting with A3).
	var format, accountID, secret string
	if strings.Contains(cleaned, "-") {
		parts := strings.Split(cleaned, "-")
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid secret key format: expected A3-XXXXXX-...")
		}
		format = parts[0]
		accountID = parts[1]
		secret = strings.Join(parts[2:], "")
	} else {
		if len(cleaned) < 10 {
			return nil, fmt.Errorf("invalid secret key: too short")
		}
		format = cleaned[:2]
		accountID = cleaned[2:8]
		secret = cleaned[8:]
	}

	if format != "A3" && format != "A2" {
		return nil, fmt.Errorf("unsupported secret key version %q (expected A3)", format)
	}
	if len(accountID) != 6 || !isAlphaNumUpper(accountID) {
		return nil, fmt.Errorf("invalid secret key account ID (expected 6 alphanumeric characters)")
	}
	if format == "A3" && len(secret) != 26 {
		return nil, fmt.Errorf("invalid A3 secret key length: got %d secret chars, expected 26 (check for typos)", len(secret))
	}
	if len(secret) < 16 || !isAlphaNumUpper(secret) {
		return nil, fmt.Errorf("invalid secret key characters or length (%d)", len(secret))
	}
	return &SecretKey{
		Format:    format,
		AccountID: accountID,
		Secret:    secret,
	}, nil
}

func isAlphaNumUpper(s string) bool {
	for i := range len(s) {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// NormalizePassword applies 1Password's password normalization (white paper §8.2.2):
// trim surrounding whitespace, then Unicode NFKD.
func NormalizePassword(password string) string {
	return norm.NFKD.String(strings.TrimSpace(password))
}

// NormalizeEmail applies 1Password's email normalization: trim, NFKD, lowercase.
func NormalizeEmail(email string) string {
	return strings.ToLower(norm.NFKD.String(strings.TrimSpace(email)))
}

// Base64URLDecode decodes unpadded or padded base64url strings (and tolerates standard base64).
func Base64URLDecode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	return base64.RawURLEncoding.DecodeString(s)
}

// Base64URLEncode encodes bytes using unpadded base64url.
func Base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// WipeBytes overwrites sensitive byte slices with zeros.
func WipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func wipeBigInt(n *big.Int) {
	if n == nil {
		return
	}
	bits := n.Bits()
	for i := range bits {
		bits[i] = 0
	}
	n.SetInt64(0)
}

// Compute2SKD implements 1Password's Two-Secret Key Derivation (2SKD, white paper §8.2).
// label is "PBES2g-HS256" for the Account Unlock Key (AUK) or "SRPg-4096" for SRP-x.
func Compute2SKD(sk *SecretKey, password, email, label string, salt []byte, iterations int) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("secret key is nil")
	}
	if iterations <= 0 {
		return nil, fmt.Errorf("invalid PBKDF2 iteration count: %d", iterations)
	}
	if iterations > MaxKDFIterations {
		return nil, fmt.Errorf("refusing excessive PBKDF2 iteration count %d (max %d)", iterations, MaxKDFIterations)
	}
	if len(salt) == 0 {
		return nil, errors.New("empty KDF salt")
	}

	emailNorm := NormalizeEmail(email)

	// Step 1: Stretch salt with email using HKDF-SHA256(ikm=salt, salt=email, info=label).
	hkdfSalt := hkdf.New(sha256.New, salt, []byte(emailNorm), []byte(label))
	stretchedSalt := make([]byte, 32)
	defer WipeBytes(stretchedSalt)
	if _, err := io.ReadFull(hkdfSalt, stretchedSalt); err != nil {
		return nil, fmt.Errorf("hkdf salt stretch: %w", err)
	}

	// Step 2: PBKDF2-HMAC-SHA256 over normalized password.
	pwNorm := []byte(NormalizePassword(password))
	defer WipeBytes(pwNorm)
	kM := pbkdf2.Key(pwNorm, stretchedSalt, iterations, 32, sha256.New)
	defer WipeBytes(kM)

	// Step 3: Derive account key component using HKDF-SHA256(ikm=secret, salt=accountID, info=format).
	hkdfSecret := hkdf.New(sha256.New, []byte(sk.Secret), []byte(sk.AccountID), []byte(sk.Format))
	kA := make([]byte, 32)
	defer WipeBytes(kA)
	if _, err := io.ReadFull(hkdfSecret, kA); err != nil {
		return nil, fmt.Errorf("hkdf secret key: %w", err)
	}

	// Step 4: XOR k_m and k_A.
	out := make([]byte, 32)
	for i := range 32 {
		out[i] = kM[i] ^ kA[i]
	}
	return out, nil
}

// EncryptedObject is 1Password's JWE-like encrypted envelope.
type EncryptedObject struct {
	Kid  string `json:"kid"`
	Enc  string `json:"enc"`
	Cty  string `json:"cty"`
	IV   string `json:"iv,omitempty"`
	Data string `json:"data"`

	// Present when kid == "mp" (password-derived key).
	Alg string `json:"alg,omitempty"`
	P2s string `json:"p2s,omitempty"`
	P2c int    `json:"p2c,omitempty"`
}

// UnmarshalEncryptedObject parses an EncryptedObject from either a JSON object or
// a JSON-encoded string containing that object (used by older 1Password 8 SQLite schemas).
func UnmarshalEncryptedObject(raw json.RawMessage) (*EncryptedObject, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "\"") {
		var inner string
		if err := json.Unmarshal(raw, &inner); err != nil {
			return nil, fmt.Errorf("unwrap stringified encrypted object: %w", err)
		}
		trimmed = strings.TrimSpace(inner)
		if trimmed == "" || trimmed == "null" {
			return nil, nil
		}
		raw = json.RawMessage(trimmed)
	}
	var obj EncryptedObject
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("parse encrypted object: %w", err)
	}
	return &obj, nil
}

// DecryptAESGCM decrypts an A256GCM EncryptedObject using a 32-byte key.
func DecryptAESGCM(obj *EncryptedObject, key []byte) ([]byte, error) {
	if obj == nil {
		return nil, errors.New("encrypted object is nil")
	}
	if obj.Enc != "A256GCM" {
		return nil, fmt.Errorf("unsupported symmetric encryption %q", obj.Enc)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid AES-256 key length %d (expected 32)", len(key))
	}
	iv, err := Base64URLDecode(obj.IV)
	if err != nil {
		return nil, fmt.Errorf("decode iv: %w", err)
	}
	ciphertext, err := Base64URLDecode(obj.Data)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes gcm: %w", err)
	}
	if len(iv) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid GCM nonce length %d (expected %d)", len(iv), gcm.NonceSize())
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-256-GCM authentication failed (kid=%q): %w", obj.Kid, err)
	}
	return plaintext, nil
}

// EncryptAESGCM encrypts plaintext into an A256GCM EncryptedObject with a fresh random 12-byte IV.
func EncryptAESGCM(kid string, key []byte, cty string, plaintext []byte) (*EncryptedObject, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid AES-256 key length %d (expected 32)", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes gcm: %w", err)
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("random iv: %w", err)
	}
	ct := gcm.Seal(nil, iv, plaintext, nil)
	return &EncryptedObject{
		Kid:  kid,
		Enc:  "A256GCM",
		Cty:  cty,
		IV:   Base64URLEncode(iv),
		Data: Base64URLEncode(ct),
	}, nil
}

// JWK represents a 1Password JSON Web Key (symmetric "oct" or asymmetric "RSA").
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`

	// Symmetric ("oct")
	K string `json:"k,omitempty"`

	// RSA private key components
	N  string `json:"n,omitempty"`
	E  string `json:"e,omitempty"`
	D  string `json:"d,omitempty"`
	P  string `json:"p,omitempty"`
	Q  string `json:"q,omitempty"`
	Dp string `json:"dp,omitempty"`
	Dq string `json:"dq,omitempty"`
	Qi string `json:"qi,omitempty"`
}

// SymmetricKey holds a decrypted 32-byte AES-256-GCM key and its key ID.
type SymmetricKey struct {
	KID string
	Key []byte
}

// Wipe zeroes the underlying key bytes.
func (s *SymmetricKey) Wipe() {
	if s != nil {
		WipeBytes(s.Key)
	}
}

// RSAPrivateKey holds a decrypted RSA private key and its key ID/default OAEP algorithm.
type RSAPrivateKey struct {
	KID string
	Alg string
	Key *rsa.PrivateKey
}

// Wipe overwrites private RSA components in memory (best-effort in Go).
func (r *RSAPrivateKey) Wipe() {
	if r == nil || r.Key == nil {
		return
	}
	wipeBigInt(r.Key.D)
	for _, p := range r.Key.Primes {
		wipeBigInt(p)
	}
	wipeBigInt(r.Key.Precomputed.Dp)
	wipeBigInt(r.Key.Precomputed.Dq)
	wipeBigInt(r.Key.Precomputed.Qinv)
}

// ParseSymmetricJWK extracts a 32-byte AES key from a decrypted JWK JSON payload.
func ParseSymmetricJWK(jwkJSON []byte) (*SymmetricKey, error) {
	var jwk JWK
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return nil, fmt.Errorf("parse symmetric JWK: %w", err)
	}
	if jwk.Kty != "oct" {
		return nil, fmt.Errorf("expected oct JWK, got %q", jwk.Kty)
	}
	k, err := Base64URLDecode(jwk.K)
	if err != nil {
		return nil, fmt.Errorf("decode symmetric key bytes: %w", err)
	}
	if len(k) != 32 {
		return nil, fmt.Errorf("unexpected symmetric key length %d (expected 32)", len(k))
	}
	return &SymmetricKey{KID: jwk.Kid, Key: k}, nil
}

// ParseRSAPrivateJWK parses an RSA private key from a decrypted JWK JSON payload.
func ParseRSAPrivateJWK(jwkJSON []byte) (*RSAPrivateKey, error) {
	var jwk JWK
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return nil, fmt.Errorf("parse RSA JWK: %w", err)
	}
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("expected RSA JWK, got %q", jwk.Kty)
	}
	decodeBig := func(name, val string) (*big.Int, error) {
		b, err := Base64URLDecode(val)
		if err != nil {
			return nil, fmt.Errorf("decode RSA %s: %w", name, err)
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("missing RSA %s", name)
		}
		return new(big.Int).SetBytes(b), nil
	}
	n, err := decodeBig("n", jwk.N)
	if err != nil {
		return nil, err
	}
	eBig, err := decodeBig("e", jwk.E)
	if err != nil {
		return nil, err
	}
	if !eBig.IsInt64() || eBig.Int64() < 3 || eBig.Int64() > math.MaxInt32 {
		return nil, errors.New("invalid RSA public exponent e")
	}
	d, err := decodeBig("d", jwk.D)
	if err != nil {
		return nil, err
	}
	p, err := decodeBig("p", jwk.P)
	if err != nil {
		return nil, err
	}
	q, err := decodeBig("q", jwk.Q)
	if err != nil {
		return nil, err
	}
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(eBig.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}
	priv.Precompute()
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("invalid RSA private key: %w", err)
	}
	return &RSAPrivateKey{
		KID: jwk.Kid,
		Alg: jwk.Alg,
		Key: priv,
	}, nil
}

// DecryptRSAOAEP decrypts an RSA-OAEP / RSA-OAEP-256 EncryptedObject.
func DecryptRSAOAEP(rsaKey *RSAPrivateKey, obj *EncryptedObject) ([]byte, error) {
	if rsaKey == nil || rsaKey.Key == nil {
		return nil, errors.New("RSA key is nil")
	}
	if obj == nil {
		return nil, errors.New("encrypted object is nil")
	}
	ct, err := Base64URLDecode(obj.Data)
	if err != nil {
		return nil, fmt.Errorf("decode RSA ciphertext: %w", err)
	}
	enc := obj.Enc
	if enc == "" {
		enc = rsaKey.Alg
	}
	var h hash.Hash
	var altHash hash.Hash
	var effectiveAlg, altAlg string
	switch enc {
	case "RSA-OAEP-256":
		h = sha256.New()
		altHash = sha1.New()
		effectiveAlg = "RSA-OAEP-256"
		altAlg = "RSA-OAEP"
	case "RSA-OAEP", "":
		h = sha1.New()
		altHash = sha256.New()
		effectiveAlg = "RSA-OAEP"
		altAlg = "RSA-OAEP-256"
	default:
		return nil, fmt.Errorf("unsupported RSA encryption %q", enc)
	}
	plain, err := rsa.DecryptOAEP(h, rand.Reader, rsaKey.Key, ct, nil)
	if err != nil {
		// Some older 1Password objects omit or mismatch alg vs enc; try the other hash before failing.
		if plainAlt, altErr := rsa.DecryptOAEP(altHash, rand.Reader, rsaKey.Key, ct, nil); altErr == nil {
			return plainAlt, nil
		} else {
			return nil, fmt.Errorf("RSA-OAEP decrypt failed (kid=%q, primary=%s: %v; fallback=%s: %v)",
				obj.Kid, effectiveAlg, err, altAlg, altErr)
		}
	}
	return plain, nil
}
