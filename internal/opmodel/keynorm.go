package opmodel

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
)

// NormalizedKey is the canonical private key representation shared by all exporters.
type NormalizedKey struct {
	PKCS8DER     []byte
	PKCS8PEM     string
	KeyAlgorithm string // "ECDSA", "EdDSA", "RSA"
	KeyCurve     string // "P-256", "P-384", "P-521", "Ed25519", ""
	SourceFormat string // human-readable detected input format
}

// NormalizePrivateKey accepts raw private key material from 1Password (base64url, base64,
// PEM, PKCS#8 DER, SEC1 EC DER, PKCS#1 RSA DER, CBOR COSE Key, JSON JWK, or raw 32/48/66-byte scalar)
// and normalizes it to canonical PKCS#8 DER + PEM with algorithm/curve metadata.
// Never includes raw private key bytes in any returned error message.
func NormalizePrivateKey(rawEncoded string, algHint string) (*NormalizedKey, error) {
	trimmed := strings.TrimSpace(rawEncoded)
	if trimmed == "" {
		return nil, errors.New("empty private key")
	}

	// 1. Direct PEM text?
	if strings.Contains(trimmed, "-----BEGIN ") {
		return parsePEMPrivateKey([]byte(trimmed), algHint, "PEM")
	}

	// 2. Direct JSON JWK text?
	if strings.HasPrefix(trimmed, "{") {
		return parseJWKPrivateKey([]byte(trimmed))
	}

	// 3. Base64url / Base64 decode to raw bytes.
	raw, err := opcrypto.Base64URLDecode(trimmed)
	if err != nil {
		return nil, fmt.Errorf("decode private key base64: %w", err)
	}
	defer opcrypto.WipeBytes(raw)
	if len(raw) == 0 {
		return nil, errors.New("decoded private key is empty")
	}
	return normalizeKeyBytes(raw, algHint)
}

func parsePEMPrivateKey(pemBytes []byte, algHint, labelPrefix string) (*NormalizedKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid PEM private key")
	}
	if strings.Contains(strings.ToUpper(block.Type), "ENCRYPTED") ||
		strings.Contains(strings.ToUpper(block.Headers["Proc-Type"]), "ENCRYPTED") {
		return nil, errors.New("encrypted PEM private keys are not supported")
	}
	nk, err := normalizeKeyBytes(block.Bytes, algHint)
	if err != nil {
		return nil, fmt.Errorf("%s inner key: %w", labelPrefix, err)
	}
	nk.SourceFormat = labelPrefix + " (" + nk.SourceFormat + ")"
	return nk, nil
}

func normalizeKeyBytes(raw []byte, algHint string) (*NormalizedKey, error) {
	// A. Check if decoded bytes are themselves PEM or JSON JWK.
	if len(raw) > 10 && strings.HasPrefix(strings.TrimSpace(string(raw)), "-----BEGIN ") {
		return parsePEMPrivateKey(raw, algHint, "Base64-PEM")
	}
	if len(raw) > 2 && raw[0] == '{' {
		if nk, err := parseJWKPrivateKey(raw); err == nil {
			nk.SourceFormat = "Base64-JWK (" + nk.SourceFormat + ")"
			return nk, nil
		}
	}

	// B. PKCS#8 DER (most common — also what Bitwarden/CXF/WebCrypto use).
	if key, err := x509.ParsePKCS8PrivateKey(raw); err == nil {
		return marshalNormalized(key, "PKCS#8 DER")
	}

	// C. SEC1 EC PrivateKey DER (RFC 5915).
	if ecKey, err := x509.ParseECPrivateKey(raw); err == nil {
		return marshalNormalized(ecKey, "SEC1 EC DER")
	}

	// D. PKCS#1 RSA PrivateKey DER.
	if rsaKey, err := x509.ParsePKCS1PrivateKey(raw); err == nil {
		return marshalNormalized(rsaKey, "PKCS#1 RSA DER")
	}

	// E. CBOR COSE Key (RFC 9052 / 1Password passkey-rs CoseKey).
	if nk, err := parseCOSEPrivateKey(raw); err == nil {
		return nk, nil
	}

	// F. Raw EC / Ed25519 scalar bytes (32 bytes for P-256/Ed25519, 48 bytes for P-384, 66 bytes for P-521).
	if nk, err := parseRawScalar(raw, algHint); err == nil {
		return nk, nil
	}

	// Provide only structural (non-secret) container hint — never raw key bytes.
	hint := "unknown container"
	if len(raw) > 0 {
		switch {
		case raw[0] == 0x30:
			hint = "ASN.1 sequence (0x30)"
		case raw[0] >= 0xa0 && raw[0] <= 0xbf:
			hint = "CBOR map"
		}
	}
	return nil, fmt.Errorf("unrecognized private key format (%d bytes, algHint=%q, hint=%s)", len(raw), algHint, hint)
}

// ecFromScalar builds and strictly validates an ECDSA private key from raw scalar bytes d
// and optional public coordinates x, y. Rejects out-of-range scalars, oversized inputs, and
// off-curve or mismatched public points without panicking.
func ecFromScalar(curve elliptic.Curve, dBytes, xBytes, yBytes []byte) (*ecdsa.PrivateKey, error) {
	params := curve.Params()
	fieldLen := (params.BitSize + 7) / 8
	if len(dBytes) == 0 || len(dBytes) > fieldLen {
		return nil, fmt.Errorf("EC scalar length %d out of range for %s (max %d)", len(dBytes), params.Name, fieldLen)
	}
	d := new(big.Int).SetBytes(dBytes)
	if d.Sign() <= 0 || d.Cmp(params.N) >= 0 {
		return nil, fmt.Errorf("EC scalar out of range [1, N-1] for %s", params.Name)
	}

	// Always derive canonical public point from d.
	derivedX, derivedY := curve.ScalarBaseMult(d.Bytes())
	if derivedX == nil || derivedY == nil || !curve.IsOnCurve(derivedX, derivedY) {
		return nil, fmt.Errorf("failed to derive valid public point on %s", params.Name)
	}

	// If x or y were provided, both must match the derived point.
	if len(xBytes) > 0 || len(yBytes) > 0 {
		if len(xBytes) == 0 || len(yBytes) == 0 {
			return nil, fmt.Errorf("incomplete EC public coordinates for %s", params.Name)
		}
		if len(xBytes) > fieldLen || len(yBytes) > fieldLen {
			return nil, fmt.Errorf("EC public coordinate exceeds field size for %s", params.Name)
		}
		supX := new(big.Int).SetBytes(xBytes)
		supY := new(big.Int).SetBytes(yBytes)
		if supX.Cmp(derivedX) != 0 || supY.Cmp(derivedY) != 0 {
			return nil, fmt.Errorf("supplied EC public point does not match private scalar on %s", params.Name)
		}
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: derivedX, Y: derivedY},
		D:         d,
	}, nil
}

func marshalNormalized(priv any, sourceFormat string) (*NormalizedKey, error) {
	var alg, curve string
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		alg = "ECDSA"
		switch k.Curve {
		case elliptic.P256():
			curve = "P-256"
		case elliptic.P384():
			curve = "P-384"
		case elliptic.P521():
			curve = "P-521"
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve %s", k.Curve.Params().Name)
		}
	case ed25519.PrivateKey:
		alg = "EdDSA"
		curve = "Ed25519"
	case *rsa.PrivateKey:
		if k.N == nil || k.N.BitLen() < 1024 {
			return nil, errors.New("RSA private key too small (<1024 bits)")
		}
		alg = "RSA"
		curve = ""
	default:
		return nil, fmt.Errorf("unsupported private key type %T", priv)
	}

	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8DER,
	})
	return &NormalizedKey{
		PKCS8DER:     pkcs8DER,
		PKCS8PEM:     string(pemBytes),
		KeyAlgorithm: alg,
		KeyCurve:     curve,
		SourceFormat: sourceFormat,
	}, nil
}

// parseCOSEPrivateKey decodes an RFC 9052 COSE_Key CBOR map (EC2, OKP, or RSA).
func parseCOSEPrivateKey(raw []byte) (*NormalizedKey, error) {
	var m map[int64]any
	if err := cbor.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	kty, ok := toInt64(m[1])
	if !ok {
		return nil, errors.New("COSE key missing kty (1)")
	}
	switch kty {
	case 2: // EC2
		crv, ok := toInt64(m[-1])
		if !ok {
			return nil, errors.New("COSE EC2 missing crv (-1)")
		}
		var curve elliptic.Curve
		switch crv {
		case 1:
			curve = elliptic.P256()
		case 2:
			curve = elliptic.P384()
		case 3:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported COSE EC2 curve %d", crv)
		}
		dBytes, ok := m[-4].([]byte)
		if !ok || len(dBytes) == 0 {
			return nil, errors.New("COSE EC2 missing private scalar d (-4)")
		}
		xBytes, _ := m[-2].([]byte)
		yBytes, _ := m[-3].([]byte)
		priv, err := ecFromScalar(curve, dBytes, xBytes, yBytes)
		if err != nil {
			return nil, fmt.Errorf("COSE EC2: %w", err)
		}
		return marshalNormalized(priv, "COSE CBOR (EC2)")

	case 1: // OKP (Ed25519)
		crv, ok := toInt64(m[-1])
		if !ok || crv != 6 {
			return nil, fmt.Errorf("unsupported COSE OKP curve %d", crv)
		}
		dBytes, ok := m[-4].([]byte)
		if !ok || len(dBytes) != ed25519.SeedSize {
			return nil, errors.New("invalid COSE Ed25519 seed length")
		}
		priv := ed25519.NewKeyFromSeed(dBytes)
		return marshalNormalized(priv, "COSE CBOR (OKP Ed25519)")

	case 3: // RSA
		nBytes, _ := m[-1].([]byte)
		eBytes, _ := m[-2].([]byte)
		dBytes, _ := m[-3].([]byte)
		pBytes, _ := m[-4].([]byte)
		qBytes, _ := m[-5].([]byte)
		if len(nBytes) == 0 || len(eBytes) == 0 || len(dBytes) == 0 || len(pBytes) == 0 || len(qBytes) == 0 {
			return nil, errors.New("incomplete COSE RSA key")
		}
		eBig := new(big.Int).SetBytes(eBytes)
		if !eBig.IsInt64() || eBig.Int64() < 3 || eBig.Int64() > math.MaxInt32 {
			return nil, errors.New("invalid COSE RSA public exponent")
		}
		priv := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: new(big.Int).SetBytes(nBytes),
				E: int(eBig.Int64()),
			},
			D:      new(big.Int).SetBytes(dBytes),
			Primes: []*big.Int{new(big.Int).SetBytes(pBytes), new(big.Int).SetBytes(qBytes)},
		}
		priv.Precompute()
		if err := priv.Validate(); err != nil {
			return nil, err
		}
		return marshalNormalized(priv, "COSE CBOR (RSA)")
	default:
		return nil, fmt.Errorf("unsupported COSE kty %d", kty)
	}
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

func parseJWKPrivateKey(raw []byte) (*NormalizedKey, error) {
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		D   string `json:"d"`
		N   string `json:"n"`
		E   string `json:"e"`
		P   string `json:"p"`
		Q   string `json:"q"`
	}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, err
	}
	switch jwk.Kty {
	case "EC":
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported JWK EC curve %q", jwk.Crv)
		}
		dBytes, err := opcrypto.Base64URLDecode(jwk.D)
		if err != nil || len(dBytes) == 0 {
			return nil, errors.New("invalid JWK EC d")
		}
		var xBytes, yBytes []byte
		if jwk.X != "" {
			if xBytes, err = opcrypto.Base64URLDecode(jwk.X); err != nil {
				return nil, fmt.Errorf("invalid JWK EC x: %w", err)
			}
		}
		if jwk.Y != "" {
			if yBytes, err = opcrypto.Base64URLDecode(jwk.Y); err != nil {
				return nil, fmt.Errorf("invalid JWK EC y: %w", err)
			}
		}
		priv, err := ecFromScalar(curve, dBytes, xBytes, yBytes)
		if err != nil {
			return nil, fmt.Errorf("JWK EC: %w", err)
		}
		return marshalNormalized(priv, "JWK (EC)")

	case "OKP":
		if jwk.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported JWK OKP curve %q", jwk.Crv)
		}
		dBytes, err := opcrypto.Base64URLDecode(jwk.D)
		if err != nil || len(dBytes) != ed25519.SeedSize {
			return nil, errors.New("invalid JWK Ed25519 d")
		}
		return marshalNormalized(ed25519.NewKeyFromSeed(dBytes), "JWK (OKP Ed25519)")

	case "RSA":
		rsaKey, err := opcrypto.ParseRSAPrivateJWK(raw)
		if err != nil {
			return nil, err
		}
		return marshalNormalized(rsaKey.Key, "JWK (RSA)")
	default:
		return nil, fmt.Errorf("unsupported JWK kty %q", jwk.Kty)
	}
}

func parseRawScalar(raw []byte, algHint string) (*NormalizedKey, error) {
	alg := strings.ToUpper(strings.TrimSpace(algHint))
	switch len(raw) {
	case 32:
		if alg == "EDDSA" || alg == "ED25519" || alg == "-8" {
			return marshalNormalized(ed25519.NewKeyFromSeed(raw), "Raw Ed25519 seed")
		}
		if alg == "" || alg == "ES256" || alg == "-7" || alg == "ECDSA" {
			priv, err := ecFromScalar(elliptic.P256(), raw, nil, nil)
			if err != nil {
				return nil, err
			}
			return marshalNormalized(priv, "Raw P-256 scalar")
		}
	case 48:
		if alg == "" || alg == "ES384" || alg == "-35" || alg == "ECDSA" {
			priv, err := ecFromScalar(elliptic.P384(), raw, nil, nil)
			if err != nil {
				return nil, err
			}
			return marshalNormalized(priv, "Raw P-384 scalar")
		}
	case 66:
		if alg == "" || alg == "ES512" || alg == "-36" || alg == "ECDSA" {
			priv, err := ecFromScalar(elliptic.P521(), raw, nil, nil)
			if err != nil {
				return nil, err
			}
			return marshalNormalized(priv, "Raw P-521 scalar")
		}
	}
	return nil, errors.New("not a recognized raw scalar")
}
