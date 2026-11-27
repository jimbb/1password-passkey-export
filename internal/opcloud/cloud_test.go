package opcloud

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
)

func TestSRPOfficialVectors(t *testing.T) {
	// Known-answer vectors derived from github.com/1Password/srp (Apache-2.0).
	const (
		wantKHex        = "3509477ea9fca66eadb7cf7b1bd0eb508f54d3989a9c988006a7d0b338374dd2"
		xHex            = "740299d2306764ad9e87f37cd54179e388fd45c85fea3b030eb425d7adcb2773"
		wantVerifierHex = "d05240ed513a4f267608e64cf2a84f5106741ddbf1435707a84f530207409d7af1e671182f9d77855b61c628df2b8f6ba8e9b6068fbc84fab80b4542f44c666e17358ebffa8d6fb00fd7037ab9ee450413f240ab1e4b586e48bf43ce38f41ad7e406d0150ea83c8f216db4dec06ec5d9fb1cbfd049f70438fc14a2faa2a920ad1b298bb1c70989d17163cf52632f202e77824d71c0ff2dd2ef63ebdcd6140beb471b9a7f7b14e2d45478994dac95d27f2b45404e564c90eb65655bf6a789bfd665035f711b7cf766a380b921a666dfcfee0238b27eafdd8a953a50cc2c4f291458d48ef9fd0740da59aa325b9165ebb97d125511b03e1056bd448b322d7d250816783462cff6f9ecd40813522dac10329b7c4bcd0c8f0ceec2eb2c46ba442ac62a84994e2fcdb94cbfe057cad578c5e4d28822cd283e8430b8a1e1106f6e2536e8596b8a0de46717fbd4e9f06b796364aa930bbcf87433cbbbf15b077b2998569027edcae71d09112857d0fac06d9f9f70371f43f8581a229c290ade4e63251f8d8a0c961e20d357069472db3ff422c3ecacf6ff9b2af54003d6aa344a37e7a7f04a1a667d5299475cea6b02c09b58505c895efbd86703a0a375ccdf81616e8bee6cfc947467c4bcbe4a7d3e245df32cd7192e212ffe635ff8ac9727d6fe05ede8338f6f3bc18b5359ea8afc13ce3952cd426fb0934c5ea54e71e10bf81028f"
		aHex            = "f1ecc95bb29e8a360e9b257d5688c83d503506a6a6eba683f1e06"
		bHex            = "780a5495cbf731d2463fd01d28822e7d9ccf697c4239d5151f85666aa06b3767e0301b54cfad3bd2b526d4d8a1d96492e59c8d8ecddca96b7e288f186155ffa57b50df6bc2103b6004400b797334a22d9dd234b40142a5ab714ea6070d2ed55096049f50efba99862b72f7e7aee51ed71ba6663fff570cc713d456316f3535630e87a245f09b0791c6e687baa65bf2dfb5c17e50c250256cdad4c9851a2484e88326888060ae9578b5a60e0c85143b25f4fb4fca794e266a4359642da085672d6a3b881649a387875685aeb1ae3d809bf7818dcad596c6e29d566ae87c0ad645a0fcc2eb4f066c097670adf48cf0954918fda4dc30588261321d592f890eed87a950d387b48cf6b4a49f9d497323f683091ae6a4efe675d6bfc4393c0c3d54c9adad65b8dd3a7b7e85cd5d31e97bebc8f23b370348dab53903ec5085cbf65de5e5491f417e5bf9953f081e788f36c26cbe00664a1256c4befb00765ea7e432af189521442c186f14442b1957e444426f740f363ebda943da2bb3b18a13e2f41be9cc3ca0a1b111f6983f9b8d0ee0f4b573c6042fbc0ca029821ebe517ed0755a94f42d32b0abef9240af0f37b5fe0e90c4ca83acf91d28a7f3acff5657bf69fdb7747e380b23fd437f637da2f7ebcf8733a69a75715fe3894e1799906b48e3ae818332cf5f9533e7af5a1f065f907c8f31fe778fa2da853e69926fc551d6b3ae"
		uHex            = "dad353365f78590c1857b29f16e3a947df4707868e2dd2d2b4eafd35c8c854a1"
		wantKeyHex      = "f6bef3d6fa5a08a849bf61041cd5b3185c16aede851c819a3644fa7e918c4da6"
	)

	if gotK := hex.EncodeToString(standardK().Bytes()); gotK != wantKHex {
		t.Fatalf("standardK = %s, want %s", gotK, wantKHex)
	}

	xBytes, err := hex.DecodeString(xHex)
	if err != nil {
		t.Fatal(err)
	}
	aInt, ok := new(big.Int).SetString(aHex, 16)
	if !ok {
		t.Fatal("bad aHex")
	}
	bInt, ok := new(big.Int).SetString(bHex, 16)
	if !ok {
		t.Fatal("bad bHex")
	}
	uInt, ok := new(big.Int).SetString(uHex, 16)
	if !ok {
		t.Fatal("bad uHex")
	}
	kInt := new(big.Int).SetBytes([]byte("H27JRK5M4NBJXOBCOETCVXJHFA"))

	client := newSRPClientWithParams(xBytes, aInt.Bytes(), kInt)
	defer client.Wipe()

	if gotV := bigIntToServerHex(client.Verifier()); gotV != wantVerifierHex {
		t.Fatalf("Verifier mismatch:\n got=%s\nwant=%s", gotV, wantVerifierHex)
	}
	gotKey, err := client.sessionKeyWithU(bInt, uInt)
	if err != nil {
		t.Fatalf("sessionKeyWithU: %v", err)
	}
	if hex.EncodeToString(gotKey) != wantKeyHex {
		t.Fatalf("sessionKey = %x, want %s", gotKey, wantKeyHex)
	}
}

func TestSRPRejectsInvalidServerB(t *testing.T) {
	c, err := NewSRPClient(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Wipe()

	for _, bad := range []*big.Int{nil, big.NewInt(0), big.NewInt(1), new(big.Int).Set(srpN4096)} {
		if _, err := c.SessionKey(bad); err == nil {
			t.Fatalf("expected error for invalid server B=%v", bad)
		}
	}
}

func TestCloudRejectsInsecureBaseURL(t *testing.T) {
	_, err := Export(context.Background(), Options{
		Email:     "clouduser@example.com",
		Password:  "pw",
		SecretKey: "A3-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE-FFFFF",
		BaseURL:   "http://example.com/api/",
	})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS rejection for non-loopback HTTP BaseURL, got: %v", err)
	}
}

func TestRequestMACOfficialVectors(t *testing.T) {
	// Official known-answer test vectors from github.com/1Password/burp-1password-session-analyzer (BSD-3-Clause).
	cases := []struct {
		expected string
		sid      string
		rid      uint32
		method   string
		rawURL   string
		keyB64   string
	}{
		{
			"v1|6|oBnE8JLpG2Othzgy",
			"RDPMIFQWUJBWZFDBKURHNRFVRA", 6, "GET",
			"https://my.b5local.com:3000/api/v1/invites",
			"ETmGs4U7ReMolW1J64ZAmmksXbQFFbeyRPW6zPWj3VM",
		},
		{
			"v1|7|E2w1PDPlDRKaVEQs",
			"RDPMIFQWUJBWZFDBKURHNRFVRA", 7, "GET",
			"https://my.b5local.com:3000/api/v2/users?limit=25&states=P&types=G,R",
			"ETmGs4U7ReMolW1J64ZAmmksXbQFFbeyRPW6zPWj3VM",
		},
		{
			"v1|7|JDqt1exoqPCjZiAJ",
			"QVLABIG34RB3TMH7ZJEW47CCKE", 7, "GET",
			"https://my.b5local.com:3000/api/v1/vaults?permission=read&attrs=accessor-previews%2Ccombined-access",
			"-K_oZ-mtamTiLJODQn5cVhXQX-nFmPI2kosmWmOWfZg",
		},
		{
			"v1|3907223784|Htb-Sn_9k4u59wOz",
			"VADBXWG7FVC6FIOKOJ4DBGE4SY", 3907223784, "DELETE",
			"https://awesome.b5dev.com/api/v1/vault/p3nfd4jax622nqjos7licewuyn",
			"xvoJlJo7KkJGQ55-mjd7tOBE6YvRYnGBNpPoo3_F2M0",
		},
		{
			"v1|781158249|kkvpSd6stufwwlsZ",
			"2UG2ZGCDLFAWRHPETAV325EL5U", 781158249, "GET",
			"https://awesome.b5dev.com/api/v1/auditevents/0/older?object_types=gva,invite",
			"WDs9nvg0DYYmQmucwPZ25FV6uUSaYsJUgse7apbs6rk",
		},
	}

	for _, tc := range cases {
		key, err := opcrypto.Base64URLDecode(tc.keyB64)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(tc.rawURL)
		if err != nil {
			t.Fatal(err)
		}
		got := RequestMAC(key, tc.sid, tc.rid, tc.method, u)
		if got != tc.expected {
			t.Fatalf("RequestMAC(%s) = %q, want %q", tc.rawURL, got, tc.expected)
		}
	}
}

func TestCloudEndToEndMockServer(t *testing.T) {
	email := "clouduser@example.com"
	password := "Cloud-Pass-2026!"
	skStr := "A3-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE-FFFFF"
	sk, _ := opcrypto.ParseSecretKey(skStr)
	authSalt := bytes.Repeat([]byte{0x77}, 16)
	authIters := 100
	sessionID := "TESTSESSIONID1234567890123"
	totpExpected := "123456"

	// Server-side SRP verifier v = g^x mod N
	srpX, _ := opcrypto.Compute2SKD(sk, password, email, opcrypto.SRPMethod4096, authSalt, authIters)
	xInt := new(big.Int).SetBytes(srpX)
	vInt := new(big.Int).Exp(srpG4096, xInt, srpN4096)

	// Prepare keyset, vault, and passkey item
	aukSalt := bytes.Repeat([]byte{0x55}, 16)
	auk, _ := opcrypto.Compute2SKD(sk, password, email, opcrypto.AlgPBES2gHS256, aukSalt, 100)
	ksSym := make([]byte, 32)
	_, _ = rand.Read(ksSym)
	ksRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	ksSymJWK, _ := json.Marshal(opcrypto.JWK{Kty: "oct", Kid: "ks1", Alg: "A256GCM", K: opcrypto.Base64URLEncode(ksSym)})
	encKsSym, _ := opcrypto.EncryptAESGCM("mp", auk, "b5+jwk+json", ksSymJWK)
	encKsSym.Alg = opcrypto.AlgPBES2gHS256
	encKsSym.P2s = opcrypto.Base64URLEncode(aukSalt)
	encKsSym.P2c = 100
	ksPriJWK, _ := json.Marshal(opcrypto.JWK{
		Kty: "RSA", Kid: "ks1", Alg: "RSA-OAEP-256",
		N: opcrypto.Base64URLEncode(ksRSA.N.Bytes()),
		E: opcrypto.Base64URLEncode(big.NewInt(int64(ksRSA.E)).Bytes()),
		D: opcrypto.Base64URLEncode(ksRSA.D.Bytes()),
		P: opcrypto.Base64URLEncode(ksRSA.Primes[0].Bytes()),
		Q: opcrypto.Base64URLEncode(ksRSA.Primes[1].Bytes()),
	})
	encKsPri, _ := opcrypto.EncryptAESGCM("ks1", ksSym, "b5+jwk+json", ksPriJWK)

	vaultKey := make([]byte, 32)
	_, _ = rand.Read(vaultKey)
	vaultKeyJWK, _ := json.Marshal(opcrypto.JWK{Kty: "oct", Kid: "v1", Alg: "A256GCM", K: opcrypto.Base64URLEncode(vaultKey)})
	vaultKeyCT, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &ksRSA.PublicKey, vaultKeyJWK, nil)
	encVaultKey := &opcrypto.EncryptedObject{Kid: "ks1", Enc: "RSA-OAEP-256", Cty: "b5+jwk+json", Data: opcrypto.Base64URLEncode(vaultKeyCT)}
	encVaultAttrs, _ := opcrypto.EncryptAESGCM("v1", vaultKey, "b5+json", []byte(`{"name":"Cloud Vault"}`))

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8DER, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	credID := []byte("cloud-cred-id-12345")
	userHandle := []byte("cloud-user-handle")
	ovJSON, _ := json.Marshal(map[string]any{
		"title": "Cloud Passkey Site",
		"passkey": map[string]any{
			"credentialId": opcrypto.Base64URLEncode(credID),
			"rpId":         "cloud.example.com",
			"userHandle":   opcrypto.Base64URLEncode(userHandle),
		},
	})
	detJSON, _ := json.Marshal(map[string]any{
		"fields": []map[string]any{{"designation": "username", "type": "T", "value": "clouduser"}},
		"passkey": map[string]any{
			"type":       "webauthn",
			"createdAt":  1732500000,
			"privateKey": opcrypto.Base64URLEncode(pkcs8DER),
			"alg":        "ES256",
			"userHandle": opcrypto.Base64URLEncode(userHandle),
		},
	})
	encOv, _ := opcrypto.EncryptAESGCM("v1", vaultKey, "b5+json", ovJSON)
	encDet, _ := opcrypto.EncryptAESGCM("v1", vaultKey, "b5+json", detJSON)

	var (
		deviceRegistered bool
		serverSessionKey []byte
		clientA          *big.Int
		serverB          *big.Int
		mfaPassed        bool
		signedOut        bool
	)

	kInt := standardK()

	replyEnc := func(w http.ResponseWriter, v any) {
		b, _ := json.Marshal(v)
		env, _ := opcrypto.EncryptAESGCM(sessionID, serverSessionKey, "b5+jwk+json", b)
		_ = json.NewEncoder(w).Encode(env)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/auth/start":
			if !deviceRegistered {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":    "device-not-registered",
					"sessionID": sessionID,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "ok",
				"sessionID":        sessionID,
				"accountKeyFormat": sk.Format,
				"accountKeyUuid":   sk.AccountID,
				"userAuth": map[string]any{
					"method":     opcrypto.SRPMethod4096,
					"salt":       opcrypto.Base64URLEncode(authSalt),
					"iterations": authIters,
				},
			})
		case "/api/v1/device":
			deviceRegistered = true
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case "/api/v2/auth":
			var body struct{ UserA string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			clientA, _ = parseServerHex(body.UserA)
			bRand := make([]byte, 38)
			_, _ = rand.Read(bRand)
			bInt := new(big.Int).SetBytes(bRand)
			// B = (k*v + g^b) mod N
			kv := new(big.Int).Mul(kInt, vInt)
			gb := new(big.Int).Exp(srpG4096, bInt, srpN4096)
			serverB = new(big.Int).Add(kv, gb)
			serverB.Mod(serverB, srpN4096)

			// u = SHA256(PAD(A) || PAD(B))
			uh := sha256.New()
			uh.Write(padModN(clientA, srpN4096))
			uh.Write(padModN(serverB, srpN4096))
			uInt := new(big.Int).SetBytes(uh.Sum(nil))
			// S = (A * v^u)^b mod N
			vu := new(big.Int).Exp(vInt, uInt, srpN4096)
			avu := new(big.Int).Mul(clientA, vu)
			avu.Mod(avu, srpN4096)
			sInt := new(big.Int).Exp(avu, bInt, srpN4096)
			kSum := sha256.Sum256([]byte(bigIntToServerHex(sInt)))
			serverSessionKey = kSum[:]

			_ = json.NewEncoder(w).Encode(map[string]any{"userB": bigIntToServerHex(serverB)})
		case "/api/v2/auth/confirm-key":
			var body struct{ ClientVerifyHash string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			m1, _ := opcrypto.Base64URLDecode(body.ClientVerifyHash)
			// Verify server confirmation hash SHA256(A || M1 || K)
			sh := sha256.New()
			sh.Write(clientA.Bytes())
			sh.Write(m1)
			sh.Write(serverSessionKey)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"serverVerifyHash": opcrypto.Base64URLEncode(sh.Sum(nil)),
			})
		case "/api/v2/auth/complete":
			replyEnc(w, map[string]any{
				"userUuid": "user-1",
				"mfa":      map[string]any{"totp": map[string]any{"enabled": true}},
			})
		case "/api/v1/auth/mfa":
			var env opcrypto.EncryptedObject
			_ = json.NewDecoder(r.Body).Decode(&env)
			plain, err := opcrypto.DecryptAESGCM(&env, serverSessionKey)
			if err != nil {
				http.Error(w, "bad enc", 400)
				return
			}
			var mfaReq struct {
				TOTP struct{ Code string } `json:"totp"`
			}
			_ = json.Unmarshal(plain, &mfaReq)
			if mfaReq.TOTP.Code != totpExpected {
				http.Error(w, "bad totp", 401)
				return
			}
			mfaPassed = true
			w.WriteHeader(200)
		case "/api/v1/account/keysets":
			if !mfaPassed {
				http.Error(w, "mfa required", 401)
				return
			}
			replyEnc(w, map[string]any{
				"keysets": []map[string]any{{
					"uuid": "ks1", "sn": 1, "encryptedBy": "mp",
					"encSymKey": encKsSym, "encPriKey": encKsPri,
				}},
			})
		case "/api/v1/account":
			replyEnc(w, map[string]any{
				"account": map[string]any{"uuid": "acct-cloud-1", "type": "I"},
				"me":      map[string]any{"name": "Cloud Alice", "email": email},
				"vaults": []map[string]any{{
					"uuid": "v1", "type": "P", "encAttrs": encVaultAttrs,
					"access": []map[string]any{{"acl": 63, "encVaultKey": encVaultKey}},
				}},
			})
		case "/api/v1/vault/v1/0/items":
			replyEnc(w, map[string]any{
				"contentVersion": 1,
				"batchComplete":  false,
				"items": []map[string]any{{
					"uuid": "item-1", "templateUuid": "001", "trashed": "N",
					"encOverview": encOv, "encDetails": encDet,
				}},
			})
		case "/api/v1/vault/v1/1/items":
			replyEnc(w, map[string]any{
				"contentVersion": 1,
				"batchComplete":  true,
				"items":          []map[string]any{},
			})
		case "/api/v1/session/signout":
			signedOut = true
			w.WriteHeader(200)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	exp, err := Export(context.Background(), Options{
		Email:            email,
		Password:         password,
		SecretKey:        skStr,
		BaseURL:          srv.URL + "/api/",
		MinKDFIterations: 100,
		PromptTOTP:       func() (string, error) { return totpExpected, nil },
	})
	if err != nil {
		t.Fatalf("cloud Export: %v", err)
	}
	if !signedOut {
		t.Fatal("expected clean sign-out")
	}
	if exp.TotalPasskeys() != 1 {
		t.Fatalf("expected 1 passkey, got %d", exp.TotalPasskeys())
	}
	pk := exp.Vaults[0].Items[0].Passkeys[0]
	if pk.RPID != "cloud.example.com" || !bytes.Equal(pk.CredentialID, credID) {
		t.Fatalf("unexpected passkey: %+v", pk)
	}
	if !bytes.Equal(pk.PrivateKeyPKCS8DER, pkcs8DER) {
		t.Fatal("decrypted cloud passkey private key mismatch")
	}
}
