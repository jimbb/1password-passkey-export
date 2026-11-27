package opcrypto

import (
	"fmt"
	"sort"
	"strings"
)

// RawKeyset represents an encrypted 1Password keyset from either SQLite or the cloud API.
type RawKeyset struct {
	UUID        string
	SN          int
	EncryptedBy string // "mp" for primary keyset, or parent keyset UUID
	EncSymKey   *EncryptedObject
	EncPriKey   *EncryptedObject
}

// UnlockedKeyset holds the decrypted symmetric and RSA private keys for one keyset.
type UnlockedKeyset struct {
	UUID    string
	SN      int
	SymKey  *SymmetricKey
	PrivKey *RSAPrivateKey
}

// Keyring maps keyset UUIDs to their unlocked keys and unwraps vault keys.
type Keyring struct {
	Keysets map[string]*UnlockedKeyset
}

// Wipe zeroes symmetric and RSA private key material held in memory (best-effort in Go).
func (k *Keyring) Wipe() {
	if k == nil {
		return
	}
	for _, ks := range k.Keysets {
		if ks.SymKey != nil {
			ks.SymKey.Wipe()
		}
		if ks.PrivKey != nil {
			ks.PrivKey.Wipe()
		}
	}
}

// UnlockKeysets derives the Account Unlock Key via 2SKD and decrypts the full keyset chain.
// Returns the unlocked keyring plus non-fatal warnings for any retired/broken secondary keysets.
func UnlockKeysets(raw []RawKeyset, sk *SecretKey, password, email string) (*Keyring, []string, error) {
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("no keysets provided")
	}

	// Sort deterministically by SN ascending so parent keysets are visited cleanly.
	ordered := make([]RawKeyset, len(raw))
	copy(ordered, raw)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].SN < ordered[j].SN })

	kr := &Keyring{Keysets: make(map[string]*UnlockedKeyset)}
	var warnings []string

	// 1. Unlock every master-password-protected ("mp") keyset first.
	mpCount := 0
	var mpErrors []string
	var lastMPErr error
	for _, ks := range ordered {
		if ks.EncryptedBy != "mp" {
			continue
		}
		mpCount++
		if ks.EncSymKey == nil {
			err := fmt.Errorf("keyset %s missing encSymKey", ks.UUID)
			lastMPErr = err
			mpErrors = append(mpErrors, err.Error())
			continue
		}
		alg := ks.EncSymKey.Alg
		if alg == "" {
			alg = AlgPBES2gHS256
		}
		if !strings.HasPrefix(alg, "PBES2") {
			err := fmt.Errorf("keyset %s unsupported KDF alg %q", ks.UUID, alg)
			lastMPErr = err
			mpErrors = append(mpErrors, err.Error())
			continue
		}
		salt, err := Base64URLDecode(ks.EncSymKey.P2s)
		if err != nil {
			err = fmt.Errorf("keyset %s decode salt: %w", ks.UUID, err)
			lastMPErr = err
			mpErrors = append(mpErrors, err.Error())
			continue
		}
		auk, err := Compute2SKD(sk, password, email, alg, salt, ks.EncSymKey.P2c)
		if err != nil {
			err = fmt.Errorf("keyset %s 2SKD: %w", ks.UUID, err)
			lastMPErr = err
			mpErrors = append(mpErrors, err.Error())
			continue
		}
		symJSON, err := DecryptAESGCM(ks.EncSymKey, auk)
		WipeBytes(auk)
		if err != nil {
			err = fmt.Errorf("wrong master password, secret key, or email (decrypting keyset %s): %w", ks.UUID, err)
			lastMPErr = err
			mpErrors = append(mpErrors, err.Error())
			continue
		}
		unlocked, err := finishKeyset(ks, symJSON)
		WipeBytes(symJSON)
		if err != nil {
			lastMPErr = err
			mpErrors = append(mpErrors, err.Error())
			continue
		}
		kr.Keysets[ks.UUID] = unlocked
	}

	if mpCount == 0 {
		kr.Wipe()
		return nil, nil, fmt.Errorf("no master-password keyset (encryptedBy == \"mp\") found")
	}
	if len(kr.Keysets) == 0 {
		kr.Wipe()
		return nil, nil, lastMPErr
	}
	warnings = append(warnings, mpErrors...)

	// 2. Iteratively unlock chained keysets encrypted by previously unlocked keysets.
	failedChained := make(map[string]bool)
	for progress := true; progress; {
		progress = false
		for _, ks := range ordered {
			if _, done := kr.Keysets[ks.UUID]; done || failedChained[ks.UUID] {
				continue
			}
			parent, ok := kr.Keysets[ks.EncryptedBy]
			if !ok && ks.EncSymKey != nil {
				parent, ok = kr.Keysets[ks.EncSymKey.Kid]
			}
			if !ok || ks.EncSymKey == nil {
				continue
			}

			var symJSON []byte
			var err error
			if ks.EncSymKey.Enc == "A256GCM" {
				symJSON, err = DecryptAESGCM(ks.EncSymKey, parent.SymKey.Key)
			} else {
				symJSON, err = DecryptRSAOAEP(parent.PrivKey, ks.EncSymKey)
			}
			if err != nil {
				failedChained[ks.UUID] = true
				warnings = append(warnings, fmt.Sprintf("skipped chained keyset %s (parent %s): %v", ks.UUID, parent.UUID, err))
				continue
			}
			unlocked, err := finishKeyset(ks, symJSON)
			WipeBytes(symJSON)
			if err != nil {
				failedChained[ks.UUID] = true
				warnings = append(warnings, fmt.Sprintf("skipped chained keyset %s: %v", ks.UUID, err))
				continue
			}
			kr.Keysets[ks.UUID] = unlocked
			progress = true
		}
	}

	// Report any keysets left unreachable after chaining finishes.
	for _, ks := range ordered {
		if _, done := kr.Keysets[ks.UUID]; !done && !failedChained[ks.UUID] && ks.EncryptedBy != "mp" {
			warnings = append(warnings, fmt.Sprintf("keyset %s could not be reached (encryptedBy=%q)", ks.UUID, ks.EncryptedBy))
		}
	}

	return kr, warnings, nil
}

func finishKeyset(ks RawKeyset, symJSON []byte) (*UnlockedKeyset, error) {
	symKey, err := ParseSymmetricJWK(symJSON)
	if err != nil {
		return nil, fmt.Errorf("keyset %s sym JWK: %w", ks.UUID, err)
	}
	if symKey.KID == "" {
		symKey.KID = ks.UUID
	}
	var privKey *RSAPrivateKey
	if ks.EncPriKey != nil {
		priJSON, err := DecryptAESGCM(ks.EncPriKey, symKey.Key)
		if err != nil {
			symKey.Wipe()
			return nil, fmt.Errorf("keyset %s decrypt encPriKey: %w", ks.UUID, err)
		}
		privKey, err = ParseRSAPrivateJWK(priJSON)
		WipeBytes(priJSON)
		if err != nil {
			symKey.Wipe()
			return nil, fmt.Errorf("keyset %s parse RSA private key: %w", ks.UUID, err)
		}
		if privKey.KID == "" {
			privKey.KID = ks.UUID
		}
	}
	return &UnlockedKeyset{
		UUID:    ks.UUID,
		SN:      ks.SN,
		SymKey:  symKey,
		PrivKey: privKey,
	}, nil
}

// UnwrapVaultKey decrypts a vault's enc_vault_key using the matching unlocked keyset.
func (k *Keyring) UnwrapVaultKey(encVaultKey *EncryptedObject) (*SymmetricKey, error) {
	if encVaultKey == nil {
		return nil, fmt.Errorf("enc_vault_key is nil")
	}
	ks, ok := k.Keysets[encVaultKey.Kid]
	if !ok {
		return nil, fmt.Errorf("no unlocked keyset with kid %q", encVaultKey.Kid)
	}
	var plain []byte
	var err error
	if encVaultKey.Enc == "A256GCM" {
		plain, err = DecryptAESGCM(encVaultKey, ks.SymKey.Key)
	} else {
		plain, err = DecryptRSAOAEP(ks.PrivKey, encVaultKey)
	}
	if err != nil {
		return nil, fmt.Errorf("unwrap vault key (kid=%s): %w", encVaultKey.Kid, err)
	}
	defer WipeBytes(plain)
	return ParseSymmetricJWK(plain)
}
