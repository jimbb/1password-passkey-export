package exporter

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"

	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
	"github.com/jimbb/1password-passkey-export/internal/opmodel"
)

// KeePassXC KPEX_PASSKEY_* attribute names (verified against keepassxreboot/keepassxc src/core/EntryAttributes.cpp).
const (
	kpexCredentialID  = "KPEX_PASSKEY_CREDENTIAL_ID"
	kpexPrivateKeyPEM = "KPEX_PASSKEY_PRIVATE_KEY_PEM"
	kpexRelyingParty  = "KPEX_PASSKEY_RELYING_PARTY"
	kpexUsername      = "KPEX_PASSKEY_USERNAME"
	kpexUserHandle    = "KPEX_PASSKEY_USER_HANDLE"
	kpexFlagBE        = "KPEX_PASSKEY_FLAG_BE"
	kpexFlagBS        = "KPEX_PASSKEY_FLAG_BS"

	// Strong Argon2 KDF parameters for exported KDBX 4 files (KeePassXC recommended baseline).
	kdbxArgon2Memory      uint64 = 64 * 1024 * 1024 // 64 MiB
	kdbxArgon2Iterations  uint64 = 3
	kdbxArgon2Parallelism uint32 = 2
	kdbxArgon2Version     uint32 = 0x13
)

// ExportKDBX creates an encrypted KeePassXC KDBX 4 database containing the exported vaults,
// logins, and passkeys using KeePassXC's native KPEX_PASSKEY_* entry attributes.
func ExportKDBX(acct *opmodel.AccountExport, kdbxPassword string, opts Options) ([]byte, error) {
	if kdbxPassword == "" {
		return nil, errors.New("KDBX master password must not be empty")
	}

	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion40())
	db.Header.FileHeaders.KdfParameters.UUID = gokeepasslib.KdfArgon2
	db.Header.FileHeaders.KdfParameters.Memory = kdbxArgon2Memory
	db.Header.FileHeaders.KdfParameters.Iterations = kdbxArgon2Iterations
	db.Header.FileHeaders.KdfParameters.Parallelism = kdbxArgon2Parallelism
	db.Header.FileHeaders.KdfParameters.Version = kdbxArgon2Version

	db.Credentials = gokeepasslib.NewPasswordCredentials(kdbxPassword)
	db.Content.Meta.DatabaseName = "1Password Export"
	if acct.Email != "" {
		db.Content.Meta.DatabaseDescription = "Exported from 1Password (" + acct.Email + ")"
	}

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"

	for _, vault := range acct.Vaults {
		group := gokeepasslib.NewGroup()
		group.Name = vault.Name

		for _, item := range vault.Items {
			if opts.PasskeysOnly && len(item.Passkeys) == 0 {
				continue
			}

			if len(item.Passkeys) <= 1 {
				var pk *opmodel.Passkey
				if len(item.Passkeys) == 1 {
					pk = &item.Passkeys[0]
				}
				entry, err := buildKDBXEntry(item, pk, 0)
				if err != nil {
					return nil, err
				}
				group.Entries = append(group.Entries, entry)
			} else {
				// KeePassXC stores one passkey per entry; emit one entry per passkey if an item has multiple.
				for idx := range item.Passkeys {
					pk := item.Passkeys[idx]
					entry, err := buildKDBXEntry(item, &pk, idx+1)
					if err != nil {
						return nil, err
					}
					group.Entries = append(group.Entries, entry)
				}
			}
		}

		if len(group.Entries) > 0 {
			rootGroup.Groups = append(rootGroup.Groups, group)
		}
	}

	db.Content.Root = &gokeepasslib.RootData{
		Groups: []gokeepasslib.Group{rootGroup},
	}

	if err := db.LockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("lock protected KDBX entries: %w", err)
	}

	var buf bytes.Buffer
	enc := gokeepasslib.NewEncoder(&buf)
	if err := enc.Encode(db); err != nil {
		return nil, fmt.Errorf("encode KDBX 4 database: %w", err)
	}
	return buf.Bytes(), nil
}

func buildKDBXEntry(item opmodel.Item, pk *opmodel.Passkey, multiIndex int) (gokeepasslib.Entry, error) {
	entry := gokeepasslib.NewEntry()

	title := strings.TrimSpace(item.Title)
	if title == "" && pk != nil && pk.RPID != "" {
		title = pk.RPID
	}
	if title == "" && len(item.URLs) > 0 {
		title = item.URLs[0]
	}
	if title == "" {
		title = "Untitled"
	}
	if multiIndex > 1 {
		title = fmt.Sprintf("%s (Passkey %d)", title, multiIndex)
	}

	if pk != nil {
		if err := validatePasskeyForExport(title, *pk); err != nil {
			return gokeepasslib.Entry{}, err
		}
	}

	usedKeys := map[string]bool{
		"Title": true, "UserName": true, "Password": true, "URL": true, "Notes": true, "otp": true,
		kpexCredentialID: true, kpexPrivateKeyPEM: true, kpexRelyingParty: true,
		kpexUsername: true, kpexUserHandle: true, kpexFlagBE: true, kpexFlagBS: true,
	}

	setPlain := func(k, v string) {
		if v == "" {
			return
		}
		usedKeys[k] = true
		entry.Values = append(entry.Values, gokeepasslib.ValueData{
			Key:   k,
			Value: gokeepasslib.V{Content: v},
		})
	}
	setProtected := func(k, v string) {
		if v == "" {
			return
		}
		usedKeys[k] = true
		entry.Values = append(entry.Values, gokeepasslib.ValueData{
			Key:   k,
			Value: gokeepasslib.V{Content: v, Protected: wrappers.NewBoolWrapper(true)},
		})
	}

	setPlain("Title", title)
	username := item.Username
	if username == "" && pk != nil {
		username = pk.UserName
	}
	setPlain("UserName", username)
	setProtected("Password", item.Password)
	if len(item.URLs) > 0 {
		setPlain("URL", item.URLs[0])
		for i, extraURL := range item.URLs[1:] {
			setPlain(fmt.Sprintf("KP2A_URL_%d", i+1), extraURL)
		}
	}
	setPlain("Notes", item.Notes)

	if totpURI := buildKDBXTOTPURI(item.TOTP, title, username); totpURI != "" {
		setProtected("otp", totpURI)
	}

	// Tags
	tags := make([]string, 0, len(item.Tags)+2)
	tags = append(tags, item.Tags...)
	if item.Favorite {
		tags = append(tags, "Favorite")
	}

	if pk != nil {
		tags = append(tags, "Passkey")
		setProtected(kpexCredentialID, opcrypto.Base64URLEncode(pk.CredentialID))
		setProtected(kpexPrivateKeyPEM, strings.TrimSpace(pk.PrivateKeyPEM))
		setPlain(kpexRelyingParty, pk.RPID)
		setPlain(kpexUsername, pk.UserName)
		setProtected(kpexUserHandle, opcrypto.Base64URLEncode(pk.UserHandle))
		setPlain(kpexFlagBE, "1")
		setPlain(kpexFlagBS, "1")
	}

	if len(tags) > 0 {
		entry.Tags = strings.Join(dedupeStrings(tags), ";")
	}

	for _, cf := range item.CustomFields {
		k := strings.TrimSpace(cf.Name)
		if cf.Section != "" && !strings.EqualFold(cf.Section, k) {
			if k == "" {
				k = strings.TrimSpace(cf.Section)
			} else {
				k = strings.TrimSpace(cf.Section) + " - " + k
			}
		}
		if k == "" {
			continue
		}
		k = uniqueAttrKey(k, usedKeys)
		if cf.Concealed {
			setProtected(k, cf.Value)
		} else {
			setPlain(k, cf.Value)
		}
	}

	if !item.CreatedAt.IsZero() {
		entry.Times.CreationTime = &wrappers.TimeWrapper{Time: item.CreatedAt.UTC()}
	}
	if !item.UpdatedAt.IsZero() {
		entry.Times.LastModificationTime = &wrappers.TimeWrapper{Time: item.UpdatedAt.UTC()}
	}

	return entry, nil
}

func buildKDBXTOTPURI(raw, title, username string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		return raw
	}
	secret := normalizeTOTPSecret(raw)
	if secret == "" {
		return ""
	}
	issuer := strings.ReplaceAll(strings.TrimSpace(title), ":", "_")
	account := strings.ReplaceAll(strings.TrimSpace(username), ":", "_")
	if account == "" {
		account = "account"
	}
	label := url.PathEscape(account)
	if issuer != "" {
		label = url.PathEscape(issuer) + ":" + label
	}
	q := url.Values{}
	q.Set("secret", secret)
	if issuer != "" {
		q.Set("issuer", issuer)
	}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func uniqueAttrKey(base string, used map[string]bool) string {
	if !used[base] {
		return base
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s (%d)", base, n)
		if !used[candidate] {
			return candidate
		}
	}
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
