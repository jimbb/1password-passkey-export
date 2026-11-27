package exporter

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
	"github.com/jimbb/1password-passkey-export/internal/opmodel"
)

// FIDO Credential Exchange Format (CXF 1.0) structures matching
// fidoalliance.org/specs/cx/cxf-v1.0, Bitwarden's cxf importer/exporter,
// and KeePassXC's CredentialExchangeReader/Writer.

type cxfHeader struct {
	Version             cxfVersion   `json:"version"`
	ExporterRPID        string       `json:"exporterRpId"`
	ExporterDisplayName string       `json:"exporterDisplayName"`
	Timestamp           int64        `json:"timestamp"`
	Accounts            []cxfAccount `json:"accounts"`
}

type cxfVersion struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

type cxfAccount struct {
	ID          string          `json:"id"`
	Username    string          `json:"username"`
	Email       string          `json:"email"`
	FullName    string          `json:"fullName,omitempty"`
	Collections []cxfCollection `json:"collections"`
	Items       []cxfItem       `json:"items"`
}

type cxfCollection struct {
	ID    string          `json:"id"`
	Title string          `json:"title"`
	Items []cxfLinkedItem `json:"items"`
}

type cxfLinkedItem struct {
	Item string `json:"item"`
}

type cxfItem struct {
	ID          string    `json:"id"`
	CreationAt  *int64    `json:"creationAt,omitempty"`
	ModifiedAt  *int64    `json:"modifiedAt,omitempty"`
	Title       string    `json:"title"`
	Subtitle    string    `json:"subtitle,omitempty"`
	Favorite    bool      `json:"favorite,omitempty"`
	Scope       *cxfScope `json:"scope,omitempty"`
	Credentials []any     `json:"credentials"`
	Tags        []string  `json:"tags,omitempty"`
}

type cxfScope struct {
	URLs        []string `json:"urls"`
	AndroidApps []any    `json:"androidApps"`
}

type cxfEditableField struct {
	FieldType string `json:"fieldType"`
	Value     string `json:"value"`
	Label     string `json:"label,omitempty"`
}

type cxfBasicAuthCred struct {
	Type     string            `json:"type"`
	Username *cxfEditableField `json:"username,omitempty"`
	Password *cxfEditableField `json:"password,omitempty"`
}

type cxfTotpCred struct {
	Type      string `json:"type"`
	Secret    string `json:"secret"`
	Period    int    `json:"period"`
	Digits    int    `json:"digits"`
	Username  string `json:"username,omitempty"`
	Algorithm string `json:"algorithm"`
	Issuer    string `json:"issuer,omitempty"`
}

type cxfNoteCred struct {
	Type    string           `json:"type"`
	Content cxfEditableField `json:"content"`
}

type cxfCustomFieldsCred struct {
	Type   string             `json:"type"`
	Fields []cxfEditableField `json:"fields"`
}

type cxfSSHKeyCred struct {
	Type       string `json:"type"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey,omitempty"`
}

type cxfPasskeyCred struct {
	Type            string              `json:"type"`
	CredentialID    string              `json:"credentialId"`
	RPID            string              `json:"rpId"`
	Username        string              `json:"username"`
	UserDisplayName string              `json:"userDisplayName"`
	UserHandle      string              `json:"userHandle"`
	Key             string              `json:"key"`
	Fido2Extensions *cxfFido2Extensions `json:"fido2Extensions,omitempty"`
}

type cxfFido2Extensions struct {
	HmacCredentials *cxfHmacCredentials `json:"hmacCredentials,omitempty"`
}

type cxfHmacCredentials struct {
	Algorithm  string `json:"algorithm"`
	CredWithUV string `json:"credWithUV,omitempty"`
}

// ExportCXFJSON converts decrypted 1Password vaults into FIDO Credential Exchange Format (CXF 1.0) JSON.
func ExportCXFJSON(acct *opmodel.AccountExport, opts Options) ([]byte, error) {
	acctUUID := uuid.NewSHA1(nsFolder, []byte("account:"+acct.AccountUUID+":"+acct.Email))
	cxfAcct := cxfAccount{
		ID:          opcrypto.Base64URLEncode(acctUUID[:]),
		Username:    acct.Email,
		Email:       acct.Email,
		FullName:    acct.UserName,
		Collections: make([]cxfCollection, 0),
		Items:       make([]cxfItem, 0),
	}

	for _, vault := range acct.Vaults {
		colUUID := uuid.NewSHA1(nsFolder, []byte(vault.UUID))
		col := cxfCollection{
			ID:    opcrypto.Base64URLEncode(colUUID[:]),
			Title: vault.Name,
			Items: make([]cxfLinkedItem, 0),
		}

		for _, item := range vault.Items {
			if opts.PasskeysOnly && len(item.Passkeys) == 0 {
				continue
			}
			itemUUID := uuid.NewSHA1(nsItem, []byte(item.VaultUUID+":"+item.UUID))
			itemIDB64 := opcrypto.Base64URLEncode(itemUUID[:])

			creds := make([]any, 0, len(item.Passkeys)+4)

			// Passkey credentials
			for _, pk := range item.Passkeys {
				if err := validatePasskeyForExport(item.Title, pk); err != nil {
					return nil, err
				}
				pkCred := cxfPasskeyCred{
					Type:            "passkey",
					CredentialID:    opcrypto.Base64URLEncode(pk.CredentialID),
					RPID:            pk.RPID,
					Username:        pk.UserName,
					UserDisplayName: pk.UserDisplayName,
					UserHandle:      opcrypto.Base64URLEncode(pk.UserHandle),
					Key:             opcrypto.Base64URLEncode(pk.PrivateKeyPKCS8DER),
				}
				if pk.PRF != nil && len(pk.PRF.CredWithUV) > 0 {
					alg := strings.ToLower(strings.ReplaceAll(pk.PRF.Algorithm, "_", "-"))
					if alg == "" {
						alg = "hmac-sha256"
					}
					pkCred.Fido2Extensions = &cxfFido2Extensions{
						HmacCredentials: &cxfHmacCredentials{
							Algorithm:  alg,
							CredWithUV: opcrypto.Base64URLEncode(pk.PRF.CredWithUV),
						},
					}
				}
				creds = append(creds, pkCred)
			}

			// Basic-auth credential (username/password)
			if item.Username != "" || item.Password != "" {
				ba := cxfBasicAuthCred{Type: "basic-auth"}
				if item.Username != "" {
					ba.Username = &cxfEditableField{FieldType: "string", Value: item.Username}
				}
				if item.Password != "" {
					ba.Password = &cxfEditableField{FieldType: "concealed-string", Value: item.Password}
				}
				creds = append(creds, ba)
			}

			// TOTP credential
			if item.TOTP != "" {
				if totp := parseTOTPForCXF(item.TOTP); totp != nil {
					creds = append(creds, *totp)
				}
			}

			// SSH key credential
			if item.SSHKey != nil && strings.TrimSpace(item.SSHKey.PrivateKey) != "" {
				creds = append(creds, cxfSSHKeyCred{
					Type:       "ssh-key",
					PrivateKey: item.SSHKey.PrivateKey,
					PublicKey:  item.SSHKey.PublicKey,
				})
			}

			// Note credential
			if strings.TrimSpace(item.Notes) != "" {
				creds = append(creds, cxfNoteCred{
					Type:    "note",
					Content: cxfEditableField{FieldType: "string", Value: item.Notes},
				})
			}

			// Custom fields credential (preserves recovery codes, extra secrets, etc.)
			if len(item.CustomFields) > 0 {
				cfFields := make([]cxfEditableField, 0, len(item.CustomFields))
				for _, cf := range item.CustomFields {
					ft := "string"
					if cf.Concealed {
						ft = "concealed-string"
					}
					label := cf.Name
					if cf.Section != "" && !strings.EqualFold(cf.Section, label) {
						label = cf.Section + ": " + label
					}
					cfFields = append(cfFields, cxfEditableField{
						FieldType: ft,
						Value:     cf.Value,
						Label:     label,
					})
				}
				creds = append(creds, cxfCustomFieldsCred{
					Type:   "custom-fields",
					Fields: cfFields,
				})
			}

			var scope *cxfScope
			if len(item.URLs) > 0 {
				scope = &cxfScope{
					URLs:        item.URLs,
					AndroidApps: []any{},
				}
			}

			subtitle := item.Username
			if subtitle == "" && len(item.Passkeys) > 0 {
				subtitle = item.Passkeys[0].UserName
			}

			var createdAt, modifiedAt *int64
			if !item.CreatedAt.IsZero() {
				v := item.CreatedAt.UTC().Unix()
				createdAt = &v
			}
			if !item.UpdatedAt.IsZero() {
				v := item.UpdatedAt.UTC().Unix()
				modifiedAt = &v
			}

			cxfAcct.Items = append(cxfAcct.Items, cxfItem{
				ID:          itemIDB64,
				CreationAt:  createdAt,
				ModifiedAt:  modifiedAt,
				Title:       item.Title,
				Subtitle:    subtitle,
				Favorite:    item.Favorite,
				Scope:       scope,
				Credentials: creds,
				Tags:        item.Tags,
			})
			col.Items = append(col.Items, cxfLinkedItem{Item: itemIDB64})
		}

		if len(col.Items) > 0 {
			cxfAcct.Collections = append(cxfAcct.Collections, col)
		}
	}

	header := cxfHeader{
		Version:             cxfVersion{Major: 1, Minor: 0},
		ExporterRPID:        "1p-passkey-export.local",
		ExporterDisplayName: "1Password Passkey Exporter",
		Timestamp:           time.Now().UTC().Unix(),
		Accounts:            []cxfAccount{cxfAcct},
	}

	return json.MarshalIndent(header, "", "  ")
}

func parseTOTPForCXF(raw string) *cxfTotpCred {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	cred := &cxfTotpCred{
		Type:      "totp",
		Period:    30,
		Digits:    6,
		Algorithm: "sha1",
	}
	if !strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		secret := normalizeTOTPSecret(raw)
		if secret == "" {
			return nil
		}
		cred.Secret = secret
		return cred
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	q := u.Query()
	secret := normalizeTOTPSecret(q.Get("secret"))
	if secret == "" {
		return nil
	}
	cred.Secret = secret
	if p, err := strconv.Atoi(q.Get("period")); err == nil && p > 0 {
		cred.Period = p
	}
	if d, err := strconv.Atoi(q.Get("digits")); err == nil && d > 0 {
		cred.Digits = d
	}
	if alg := strings.ToLower(strings.TrimSpace(q.Get("algorithm"))); alg != "" {
		switch alg {
		case "sha1", "sha256", "sha512":
			cred.Algorithm = alg
		default:
			cred.Algorithm = "unknown"
		}
	}
	if iss := strings.TrimSpace(q.Get("issuer")); iss != "" {
		cred.Issuer = iss
	}
	label := strings.TrimPrefix(u.Path, "/")
	if parts := strings.SplitN(label, ":", 2); len(parts) == 2 {
		if cred.Issuer == "" {
			cred.Issuer = strings.TrimSpace(parts[0])
		}
		cred.Username = strings.TrimSpace(parts[1])
	} else if label != "" {
		cred.Username = strings.TrimSpace(label)
	}
	return cred
}

func normalizeTOTPSecret(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}
