package exporter

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
	"github.com/jimbb/1password-passkey-export/internal/opmodel"
)

// Options controls filtering and formatting across exporters.
type Options struct {
	PasskeysOnly bool // when true, only export items that contain at least one passkey
}

// Namespace UUIDs for deterministic RFC-4122 UUIDv5 IDs in exports.
var (
	nsFolder = uuid.MustParse("7f2b5031-764e-4b3e-8d2f-3b5c4d2e1a10")
	nsItem   = uuid.MustParse("8e3c6142-875f-4c4f-9e30-4c6d5e3f2b21")
)

type bitwardenExport struct {
	Encrypted bool              `json:"encrypted"`
	Folders   []bitwardenFolder `json:"folders"`
	Items     []bitwardenItem   `json:"items"`
}

type bitwardenFolder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type bitwardenItem struct {
	ID              string                `json:"id"`
	FolderID        *string               `json:"folderId"`
	OrganizationID  *string               `json:"organizationId"`
	CollectionIDs   *[]string             `json:"collectionIds"`
	Type            int                   `json:"type"`
	Name            string                `json:"name"`
	Notes           *string               `json:"notes"`
	Favorite        bool                  `json:"favorite"`
	Reprompt        int                   `json:"reprompt"`
	Fields          []bitwardenField      `json:"fields,omitempty"`
	Login           *bitwardenLogin       `json:"login,omitempty"`
	SecureNote      *bitwardenSecureNote  `json:"secureNote,omitempty"`
	SSHKey          *bitwardenSSHKey      `json:"sshKey,omitempty"`
	PasswordHistory *[]bitwardenPwHistory `json:"passwordHistory"`
	RevisionDate    string                `json:"revisionDate"`
	CreationDate    string                `json:"creationDate"`
	DeletedDate     *string               `json:"deletedDate"`
}

type bitwardenLogin struct {
	Username         *string              `json:"username"`
	Password         *string              `json:"password"`
	URIs             []bitwardenLoginURI  `json:"uris"`
	TOTP             *string              `json:"totp"`
	Fido2Credentials []bitwardenFido2Cred `json:"fido2Credentials,omitempty"`
}

type bitwardenLoginURI struct {
	URI   *string `json:"uri"`
	Match *int    `json:"match"`
}

type bitwardenFido2Cred struct {
	CredentialID    string  `json:"credentialId"`
	KeyType         string  `json:"keyType"`
	KeyAlgorithm    string  `json:"keyAlgorithm"`
	KeyCurve        string  `json:"keyCurve"`
	KeyValue        string  `json:"keyValue"`
	RPID            string  `json:"rpId"`
	UserHandle      *string `json:"userHandle"`
	UserName        *string `json:"userName"`
	Counter         string  `json:"counter"`
	RPName          *string `json:"rpName"`
	UserDisplayName *string `json:"userDisplayName"`
	Discoverable    string  `json:"discoverable"`
	CreationDate    string  `json:"creationDate"`
}

type bitwardenSecureNote struct {
	Type int `json:"type"`
}

type bitwardenSSHKey struct {
	PrivateKey     string `json:"privateKey"`
	PublicKey      string `json:"publicKey"`
	KeyFingerprint string `json:"keyFingerprint"`
}

type bitwardenField struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Type     int    `json:"type"` // 0=Text, 1=Hidden
	LinkedID *int   `json:"linkedId"`
}

type bitwardenPwHistory struct {
	Password     string `json:"password"`
	LastUsedDate string `json:"lastUsedDate"`
}

func validatePasskeyForExport(itemTitle string, pk opmodel.Passkey) error {
	if len(pk.PrivateKeyPKCS8DER) == 0 {
		return fmt.Errorf("item %q: passkey has empty PKCS#8 private key; refusing to export broken credential", itemTitle)
	}
	if len(pk.CredentialID) == 0 {
		return fmt.Errorf("item %q: passkey has empty credentialId; refusing to export broken credential", itemTitle)
	}
	if strings.TrimSpace(pk.RPID) == "" {
		return fmt.Errorf("item %q: passkey has empty rpId; refusing to export broken credential", itemTitle)
	}
	return nil
}

// ExportBitwardenJSON converts decrypted 1Password vaults into Bitwarden unencrypted JSON format,
// including login.fido2Credentials[] for all passkeys.
func ExportBitwardenJSON(acct *opmodel.AccountExport, opts Options) ([]byte, error) {
	out := bitwardenExport{
		Encrypted: false,
		Folders:   make([]bitwardenFolder, 0, len(acct.Vaults)),
		Items:     make([]bitwardenItem, 0),
	}

	for _, vault := range acct.Vaults {
		folderID := uuid.NewSHA1(nsFolder, []byte(vault.UUID)).String()
		vaultHasItems := false

		for _, item := range vault.Items {
			if opts.PasskeysOnly && len(item.Passkeys) == 0 {
				continue
			}
			vaultHasItems = true

			if len(item.Passkeys) <= 1 {
				var pk *opmodel.Passkey
				if len(item.Passkeys) == 1 {
					pk = &item.Passkeys[0]
				}
				bwItem, err := toBitwardenItem(item, folderID, pk, 0)
				if err != nil {
					return nil, err
				}
				out.Items = append(out.Items, bwItem)
			} else {
				// Bitwarden clients only use fido2Credentials[0], so split multi-passkey items into one login per passkey.
				for idx := range item.Passkeys {
					pk := item.Passkeys[idx]
					bwItem, err := toBitwardenItem(item, folderID, &pk, idx+1)
					if err != nil {
						return nil, err
					}
					out.Items = append(out.Items, bwItem)
				}
			}
		}

		if vaultHasItems {
			out.Folders = append(out.Folders, bitwardenFolder{
				ID:   folderID,
				Name: vault.Name,
			})
		}
	}

	return json.MarshalIndent(out, "", "  ")
}

func toBitwardenItem(item opmodel.Item, folderID string, pk *opmodel.Passkey, multiIndex int) (bitwardenItem, error) {
	idSeed := item.VaultUUID + ":" + item.UUID
	if multiIndex > 1 {
		idSeed = fmt.Sprintf("%s:pk:%d", idSeed, multiIndex)
	}
	itemID := uuid.NewSHA1(nsItem, []byte(idSeed)).String()
	fid := folderID

	name := strings.TrimSpace(item.Title)
	if name == "" && pk != nil && pk.RPID != "" {
		name = pk.RPID
	}
	if name == "" && len(item.URLs) > 0 {
		name = item.URLs[0]
	}
	if name == "" {
		name = "Untitled"
	}
	if multiIndex > 1 {
		name = fmt.Sprintf("%s (Passkey %d)", name, multiIndex)
	}

	var fields []bitwardenField
	for _, cf := range item.CustomFields {
		ft := 0
		if cf.Concealed {
			ft = 1
		}
		fname := cf.Name
		if cf.Section != "" && !strings.EqualFold(cf.Section, fname) {
			fname = cf.Section + ": " + fname
		}
		fields = append(fields, bitwardenField{
			Name:  fname,
			Value: cf.Value,
			Type:  ft,
		})
	}
	if len(item.Tags) > 0 {
		fields = append(fields, bitwardenField{
			Name:  "tags",
			Value: strings.Join(item.Tags, ", "),
			Type:  0,
		})
	}

	bw := bitwardenItem{
		ID:           itemID,
		FolderID:     &fid,
		Name:         name,
		Notes:        trimmedStrPtrOrNil(item.Notes),
		Favorite:     item.Favorite,
		Reprompt:     0,
		Fields:       fields,
		CreationDate: formatBWTimestamp(item.CreatedAt),
		RevisionDate: formatBWTimestamp(item.UpdatedAt),
	}

	// Items with passkeys, login credentials, TOTP, or Login/Password category become Bitwarden Logins (type 1).
	if pk != nil || item.CategoryUUID == opmodel.CategoryLogin || item.CategoryUUID == opmodel.CategoryPassword ||
		item.Username != "" || item.Password != "" || item.TOTP != "" {
		bw.Type = 1
		uris := make([]bitwardenLoginURI, 0, len(item.URLs))
		for _, u := range item.URLs {
			uCopy := u
			uris = append(uris, bitwardenLoginURI{URI: &uCopy})
		}
		var fido2 []bitwardenFido2Cred
		if pk != nil {
			if err := validatePasskeyForExport(name, *pk); err != nil {
				return bitwardenItem{}, err
			}
			fido2 = []bitwardenFido2Cred{toBitwardenFido2(*pk)}
		}
		bw.Login = &bitwardenLogin{
			Username:         rawStrPtrOrNil(item.Username),
			Password:         rawStrPtrOrNil(item.Password),
			URIs:             uris,
			TOTP:             trimmedStrPtrOrNil(item.TOTP),
			Fido2Credentials: fido2,
		}
	} else if item.SSHKey != nil && item.CategoryUUID == opmodel.CategorySSHKey {
		bw.Type = 5
		bw.SSHKey = &bitwardenSSHKey{
			PrivateKey:     item.SSHKey.PrivateKey,
			PublicKey:      item.SSHKey.PublicKey,
			KeyFingerprint: item.SSHKey.Fingerprint,
		}
	} else {
		bw.Type = 2
		bw.SecureNote = &bitwardenSecureNote{Type: 0}
	}

	return bw, nil
}

func toBitwardenFido2(pk opmodel.Passkey) bitwardenFido2Cred {
	// Bitwarden expects "b64.<base64url_nopad>" for imported passkey credential IDs of any byte length.
	credID := "b64." + opcrypto.Base64URLEncode(pk.CredentialID)
	keyVal := opcrypto.Base64URLEncode(pk.PrivateKeyPKCS8DER)

	var userHandle *string
	if len(pk.UserHandle) > 0 {
		s := opcrypto.Base64URLEncode(pk.UserHandle)
		userHandle = &s
	}

	discoverable := "true"
	if !pk.Discoverable {
		discoverable = "false"
	}

	alg := pk.KeyAlgorithm
	if alg == "" {
		alg = "ECDSA"
	}
	curve := pk.KeyCurve
	if curve == "" && alg == "ECDSA" {
		curve = "P-256"
	}

	return bitwardenFido2Cred{
		CredentialID:    credID,
		KeyType:         "public-key",
		KeyAlgorithm:    alg,
		KeyCurve:        curve,
		KeyValue:        keyVal,
		RPID:            pk.RPID,
		UserHandle:      userHandle,
		UserName:        rawStrPtrOrNil(pk.UserName),
		Counter:         fmt.Sprintf("%d", pk.Counter),
		RPName:          trimmedStrPtrOrNil(pk.RPName),
		UserDisplayName: rawStrPtrOrNil(pk.UserDisplayName),
		Discoverable:    discoverable,
		CreationDate:    formatBWTimestamp(pk.CreatedAt),
	}
}

func formatBWTimestamp(t time.Time) string {
	if t.IsZero() {
		return "1970-01-01T00:00:00.000Z"
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func trimmedStrPtrOrNil(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

func rawStrPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
