package opmodel

import (
	"time"
)

// Category UUID constants used by 1Password.
const (
	CategoryLogin          = "001"
	CategoryCreditCard     = "002"
	CategorySecureNote     = "003"
	CategoryIdentity       = "004"
	CategoryPassword       = "005"
	CategoryDocument       = "006"
	CategorySoftwareLic    = "100"
	CategoryBankAccount    = "101"
	CategoryDatabase       = "102"
	CategoryDriverLicense  = "103"
	CategoryOutdoorLicense = "104"
	CategoryMembership     = "105"
	CategoryPassport       = "106"
	CategoryRewardProgram  = "107"
	CategorySSN            = "108"
	CategoryWirelessRouter = "109"
	CategoryServer         = "110"
	CategoryEmailAccount   = "111"
	CategoryAPICredential  = "112"
	CategoryMedicalRecord  = "113"
	CategorySSHKey         = "114"
)

// AccountExport is the complete decrypted output from either SQLite or Cloud.
type AccountExport struct {
	AccountUUID string
	Email       string
	UserName    string
	SignInURL   string
	Source      string // "sqlite" or "cloud"
	Vaults      []Vault
	Warnings    []string
}

// Vault is a decrypted 1Password vault with its active items.
type Vault struct {
	UUID      string
	Name      string
	VaultType string // "P" (Personal/Private), "E" (Everyone), "U" (User-created)
	Items     []Item
}

// Item is a decrypted 1Password item normalized for export.
type Item struct {
	UUID         string
	VaultUUID    string
	VaultName    string
	CategoryUUID string
	Title        string
	Username     string
	Password     string
	URLs         []string
	Notes        string
	TOTP         string
	Tags         []string
	Favorite     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	CustomFields []CustomField
	Passkeys     []Passkey
	SSHKey       *SSHKey

	// Inspect metadata (never contains secret values)
	PasskeyInspect []PasskeyDiagnostic
}

// CustomField preserves non-standard fields from a 1Password item.
type CustomField struct {
	Section   string
	Name      string
	Value     string
	Concealed bool
}

// SSHKey holds SSH key material when present on an item.
type SSHKey struct {
	PrivateKey  string
	PublicKey   string
	Fingerprint string
}

// PRFData holds optional WebAuthn PRF / hmac-secret extension material.
type PRFData struct {
	Algorithm  string // e.g. "HMAC_SHA256"
	CredWithUV []byte // raw bytes
}

// Passkey is a normalized WebAuthn passkey ready for export to Bitwarden, CXF, or KeePassXC.
type Passkey struct {
	CredentialID    []byte // raw credential ID bytes
	RPID            string
	RPName          string
	UserHandle      []byte // raw user handle bytes
	UserName        string
	UserDisplayName string
	Counter         uint32
	Discoverable    bool
	CreatedAt       time.Time

	// Normalized private key material
	PrivateKeyPKCS8DER []byte // canonical PKCS#8 DER
	PrivateKeyPEM      string // canonical PKCS#8 PEM ("-----BEGIN PRIVATE KEY-----...")
	KeyAlgorithm       string // "ECDSA", "EdDSA", "RSA"
	KeyCurve           string // "P-256", "P-384", "P-521", "Ed25519", ""
	SourceAlg          string // e.g. "ES256"
	SourceFormat       string // detected encoding inside 1Password (e.g. "PKCS#8 DER", "COSE CBOR")

	PRF *PRFData
}

// PasskeyDiagnostic holds safe, non-secret inspection info about passkey fields found in an item.
type PasskeyDiagnostic struct {
	ItemUUID        string   `json:"itemUuid"`
	VaultName       string   `json:"vaultName"`
	ItemTitle       string   `json:"itemTitle"`
	Location        string   `json:"location"`
	Type            string   `json:"type,omitempty"`
	Alg             string   `json:"alg,omitempty"`
	RPID            string   `json:"rpId,omitempty"`
	CredIDBytes     int      `json:"credentialIdBytes"`
	UserHandleBytes int      `json:"userHandleBytes"`
	PrivateKeyBytes int      `json:"privateKeyBytes"`
	DetectedFormat  string   `json:"detectedKeyFormat,omitempty"`
	KeyAlgorithm    string   `json:"keyAlgorithm,omitempty"`
	KeyCurve        string   `json:"keyCurve,omitempty"`
	HasPRF          bool     `json:"hasPrf"`
	OverviewKeys    []string `json:"overviewPasskeyKeys,omitempty"`
	DetailsKeys     []string `json:"detailsPasskeyKeys,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// TotalPasskeys returns the total number of exportable passkeys across all vaults.
func (a *AccountExport) TotalPasskeys() int {
	n := 0
	for _, v := range a.Vaults {
		for _, it := range v.Items {
			n += len(it.Passkeys)
		}
	}
	return n
}

// TotalItems returns the total number of items across all vaults.
func (a *AccountExport) TotalItems() int {
	n := 0
	for _, v := range a.Vaults {
		n += len(v.Items)
	}
	return n
}
