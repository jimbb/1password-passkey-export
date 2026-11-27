package opsqlite

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
	"github.com/jimbb/1password-passkey-export/internal/opmodel"
)

// AccountSummary describes an account row discovered in 1password.sqlite.
type AccountSummary struct {
	RowID                 int64  `json:"rowId,omitempty"`
	AccountUUID           string `json:"accountUuid"`
	Email                 string `json:"email"`
	UserName              string `json:"userName,omitempty"`
	SignInURL             string `json:"signInUrl,omitempty"`
	AccountType           string `json:"accountType,omitempty"`
	PlaintextSecretKey    string `json:"-"` // NEVER serialize to JSON!
	HasPlaintextSecretKey bool   `json:"hasPlaintextSecretKey"`
	HasStoredSecretKey    bool   `json:"hasStoredSecretKey"`
	SchemaVersion         int    `json:"schemaVersion"`
}

// Options configures reading from a local 1password.sqlite database.
type Options struct {
	DBPath         string
	AccountFilter  string // optional: match account UUID, email, or sign-in URL
	EmailOverride  string // optional: override email used for 2SKD if needed
	Password       string
	SecretKey      string // A3-... (required unless plaintext secret_key is present in DB)
	IncludeTrashed bool
	VaultFilter    string // optional: filter by vault name or UUID
}

// DefaultDBPaths returns candidate paths for 1Password 8's local SQLite cache on the current OS.
func DefaultDBPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	switch runtime.GOOS {
	case "darwin":
		return []string{
			filepath.Join(home, "Library", "Group Containers", "2BUA8C4S2C.com.1password", "Library", "Application Support", "1Password", "Data", "1password.sqlite"),
		}
	case "windows":
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			localAppData = filepath.Join(home, "AppData", "Local")
		}
		return []string{
			filepath.Join(localAppData, "1Password", "data", "1password.sqlite"),
			filepath.Join(localAppData, "1Password", "1password.sqlite"),
		}
	default: // linux and other unix
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" {
			xdgConfig = filepath.Join(home, ".config")
		}
		return []string{
			filepath.Join(xdgConfig, "1Password", "data", "1password.sqlite"),
			filepath.Join(xdgConfig, "1Password", "1password.sqlite"),
			filepath.Join(home, ".var", "app", "com.onepassword.OnePassword", "config", "1Password", "data", "1password.sqlite"),
			filepath.Join(home, "snap", "1password", "current", ".config", "1Password", "data", "1password.sqlite"),
		}
	}
}

// FindDefaultDB locates the first existing 1password.sqlite on this machine.
func FindDefaultDB() (string, error) {
	candidates := DefaultDBPaths()
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("could not find 1password.sqlite in default locations (%s); pass --db <path>", strings.Join(candidates, ", "))
}

type openedDB struct {
	db       *sql.DB
	tempDir  string
	warnings []string
}

func (o *openedDB) Close() {
	if o == nil {
		return
	}
	if o.db != nil {
		_ = o.db.Close()
	}
	if o.tempDir != "" {
		_ = os.RemoveAll(o.tempDir)
	}
}

func makeFileURI(absPath, query string) string {
	uriPath := filepath.ToSlash(absPath)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	return u.String() + "?" + query
}

func probeReadable(db *sql.DB) error {
	// Touch sqlite_master so SQLite actually reads the DB pages (and WAL/SHM if in WAL mode).
	var n int
	return db.QueryRow(`SELECT count(*) FROM sqlite_master`).Scan(&n)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func openReadOnly(path string) (*openedDB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("stat sqlite db %q: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}

	// 1. Try direct read-only mode (reads WAL/SHM when directory allows SHM creation/mapping).
	roURI := makeFileURI(abs, "mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)")
	if db, err := sql.Open("sqlite", roURI); err == nil {
		if probeErr := probeReadable(db); probeErr == nil {
			return &openedDB{db: db}, nil
		}
		_ = db.Close()
	}

	// 2. If a non-empty -wal sidecar exists, copy DB + WAL + SHM into a private 0700 temp dir
	// so SQLite can replay the WAL safely without touching the original files or dropping recent passkeys.
	walPath := abs + "-wal"
	walInfo, walErr := os.Stat(walPath)
	hasNonEmptyWAL := walErr == nil && !walInfo.IsDir() && walInfo.Size() > 0

	if hasNonEmptyWAL {
		tmpDir, err := os.MkdirTemp("", "1p-sqlite-copy-*")
		if err == nil {
			_ = os.Chmod(tmpDir, 0700)
			dstDB := filepath.Join(tmpDir, "1password.sqlite")
			if err := copyFile(abs, dstDB); err == nil {
				_ = copyFile(walPath, dstDB+"-wal")
				if _, shmErr := os.Stat(abs + "-shm"); shmErr == nil {
					_ = copyFile(abs+"-shm", dstDB+"-shm")
				}
				// Open temp copy in read-only mode (writable dir allows SHM so WAL is replayed cleanly).
				tmpURI := makeFileURI(dstDB, "mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)")
				if db, err := sql.Open("sqlite", tmpURI); err == nil {
					if probeErr := probeReadable(db); probeErr == nil {
						return &openedDB{db: db, tempDir: tmpDir}, nil
					}
					_ = db.Close()
				}
			}
			_ = os.RemoveAll(tmpDir)
		}
	}

	// 3. Fallback: immutable=1 (for standalone copied DB files on read-only media).
	immURI := makeFileURI(abs, "immutable=1&_pragma=query_only(1)")
	db, err := sql.Open("sqlite", immURI)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db %q: %w", path, err)
	}
	if err := probeReadable(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read sqlite db %q: %w", path, err)
	}
	opened := &openedDB{db: db}
	if hasNonEmptyWAL {
		opened.warnings = append(opened.warnings,
			fmt.Sprintf("opened %q with immutable=1 while a non-empty WAL (%s) exists; recent passkeys still in WAL may be missing — quit 1Password or copy the DB + -wal/-shm files together", path, walPath))
	}
	return opened, nil
}

func tableExists(db *sql.DB, name string) bool {
	var found string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&found)
	return err == nil && found == name
}

func tableHasColumn(db *sql.DB, table, column string) bool {
	var found string
	err := db.QueryRow(`SELECT name FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&found)
	return err == nil && found == column
}

func getSchemaVersion(db *sql.DB) int {
	if !tableExists(db, "config") {
		return 0
	}
	var ver int
	if err := db.QueryRow(`SELECT CAST(value AS INTEGER) FROM config WHERE name = 'version'`).Scan(&ver); err != nil {
		return 0
	}
	return ver
}

type accountBlob struct {
	AccountUUID    string `json:"account_uuid"`
	UserEmail      string `json:"user_email"`
	UserName       string `json:"user_name"`
	SignInURL      string `json:"sign_in_url"`
	AccountType    string `json:"account_type"`
	SignInProvider struct {
		Type      string `json:"type"`
		SecretKey string `json:"secret_key"`
	} `json:"sign_in_provider"`
}

// ListAccounts returns all accounts stored in the given 1password.sqlite file.
func ListAccounts(dbPath string) ([]AccountSummary, error) {
	opened, err := openReadOnly(dbPath)
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	return listAccountsDB(opened.db)
}

func listAccountsDB(db *sql.DB) ([]AccountSummary, error) {
	if !tableExists(db, "accounts") {
		return nil, errors.New("not a valid 1Password 8 SQLite database: missing 'accounts' table")
	}
	version := getSchemaVersion(db)
	hasID := tableHasColumn(db, "accounts", "id")

	query := `SELECT 0, account_uuid, data FROM accounts`
	if hasID {
		query = `SELECT id, account_uuid, data FROM accounts`
	}
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query accounts: %w", err)
	}
	defer rows.Close()

	var out []AccountSummary
	for rows.Next() {
		var rowID int64
		var acctUUID string
		var rawData []byte
		if err := rows.Scan(&rowID, &acctUUID, &rawData); err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		var blob accountBlob
		if err := json.Unmarshal(rawData, &blob); err != nil {
			return nil, fmt.Errorf("parse account JSON (%s): %w", acctUUID, err)
		}
		summary := AccountSummary{
			RowID:              rowID,
			AccountUUID:        acctUUID,
			Email:              blob.UserEmail,
			UserName:           blob.UserName,
			SignInURL:          blob.SignInURL,
			AccountType:        blob.AccountType,
			HasStoredSecretKey: strings.TrimSpace(blob.SignInProvider.SecretKey) != "",
			SchemaVersion:      version,
		}
		// Some older/Linux DBs store the Secret Key in plaintext A3-... form.
		if _, err := opcrypto.ParseSecretKey(blob.SignInProvider.SecretKey); err == nil {
			summary.PlaintextSecretKey = blob.SignInProvider.SecretKey
			summary.HasPlaintextSecretKey = true
		}
		out = append(out, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Export reads and decrypts vaults, items, and passkeys from a local 1password.sqlite file.
func Export(opts Options) (*opmodel.AccountExport, error) {
	dbPath := opts.DBPath
	if dbPath == "" {
		var err error
		dbPath, err = FindDefaultDB()
		if err != nil {
			return nil, err
		}
	}
	if opts.Password == "" {
		return nil, errors.New("master password is required")
	}

	opened, err := openReadOnly(dbPath)
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	db := opened.db

	accounts, err := listAccountsDB(db)
	if err != nil {
		return nil, err
	}
	if len(accounts) == 0 {
		return nil, errors.New("no accounts found in 1password.sqlite")
	}

	selected, err := selectAccount(accounts, opts.AccountFilter)
	if err != nil {
		return nil, err
	}

	email := selected.Email
	if strings.TrimSpace(opts.EmailOverride) != "" {
		email = strings.TrimSpace(opts.EmailOverride)
	}
	if email == "" {
		return nil, errors.New("account email missing in database; pass --email")
	}

	secretKeyStr := strings.TrimSpace(opts.SecretKey)
	if secretKeyStr == "" && selected.PlaintextSecretKey != "" {
		secretKeyStr = selected.PlaintextSecretKey
	}
	if secretKeyStr == "" {
		return nil, errors.New("1Password Secret Key is required (pass --secret-key or set OP_SECRET_KEY)")
	}
	sk, err := opcrypto.ParseSecretKey(secretKeyStr)
	if err != nil {
		return nil, fmt.Errorf("parse secret key: %w", err)
	}

	rawKeysets, err := loadKeysets(db, selected)
	if err != nil {
		return nil, err
	}
	keyring, ksWarnings, err := opcrypto.UnlockKeysets(rawKeysets, sk, opts.Password, email)
	if err != nil {
		return nil, err
	}
	defer keyring.Wipe()

	rawVaults, err := loadVaults(db, selected)
	if err != nil {
		return nil, err
	}

	export := &opmodel.AccountExport{
		AccountUUID: selected.AccountUUID,
		Email:       email,
		UserName:    selected.UserName,
		SignInURL:   selected.SignInURL,
		Source:      "sqlite",
		Warnings:    append(append([]string(nil), opened.warnings...), ksWarnings...),
	}

	vaultFilter := strings.TrimSpace(opts.VaultFilter)

	for _, rv := range rawVaults {
		vaultKey, err := keyring.UnwrapVaultKey(rv.EncVaultKey)
		if err != nil {
			export.Warnings = append(export.Warnings, fmt.Sprintf("vault %s: skipped (%v)", rv.UUID, err))
			continue
		}

		vaultName := decryptVaultName(vaultKey, rv.EncAttrs, rv.VaultType, selected.AccountType, rv.UUID)

		if vaultFilter != "" && !strings.EqualFold(vaultName, vaultFilter) && rv.UUID != vaultFilter {
			vaultKey.Wipe()
			continue
		}

		rawItems, itemLoadWarns, err := loadItems(db, selected, rv, opts.IncludeTrashed)
		export.Warnings = append(export.Warnings, itemLoadWarns...)
		if err != nil {
			vaultKey.Wipe()
			return nil, fmt.Errorf("load items for vault %q (%s): %w", vaultName, rv.UUID, err)
		}

		vault := opmodel.Vault{
			UUID:      rv.UUID,
			Name:      vaultName,
			VaultType: rv.VaultType,
		}

		for _, ri := range rawItems {
			var ovPlain, detPlain []byte
			if ri.EncOverview != nil {
				ovPlain, err = opcrypto.DecryptAESGCM(ri.EncOverview, vaultKey.Key)
				if err != nil {
					export.Warnings = append(export.Warnings, fmt.Sprintf("vault %q item %s: decrypt overview failed: %v", vaultName, ri.UUID, err))
					continue
				}
			}
			if ri.EncDetails != nil {
				detPlain, err = opcrypto.DecryptAESGCM(ri.EncDetails, vaultKey.Key)
				if err != nil {
					opcrypto.WipeBytes(ovPlain)
					export.Warnings = append(export.Warnings, fmt.Sprintf("vault %q item %s: decrypt details failed: %v", vaultName, ri.UUID, err))
					continue
				}
			}

			item, itemWarns, err := opmodel.ExtractItem(
				rv.UUID, vaultName, ri.UUID, ri.CategoryUUID,
				ri.CreatedAt, ri.UpdatedAt, ri.Favorite,
				ovPlain, detPlain,
			)
			opcrypto.WipeBytes(ovPlain)
			opcrypto.WipeBytes(detPlain)
			if err != nil {
				export.Warnings = append(export.Warnings, fmt.Sprintf("vault %q item %s: parse failed: %v", vaultName, ri.UUID, err))
				continue
			}
			export.Warnings = append(export.Warnings, itemWarns...)
			vault.Items = append(vault.Items, *item)
		}

		vaultKey.Wipe()
		export.Vaults = append(export.Vaults, vault)
	}

	return export, nil
}

func selectAccount(accounts []AccountSummary, filter string) (AccountSummary, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		if len(accounts) == 1 {
			return accounts[0], nil
		}
		var desc []string
		for _, a := range accounts {
			desc = append(desc, fmt.Sprintf("%s (%s, %s)", a.Email, a.AccountUUID, a.SignInURL))
		}
		return AccountSummary{}, fmt.Errorf("multiple accounts in 1password.sqlite (%s); specify one with --account", strings.Join(desc, "; "))
	}
	for _, a := range accounts {
		if a.AccountUUID == filter || strings.EqualFold(a.Email, filter) || strings.EqualFold(a.SignInURL, filter) {
			return a, nil
		}
	}
	return AccountSummary{}, fmt.Errorf("no account matching %q in 1password.sqlite", filter)
}

func loadKeysets(db *sql.DB, acct AccountSummary) ([]opcrypto.RawKeyset, error) {
	var keysets []opcrypto.RawKeyset

	// 1. Modern (v61+) & v60 objects_associated (type = 36).
	if tableExists(db, "objects_associated") {
		var rows *sql.Rows
		var err error
		if tableHasColumn(db, "objects_associated", "account_uuid") {
			rows, err = db.Query(`SELECT key_name, data FROM objects_associated WHERE account_uuid = ? AND type = 36`, acct.AccountUUID)
		} else if tableHasColumn(db, "objects_associated", "associated_account") {
			rows, err = db.Query(`SELECT key_name, data FROM objects_associated WHERE associated_account = ? AND type = 36`, acct.RowID)
		}
		if err != nil {
			return nil, fmt.Errorf("query objects_associated keysets: %w", err)
		}
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var keyName string
				var data []byte
				if err := rows.Scan(&keyName, &data); err != nil {
					return nil, fmt.Errorf("scan keyset: %w", err)
				}
				ks, err := parseKeysetRow(keyName, data)
				if err != nil {
					return nil, fmt.Errorf("parse keyset %s: %w", keyName, err)
				}
				keysets = append(keysets, ks)
			}
			if err := rows.Err(); err != nil {
				return nil, err
			}
		}
	}

	// 2. Fallback for pre-v60 schemas: account_objects (object_type = 'keyset').
	if len(keysets) == 0 && tableExists(db, "account_objects") {
		rows, err := db.Query(`SELECT uuid, data FROM account_objects WHERE account_id = ? AND object_type = 'keyset'`, acct.RowID)
		if err != nil {
			return nil, fmt.Errorf("query account_objects keysets: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var uuid string
			var data []byte
			if err := rows.Scan(&uuid, &data); err != nil {
				return nil, fmt.Errorf("scan legacy keyset: %w", err)
			}
			ks, err := parseKeysetRow(uuid, data)
			if err != nil {
				return nil, fmt.Errorf("parse legacy keyset %s: %w", uuid, err)
			}
			keysets = append(keysets, ks)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	if len(keysets) == 0 {
		return nil, fmt.Errorf("no keysets found for account %s in 1password.sqlite", acct.AccountUUID)
	}
	return keysets, nil
}

func parseKeysetRow(keyName string, data []byte) (opcrypto.RawKeyset, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return opcrypto.RawKeyset{}, err
	}
	ks := opcrypto.RawKeyset{UUID: keyName}
	if v, ok := raw["sn"]; ok {
		_ = json.Unmarshal(v, &ks.SN)
	}
	if v, ok := raw["encryptedBy"]; ok {
		_ = json.Unmarshal(v, &ks.EncryptedBy)
	} else if v, ok := raw["encrypted_by"]; ok {
		_ = json.Unmarshal(v, &ks.EncryptedBy)
	}
	if v, ok := raw["encSymKey"]; ok {
		obj, err := opcrypto.UnmarshalEncryptedObject(v)
		if err != nil {
			return opcrypto.RawKeyset{}, fmt.Errorf("encSymKey: %w", err)
		}
		ks.EncSymKey = obj
	} else if v, ok := raw["enc_sym_key"]; ok {
		obj, err := opcrypto.UnmarshalEncryptedObject(v)
		if err != nil {
			return opcrypto.RawKeyset{}, fmt.Errorf("enc_sym_key: %w", err)
		}
		ks.EncSymKey = obj
	}
	if v, ok := raw["encPriKey"]; ok {
		obj, err := opcrypto.UnmarshalEncryptedObject(v)
		if err != nil {
			return opcrypto.RawKeyset{}, fmt.Errorf("encPriKey: %w", err)
		}
		ks.EncPriKey = obj
	} else if v, ok := raw["enc_pri_key"]; ok {
		obj, err := opcrypto.UnmarshalEncryptedObject(v)
		if err != nil {
			return opcrypto.RawKeyset{}, fmt.Errorf("enc_pri_key: %w", err)
		}
		ks.EncPriKey = obj
	}
	return ks, nil
}

type rawVault struct {
	RowID       int64
	UUID        string
	VaultType   string
	EncVaultKey *opcrypto.EncryptedObject
	EncAttrs    *opcrypto.EncryptedObject
}

func loadVaults(db *sql.DB, acct AccountSummary) ([]rawVault, error) {
	// Modern v61+ schema: dedicated vaults table.
	if tableExists(db, "vaults") {
		rows, err := db.Query(`SELECT vault_uuid, data FROM vaults WHERE account_uuid = ?`, acct.AccountUUID)
		if err != nil {
			return nil, fmt.Errorf("query vaults: %w", err)
		}
		defer rows.Close()
		var out []rawVault
		for rows.Next() {
			var vaultUUID string
			var data []byte
			if err := rows.Scan(&vaultUUID, &data); err != nil {
				return nil, fmt.Errorf("scan vault: %w", err)
			}
			rv, err := parseVaultRow(0, vaultUUID, data)
			if err != nil {
				return nil, fmt.Errorf("parse vault %s: %w", vaultUUID, err)
			}
			out = append(out, rv)
		}
		return out, rows.Err()
	}

	// Pre-v61 schema: account_objects (object_type = 'vault').
	if tableExists(db, "account_objects") {
		rows, err := db.Query(`SELECT id, uuid, data FROM account_objects WHERE account_id = ? AND object_type = 'vault'`, acct.RowID)
		if err != nil {
			return nil, fmt.Errorf("query legacy vaults: %w", err)
		}
		defer rows.Close()
		var out []rawVault
		for rows.Next() {
			var rowID int64
			var vaultUUID string
			var data []byte
			if err := rows.Scan(&rowID, &vaultUUID, &data); err != nil {
				return nil, fmt.Errorf("scan legacy vault: %w", err)
			}
			rv, err := parseVaultRow(rowID, vaultUUID, data)
			if err != nil {
				return nil, fmt.Errorf("parse legacy vault %s: %w", vaultUUID, err)
			}
			out = append(out, rv)
		}
		return out, rows.Err()
	}

	return nil, errors.New("neither 'vaults' nor 'account_objects' table found in database")
}

func parseVaultRow(rowID int64, vaultUUID string, data []byte) (rawVault, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return rawVault{}, err
	}
	rv := rawVault{RowID: rowID, UUID: vaultUUID}
	if rv.UUID == "" {
		if v, ok := raw["vault_uuid"]; ok {
			_ = json.Unmarshal(v, &rv.UUID)
		}
	}
	if v, ok := raw["vault_type"]; ok {
		_ = json.Unmarshal(v, &rv.VaultType)
	} else if v, ok := raw["type"]; ok {
		_ = json.Unmarshal(v, &rv.VaultType)
	}
	if v, ok := raw["enc_vault_key"]; ok {
		obj, err := opcrypto.UnmarshalEncryptedObject(v)
		if err != nil {
			return rawVault{}, fmt.Errorf("enc_vault_key: %w", err)
		}
		rv.EncVaultKey = obj
	} else if v, ok := raw["encVaultKey"]; ok {
		obj, err := opcrypto.UnmarshalEncryptedObject(v)
		if err != nil {
			return rawVault{}, fmt.Errorf("encVaultKey: %w", err)
		}
		rv.EncVaultKey = obj
	}
	if v, ok := raw["enc_attrs"]; ok {
		obj, err := opcrypto.UnmarshalEncryptedObject(v)
		if err != nil {
			return rawVault{}, fmt.Errorf("enc_attrs: %w", err)
		}
		rv.EncAttrs = obj
	} else if v, ok := raw["encAttrs"]; ok {
		obj, err := opcrypto.UnmarshalEncryptedObject(v)
		if err != nil {
			return rawVault{}, fmt.Errorf("encAttrs: %w", err)
		}
		rv.EncAttrs = obj
	}
	return rv, nil
}

type rawItem struct {
	UUID         string
	CategoryUUID string
	CreatedAt    int64
	UpdatedAt    int64
	Favorite     bool
	EncOverview  *opcrypto.EncryptedObject
	EncDetails   *opcrypto.EncryptedObject
}

func isActiveState(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return true
	}
	var num int
	if json.Unmarshal(raw, &num) == nil {
		return num == 0
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		s := strings.ToLower(strings.TrimSpace(str))
		return s == "" || s == "0" || s == "active"
	}
	return true
}

func loadItems(db *sql.DB, acct AccountSummary, vault rawVault, includeTrashed bool) ([]rawItem, []string, error) {
	var warnings []string

	// Modern v61+ schema: merged items table. Filter state in Go to handle int/string variations cleanly.
	if tableExists(db, "items") {
		rows, err := db.Query(`SELECT item_uuid, data FROM items WHERE account_uuid = ? AND vault_uuid = ?`, acct.AccountUUID, vault.UUID)
		if err != nil {
			return nil, nil, fmt.Errorf("query items: %w", err)
		}
		defer rows.Close()

		var out []rawItem
		for rows.Next() {
			var itemUUID string
			var data []byte
			if err := rows.Scan(&itemUUID, &data); err != nil {
				warnings = append(warnings, fmt.Sprintf("vault %s: scan item failed: %v", vault.UUID, err))
				continue
			}
			var parsed struct {
				CategoryUUID string          `json:"category_uuid"`
				CreatedAt    int64           `json:"created_at"`
				UpdatedAt    int64           `json:"updated_at"`
				IsFavorite   bool            `json:"is_favorite"`
				State        json.RawMessage `json:"state"`
				Overview     json.RawMessage `json:"overview"`
				Details      json.RawMessage `json:"details"`
			}
			if err := json.Unmarshal(data, &parsed); err != nil {
				warnings = append(warnings, fmt.Sprintf("vault %s item %s: parse JSON failed: %v", vault.UUID, itemUUID, err))
				continue
			}
			if !includeTrashed && !isActiveState(parsed.State) {
				continue
			}
			ov, err := opcrypto.UnmarshalEncryptedObject(parsed.Overview)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("vault %s item %s: parse overview envelope failed: %v", vault.UUID, itemUUID, err))
				continue
			}
			det, err := opcrypto.UnmarshalEncryptedObject(parsed.Details)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("vault %s item %s: parse details envelope failed: %v", vault.UUID, itemUUID, err))
				continue
			}
			out = append(out, rawItem{
				UUID:         itemUUID,
				CategoryUUID: parsed.CategoryUUID,
				CreatedAt:    parsed.CreatedAt,
				UpdatedAt:    parsed.UpdatedAt,
				Favorite:     parsed.IsFavorite,
				EncOverview:  ov,
				EncDetails:   det,
			})
		}
		return out, warnings, rows.Err()
	}

	// Pre-v61 schema: item_overviews + item_details.
	if tableExists(db, "item_overviews") && tableExists(db, "item_details") {
		query := `
			SELECT o.uuid, o.template_uuid, o.created_at, o.updated_at, o.favorite, o.trashed, o.enc_overview, d.enc_details
			FROM item_overviews o
			INNER JOIN item_details d ON d.id = o.id
			WHERE o.vault_id = ?`
		rows, err := db.Query(query, vault.RowID)
		if err != nil {
			return nil, nil, fmt.Errorf("query legacy items: %w", err)
		}
		defer rows.Close()

		var out []rawItem
		for rows.Next() {
			var itemUUID string
			var tmplUUID sql.NullString
			var createdAt, updatedAt, fav, trashed sql.NullInt64
			var encOv, encDet []byte
			if err := rows.Scan(&itemUUID, &tmplUUID, &createdAt, &updatedAt, &fav, &trashed, &encOv, &encDet); err != nil {
				warnings = append(warnings, fmt.Sprintf("vault %s: scan legacy item failed: %v", vault.UUID, err))
				continue
			}
			if !includeTrashed && trashed.Valid && trashed.Int64 != 0 {
				continue
			}
			ov, err := opcrypto.UnmarshalEncryptedObject(encOv)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("vault %s legacy item %s: parse overview failed: %v", vault.UUID, itemUUID, err))
				continue
			}
			det, err := opcrypto.UnmarshalEncryptedObject(encDet)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("vault %s legacy item %s: parse details failed: %v", vault.UUID, itemUUID, err))
				continue
			}
			out = append(out, rawItem{
				UUID:         itemUUID,
				CategoryUUID: tmplUUID.String,
				CreatedAt:    createdAt.Int64,
				UpdatedAt:    updatedAt.Int64,
				Favorite:     fav.Int64 != 0,
				EncOverview:  ov,
				EncDetails:   det,
			})
		}
		return out, warnings, rows.Err()
	}

	return nil, nil, errors.New("neither 'items' nor 'item_overviews'/'item_details' tables found in database")
}

func decryptVaultName(vaultKey *opcrypto.SymmetricKey, encAttrs *opcrypto.EncryptedObject, vaultType, accountType, fallbackUUID string) string {
	var storedName string
	if encAttrs != nil {
		if plain, err := opcrypto.DecryptAESGCM(encAttrs, vaultKey.Key); err == nil {
			var attrs struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(plain, &attrs) == nil {
				storedName = strings.TrimSpace(attrs.Name)
			}
			opcrypto.WipeBytes(plain)
		}
	}
	if storedName != "" {
		return storedName
	}
	if vaultType == "P" {
		if accountType == "I" || accountType == "F" {
			return "Personal"
		}
		return "Private"
	}
	return fallbackUUID
}
