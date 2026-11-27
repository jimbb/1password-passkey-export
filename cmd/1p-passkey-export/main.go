package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/jimbb/1password-passkey-export/internal/exporter"
	"github.com/jimbb/1password-passkey-export/internal/opcloud"
	"github.com/jimbb/1password-passkey-export/internal/opmodel"
	"github.com/jimbb/1password-passkey-export/internal/opsqlite"
)

const version = "0.1.0"

// Shared reader so piped multi-line stdin does not lose buffered lines between prompts.
var stdinReader = bufio.NewReader(os.Stdin)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "list-accounts":
		err = cmdListAccounts(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("1p-passkey-export %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`1p-passkey-export - Export passkeys (and logins) from 1Password without iOS/Android

Usage:
  1p-passkey-export list-accounts [--db <path/to/1password.sqlite>]
  1p-passkey-export inspect       [source flags] [--json]
  1p-passkey-export export        [source flags] --format <bitwarden|cxf|kdbx|all> --out <file-or-prefix>

Sources:
  --source sqlite   (default) Read offline from 1Password 8's local 1password.sqlite (zero network calls)
  --source cloud    Sign in directly to 1Password servers via SRP-6a + 2SKD (+ TOTP 2FA)

Target formats:
  bitwarden         Bitwarden unencrypted JSON (with login.fido2Credentials[])
  cxf               FIDO Credential Exchange Format (CXF 1.0) JSON
  kdbx              KeePassXC encrypted KDBX 4 database (with KPEX_PASSKEY_* attributes)
  all               Write <out>.bitwarden.json, <out>.cxf.json, and <out>.kdbx

Environment variables (recommended over CLI flags to keep secrets out of ps/shell history):
  OP_PASSWORD       1Password master password
  OP_SECRET_KEY     1Password Secret Key (A3-XXXXXX-...)
  OP_TOTP           6-digit TOTP code (for cloud login with 2FA)
  KDBX_PASSWORD     Master password for generated .kdbx file

Examples:
  1p-passkey-export list-accounts --db /path/to/1password.sqlite
  1p-passkey-export inspect --db /path/to/1password.sqlite
  1p-passkey-export export --db /path/to/1password.sqlite --format bitwarden --out bitwarden-passkeys.json
  1p-passkey-export export --db /path/to/1password.sqlite --format all --out my-export
  1p-passkey-export export --source cloud --email you@example.com --format bitwarden --out bitwarden-passkeys.json
`)
}

type sourceFlags struct {
	source         string
	dbPath         string
	account        string
	email          string
	signInAddress  string
	secretKey      string
	password       string
	deviceUUID     string
	vault          string
	includeTrashed bool
	allowAnyHost   bool
}

func bindSourceFlags(fs *flag.FlagSet, sf *sourceFlags) {
	fs.StringVar(&sf.source, "source", "sqlite", "Source: sqlite (offline 1password.sqlite) or cloud (direct 1Password API)")
	fs.StringVar(&sf.dbPath, "db", "", "Path to 1password.sqlite (auto-detected if omitted)")
	fs.StringVar(&sf.account, "account", "", "Account UUID, email, or sign-in URL (sqlite with multiple accounts)")
	fs.StringVar(&sf.email, "email", "", "1Password account email (required for cloud; optional override for sqlite)")
	fs.StringVar(&sf.signInAddress, "sign-in-address", "my.1password.com", "1Password sign-in host for cloud login (e.g. my.1password.com, my.1password.eu)")
	fs.StringVar(&sf.secretKey, "secret-key", "", "1Password Secret Key (prefer OP_SECRET_KEY env or prompt; CLI flags appear in ps/history)")
	fs.StringVar(&sf.password, "password", "", "1Password master password (prefer OP_PASSWORD env or prompt; CLI flags appear in ps/history)")
	fs.StringVar(&sf.deviceUUID, "device-uuid", "", "Reusable 26-char base32 device UUID for cloud login (auto-saved in user config dir if omitted)")
	fs.StringVar(&sf.vault, "vault", "", "Optional: only export a single vault (by name or UUID)")
	fs.BoolVar(&sf.includeTrashed, "include-trashed", false, "Include trashed/archived items")
	fs.BoolVar(&sf.allowAnyHost, "allow-any-host", false, "DANGEROUS: allow non-*.1password.{com,ca,eu} host for cloud login (a hostile host receives SRP material enabling offline password guessing)")
}

func cmdListAccounts(args []string) error {
	fs := flag.NewFlagSet("list-accounts", flag.ExitOnError)
	dbPath := fs.String("db", "", "Path to 1password.sqlite (auto-detected if omitted)")
	asJSON := fs.Bool("json", false, "Output as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := *dbPath
	if path == "" {
		var err error
		path, err = opsqlite.FindDefaultDB()
		if err != nil {
			return err
		}
	}
	accts, err := opsqlite.ListAccounts(path)
	if err != nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(accts, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Printf("Database: %s (schema v%d)\n", path, firstSchemaVersion(accts))
	if len(accts) == 0 {
		fmt.Println("No accounts found.")
		return nil
	}
	for _, a := range accts {
		skNote := "secret key required via prompt/OP_SECRET_KEY"
		if a.HasPlaintextSecretKey {
			skNote = "plaintext secret key readable from DB"
		}
		fmt.Printf("  - %s | uuid=%s | url=%s | type=%s (%s)\n", a.Email, a.AccountUUID, a.SignInURL, a.AccountType, skNote)
	}
	return nil
}

func firstSchemaVersion(accts []opsqlite.AccountSummary) int {
	if len(accts) == 0 {
		return 0
	}
	return accts[0].SchemaVersion
}

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	var sf sourceFlags
	bindSourceFlags(fs, &sf)
	asJSON := fs.Bool("json", false, "Output redacted diagnostic JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	acct, err := loadAccount(&sf)
	if err != nil {
		return err
	}

	var diags []opmodel.PasskeyDiagnostic
	for _, v := range acct.Vaults {
		for _, it := range v.Items {
			diags = append(diags, it.PasskeyInspect...)
		}
	}

	if *asJSON {
		payload := map[string]any{
			"source":         acct.Source,
			"vaults":         len(acct.Vaults),
			"items":          acct.TotalItems(),
			"passkeys":       acct.TotalPasskeys(),
			"passkeyDetails": diags,
			"warnings":       acct.Warnings,
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("Source: %s | Vaults: %d | Items: %d | Exportable passkeys: %d\n",
		acct.Source, len(acct.Vaults), acct.TotalItems(), acct.TotalPasskeys())
	for _, d := range diags {
		status := fmt.Sprintf("OK [%s %s %s, credId=%dB, userHandle=%dB, key=%dB, prf=%v]",
			d.DetectedFormat, d.KeyAlgorithm, d.KeyCurve, d.CredIDBytes, d.UserHandleBytes, d.PrivateKeyBytes, d.HasPRF)
		if d.Error != "" {
			status = "ERROR: " + d.Error
		}
		fmt.Printf("  - [%s] %s | rpId=%s | type=%s | alg=%s | loc=%s | %s\n",
			d.VaultName, d.ItemTitle, d.RPID, d.Type, d.Alg, d.Location, status)
		if len(d.OverviewKeys) > 0 || len(d.DetailsKeys) > 0 {
			fmt.Printf("      overview.passkey keys=%v | details.passkey keys=%v\n", d.OverviewKeys, d.DetailsKeys)
		}
	}
	printWarnings(acct.Warnings)
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	var sf sourceFlags
	bindSourceFlags(fs, &sf)
	format := fs.String("format", "bitwarden", "Export format: bitwarden, cxf, kdbx, or all")
	outPath := fs.String("out", "", "Output file path (or filename prefix when --format all)")
	passkeysOnly := fs.Bool("passkeys-only", true, "Export only items that contain passkeys (set --passkeys-only=false for full vault)")
	allItems := fs.Bool("all-items", false, "Shorthand for --passkeys-only=false (export all vault items + passkeys)")
	force := fs.Bool("force", false, "Overwrite existing output file(s) safely by removing and recreating with mode 0600")
	kdbxPassword := fs.String("kdbx-password", "", "Master password for generated .kdbx file (prefer KDBX_PASSWORD env or prompt)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *kdbxPassword != "" {
		fmt.Fprintln(os.Stderr, "WARNING: passing --kdbx-password on the command line may expose it in process listings and shell history; prefer KDBX_PASSWORD env or interactive prompt.")
	}

	fmtLower := strings.ToLower(strings.TrimSpace(*format))
	switch fmtLower {
	case "bitwarden", "cxf", "kdbx", "all":
	default:
		return fmt.Errorf("unsupported --format %q (expected bitwarden, cxf, kdbx, or all)", *format)
	}

	if strings.TrimSpace(*outPath) == "" {
		return errors.New("--out <path> is required")
	}

	needsKDBX := fmtLower == "kdbx" || fmtLower == "all"
	kdbxPw := *kdbxPassword
	if kdbxPw == "" {
		kdbxPw = os.Getenv("KDBX_PASSWORD")
	}
	if needsKDBX && kdbxPw == "" {
		var err error
		kdbxPw, err = promptSecret("New KeePassXC (.kdbx) database password: ")
		if err != nil {
			return fmt.Errorf("read KDBX password: %w", err)
		}
		if kdbxPw == "" {
			return errors.New("KDBX password cannot be empty")
		}
	}

	acct, err := loadAccount(&sf)
	if err != nil {
		return err
	}

	expOpts := exporter.Options{
		PasskeysOnly: *passkeysOnly && !*allItems,
	}

	// Build ALL requested output payloads in memory before writing anything to disk,
	// so a failure in one format never leaves partial plaintext exports behind.
	type pendingOutput struct {
		path string
		data []byte
	}
	var outputs []pendingOutput

	switch fmtLower {
	case "bitwarden":
		b, err := exporter.ExportBitwardenJSON(acct, expOpts)
		if err != nil {
			return err
		}
		outputs = append(outputs, pendingOutput{path: *outPath, data: b})
	case "cxf":
		b, err := exporter.ExportCXFJSON(acct, expOpts)
		if err != nil {
			return err
		}
		outputs = append(outputs, pendingOutput{path: *outPath, data: b})
	case "kdbx":
		b, err := exporter.ExportKDBX(acct, kdbxPw, expOpts)
		if err != nil {
			return err
		}
		outputs = append(outputs, pendingOutput{path: *outPath, data: b})
	case "all":
		prefix := strings.TrimSuffix(*outPath, ".json")
		prefix = strings.TrimSuffix(prefix, ".kdbx")
		prefix = strings.TrimSuffix(prefix, ".cxf")

		bw, err := exporter.ExportBitwardenJSON(acct, expOpts)
		if err != nil {
			return err
		}
		cxf, err := exporter.ExportCXFJSON(acct, expOpts)
		if err != nil {
			return err
		}
		kdbx, err := exporter.ExportKDBX(acct, kdbxPw, expOpts)
		if err != nil {
			return err
		}
		outputs = append(outputs,
			pendingOutput{path: prefix + ".bitwarden.json", data: bw},
			pendingOutput{path: prefix + ".cxf.json", data: cxf},
			pendingOutput{path: prefix + ".kdbx", data: kdbx},
		)
	}

	// Check destination paths first before creating any files.
	for _, out := range outputs {
		if err := checkOutputPath(out.path, *force); err != nil {
			return err
		}
	}

	written := make([]string, 0, len(outputs))
	for _, out := range outputs {
		if err := writeSecretFileExclusive(out.path, out.data, *force); err != nil {
			return err
		}
		written = append(written, out.path)
	}

	fmt.Printf("Decrypted %d vaults, %d items, %d passkeys (source=%s).\n",
		len(acct.Vaults), acct.TotalItems(), acct.TotalPasskeys(), acct.Source)
	for _, p := range written {
		fmt.Printf("Wrote: %s (mode 0600)\n", p)
	}
	if fmtLower == "bitwarden" || fmtLower == "cxf" || fmtLower == "all" {
		fmt.Fprintln(os.Stderr, "NOTE: Plaintext JSON exports contain passkey private keys. Delete them immediately after importing.")
	}
	printWarnings(acct.Warnings)
	return nil
}

func checkOutputPath(path string, force bool) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %q: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write secrets to symlink %q", path)
	}
	if fi.IsDir() {
		return fmt.Errorf("output path %q is a directory", path)
	}
	if !force {
		return fmt.Errorf("output file %q already exists (refusing to overwrite; pass --force to replace)", path)
	}
	return nil
}

func writeSecretFileExclusive(path string, data []byte, force bool) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	if force {
		if fi, err := os.Lstat(path); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing to remove symlink %q", path)
			}
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove existing %q: %w", path, err)
			}
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create %q: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %q: %w", path, err)
	}
	return nil
}

func loadAccount(sf *sourceFlags) (*opmodel.AccountExport, error) {
	if sf.password != "" {
		fmt.Fprintln(os.Stderr, "WARNING: passing --password on the command line may expose it in process listings and shell history; prefer OP_PASSWORD env or interactive prompt.")
	}
	if sf.secretKey != "" {
		fmt.Fprintln(os.Stderr, "WARNING: passing --secret-key on the command line may expose it in process listings and shell history; prefer OP_SECRET_KEY env or interactive prompt.")
	}

	password := sf.password
	if password == "" {
		password = os.Getenv("OP_PASSWORD")
	}
	secretKey := sf.secretKey
	if secretKey == "" {
		secretKey = os.Getenv("OP_SECRET_KEY")
	}

	switch strings.ToLower(strings.TrimSpace(sf.source)) {
	case "sqlite", "":
		dbPath := sf.dbPath
		if dbPath == "" {
			var err error
			dbPath, err = opsqlite.FindDefaultDB()
			if err != nil {
				return nil, err
			}
		}
		// Check whether the DB already has a plaintext Secret Key before prompting.
		if secretKey == "" {
			if accts, err := opsqlite.ListAccounts(dbPath); err == nil {
				if len(accts) == 1 && accts[0].PlaintextSecretKey != "" {
					secretKey = accts[0].PlaintextSecretKey
				}
			}
		}
		if secretKey == "" {
			var err error
			secretKey, err = promptSecret("1Password Secret Key (A3-...): ")
			if err != nil {
				return nil, fmt.Errorf("read secret key: %w", err)
			}
		}
		if password == "" {
			var err error
			password, err = promptSecret("1Password Master Password: ")
			if err != nil {
				return nil, fmt.Errorf("read password: %w", err)
			}
		}
		return opsqlite.Export(opsqlite.Options{
			DBPath:         dbPath,
			AccountFilter:  sf.account,
			EmailOverride:  sf.email,
			Password:       password,
			SecretKey:      secretKey,
			IncludeTrashed: sf.includeTrashed,
			VaultFilter:    sf.vault,
		})

	case "cloud":
		email := strings.TrimSpace(sf.email)
		if email == "" {
			var err error
			email, err = promptLine("1Password Email: ")
			if err != nil {
				return nil, fmt.Errorf("read email: %w", err)
			}
		}
		if secretKey == "" {
			var err error
			secretKey, err = promptSecret("1Password Secret Key (A3-...): ")
			if err != nil {
				return nil, fmt.Errorf("read secret key: %w", err)
			}
		}
		if password == "" {
			var err error
			password, err = promptSecret("1Password Master Password: ")
			if err != nil {
				return nil, fmt.Errorf("read password: %w", err)
			}
		}
		deviceUUID := sf.deviceUUID
		if deviceUUID == "" {
			deviceUUID = loadOrCreateDeviceUUID()
		}
		return opcloud.Export(context.Background(), opcloud.Options{
			SignInAddress:  sf.signInAddress,
			Email:          email,
			Password:       password,
			SecretKey:      secretKey,
			DeviceUUID:     deviceUUID,
			VaultFilter:    sf.vault,
			IncludeTrashed: sf.includeTrashed,
			AllowAnyHost:   sf.allowAnyHost,
			PromptTOTP: func() (string, error) {
				if envCode := strings.TrimSpace(os.Getenv("OP_TOTP")); envCode != "" {
					return envCode, nil
				}
				return promptLine("1Password 2FA (TOTP) 6-digit code: ")
			},
		})

	default:
		return nil, fmt.Errorf("unsupported --source %q (expected sqlite or cloud)", sf.source)
	}
}

func loadOrCreateDeviceUUID() string {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return opcloud.NewDeviceUUID()
	}
	dir := filepath.Join(cfgDir, "1p-passkey-export")
	path := filepath.Join(dir, "device-uuid")
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); len(id) == 26 {
			return id
		}
	}
	id := opcloud.NewDeviceUUID()
	if os.MkdirAll(dir, 0700) == nil {
		_ = os.WriteFile(path, []byte(id+"\n"), 0600)
	}
	return id
}

func promptSecret(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return readStdinLine()
}

func promptLine(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	return readStdinLine()
}

func readStdinLine() (string, error) {
	line, err := stdinReader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func printWarnings(warnings []string) {
	if len(warnings) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\nWarnings (%d):\n", len(warnings))
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "  - %s\n", w)
	}
}
