package opcloud

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
	"github.com/jimbb/1password-passkey-export/internal/opmodel"
)

const (
	headerMAC         = "X-AgileBits-MAC"
	headerSessionID   = "X-AgileBits-Session-ID"
	headerClient      = "X-AgileBits-Client"
	headerOPUserAgent = "OP-User-Agent"

	defaultClientName    = "1Password for Mac"
	defaultClientVersion = "81210036"
	defaultDeviceName    = "1p-passkey-export"
	defaultOSName        = "macOS"
	defaultPlatform      = "MacOSX|26.3.1|aarch64"
	defaultPlatformCode  = "M"

	defaultMinKDFIterations = 100000
	maxResponseBytes        = 64 * 1024 * 1024
	maxItemPages            = 1000
)

// Options configures a direct cloud login and vault export against 1Password's servers.
type Options struct {
	SignInAddress    string // e.g. "my.1password.com", "my.1password.eu", "team.1password.com"
	Email            string
	Password         string
	SecretKey        string
	DeviceUUID       string                 // optional 26-char base32 device ID; generated if empty
	PromptTOTP       func() (string, error) // called if authenticator-app 2FA is enabled
	VaultFilter      string                 // optional: filter by vault name or UUID
	IncludeTrashed   bool
	BaseURL          string // override for tests (requires https, or loopback http, unless AllowAnyHost)
	AllowAnyHost     bool
	MinKDFIterations int
	Timeout          time.Duration
}

// NewDeviceUUID generates a 26-character lowercase base32 device UUID matching 1Password's format.
func NewDeviceUUID() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var raw [26]byte
	_, _ = io.ReadFull(rand.Reader, raw[:])
	out := make([]byte, 26)
	for i, b := range raw {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out)
}

func checkOnePasswordHost(u *url.URL) error {
	host := strings.ToLower(u.Hostname())
	allowed := []string{".1password.com", ".1password.ca", ".1password.eu"}
	for _, suf := range allowed {
		if strings.HasSuffix(host, suf) && len(host) > len(suf) {
			return nil
		}
	}
	return fmt.Errorf("refusing non-1Password host %q (expected *.1password.com, *.1password.ca, or *.1password.eu; pass --allow-any-host to override)", host)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Export signs into a 1Password account via SRP-6a + 2SKD, downloads and decrypts every accessible vault,
// extracts passkeys & items, and signs out cleanly.
func Export(ctx context.Context, opts Options) (*opmodel.AccountExport, error) {
	if strings.TrimSpace(opts.Email) == "" {
		return nil, errors.New("email is required for cloud login")
	}
	if opts.Password == "" {
		return nil, errors.New("master password is required for cloud login")
	}
	sk, err := opcrypto.ParseSecretKey(opts.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("parse secret key: %w", err)
	}

	var baseURL *url.URL
	if opts.BaseURL != "" {
		baseURL, err = url.Parse(opts.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid base URL: %w", err)
		}
		if !opts.AllowAnyHost {
			scheme := strings.ToLower(baseURL.Scheme)
			if scheme == "http" {
				if !isLoopbackHost(baseURL.Hostname()) {
					return nil, fmt.Errorf("refusing plaintext HTTP base URL %q (only loopback HTTP or HTTPS allowed unless AllowAnyHost is set)", baseURL.Host)
				}
			} else if scheme != "https" {
				return nil, fmt.Errorf("unsupported base URL scheme %q (expected https)", baseURL.Scheme)
			} else if !isLoopbackHost(baseURL.Hostname()) {
				if err := checkOnePasswordHost(baseURL); err != nil {
					return nil, err
				}
			}
		}
	} else {
		addr := strings.TrimSpace(opts.SignInAddress)
		if addr == "" {
			addr = "my.1password.com"
		}
		addr = strings.TrimPrefix(addr, "https://")
		addr = strings.TrimPrefix(addr, "http://")
		addr = strings.TrimRight(addr, "/")
		baseURL, err = url.Parse("https://" + addr + "/api/")
		if err != nil {
			return nil, fmt.Errorf("invalid sign-in address: %w", err)
		}
		if !opts.AllowAnyHost {
			if err := checkOnePasswordHost(baseURL); err != nil {
				return nil, err
			}
		}
	}
	if !strings.HasSuffix(baseURL.Path, "/") {
		baseURL.Path += "/"
	}

	deviceUUID := strings.TrimSpace(opts.DeviceUUID)
	if deviceUUID == "" {
		deviceUUID = NewDeviceUUID()
	}

	minIters := opts.MinKDFIterations
	if minIters <= 0 {
		minIters = defaultMinKDFIterations
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}

	httpClient := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("unexpected HTTP redirect from 1Password API")
		},
	}

	c := &restClient{
		http:       httpClient,
		base:       baseURL,
		deviceUUID: deviceUUID,
		clientID:   defaultClientName + "/" + defaultClientVersion,
		opUA:       fmt.Sprintf("1|%s|%s|%s|||go-http|1.0|%s", defaultPlatformCode, defaultClientVersion, deviceUUID, defaultPlatform),
	}

	// 1. Start session (registering or reauthorizing device if needed).
	start, err := c.startSession(ctx, opts.Email, sk)
	if err != nil {
		return nil, err
	}
	if start.AccountKeyFormat != sk.Format || start.AccountKeyUUID != sk.AccountID {
		return nil, errors.New("Secret Key does not belong to this account")
	}
	if start.UserAuth.Iterations < minIters {
		return nil, fmt.Errorf("refusing weak KDF iteration count %d (minimum %d)", start.UserAuth.Iterations, minIters)
	}
	if start.UserAuth.Iterations > opcrypto.MaxKDFIterations {
		return nil, fmt.Errorf("refusing excessive KDF iteration count %d (max %d)", start.UserAuth.Iterations, opcrypto.MaxKDFIterations)
	}
	if start.UserAuth.Method != opcrypto.SRPMethod4096 {
		return nil, fmt.Errorf("unsupported SRP method %q (expected %s)", start.UserAuth.Method, opcrypto.SRPMethod4096)
	}
	c.sessionID = start.SessionID

	// 2. SRP-6a key exchange.
	salt, err := opcrypto.Base64URLDecode(start.UserAuth.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode auth salt: %w", err)
	}
	srpX, err := opcrypto.Compute2SKD(sk, opts.Password, opts.Email, start.UserAuth.Method, salt, start.UserAuth.Iterations)
	if err != nil {
		return nil, fmt.Errorf("derive SRP-x: %w", err)
	}
	srpClient, err := NewSRPClient(srpX)
	opcrypto.WipeBytes(srpX)
	if err != nil {
		return nil, err
	}
	defer srpClient.Wipe()

	var authResp struct {
		UserB string `json:"userB"`
	}
	if err := c.doPlain(ctx, http.MethodPost, "v2/auth", map[string]any{"userA": srpClient.PublicAHex()}, &authResp); err != nil {
		return nil, fmt.Errorf("v2/auth: %w", err)
	}
	bigB, err := parseServerHex(authResp.UserB)
	if err != nil {
		return nil, fmt.Errorf("parse userB: %w", err)
	}
	sessionKey, err := srpClient.SessionKey(bigB)
	srpClient.Wipe()
	if err != nil {
		return nil, fmt.Errorf("SRP session key: %w", err)
	}
	defer opcrypto.WipeBytes(sessionKey)

	// 3. Mutual SRP proof.
	identity := SRPIdentity(opts.Email, sk.AccountID)
	m1 := srpClient.ClientProof(bigB, sessionKey, identity, salt)
	var confirmResp struct {
		ServerVerifyHash string `json:"serverVerifyHash"`
	}
	if err := c.doPlain(ctx, http.MethodPost, "v2/auth/confirm-key", map[string]any{
		"clientVerifyHash": opcrypto.Base64URLEncode(m1),
	}, &confirmResp); err != nil {
		return nil, fmt.Errorf("SRP confirm-key (wrong password or Secret Key?): %w", err)
	}
	serverHash, err := opcrypto.Base64URLDecode(confirmResp.ServerVerifyHash)
	if err != nil {
		return nil, fmt.Errorf("decode serverVerifyHash: %w", err)
	}
	if err := srpClient.VerifyServerConfirmation(m1, sessionKey, serverHash); err != nil {
		return nil, err
	}

	// 4. Enable encrypted + MAC'd session transport.
	c.sessionKey = sessionKey
	c.requestID.Store(randomStartRequestID())
	defer func() {
		signOutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = c.signOut(signOutCtx)
	}()

	var completeResp struct {
		UserUUID string         `json:"userUuid"`
		MFA      map[string]any `json:"mfa"`
	}
	if err := c.doEncrypted(ctx, http.MethodPost, "v2/auth/complete", map[string]any{
		"client": c.clientID,
		"device": c.deviceBody(),
	}, &completeResp); err != nil {
		return nil, fmt.Errorf("v2/auth/complete: %w", err)
	}

	// 5. Second factor (TOTP) if required.
	if err := c.handleMFA(ctx, completeResp.MFA, opts.PromptTOTP); err != nil {
		return nil, err
	}

	// 6. Download and unlock keysets.
	var ksResp struct {
		Keysets []struct {
			UUID        string          `json:"uuid"`
			SN          int             `json:"sn"`
			EncryptedBy string          `json:"encryptedBy"`
			EncSymKey   json.RawMessage `json:"encSymKey"`
			EncPriKey   json.RawMessage `json:"encPriKey"`
		} `json:"keysets"`
	}
	if err := c.doEncrypted(ctx, http.MethodGet, "v1/account/keysets", nil, &ksResp); err != nil {
		return nil, fmt.Errorf("v1/account/keysets: %w", err)
	}
	rawKeysets := make([]opcrypto.RawKeyset, 0, len(ksResp.Keysets))
	for _, k := range ksResp.Keysets {
		sym, err := opcrypto.UnmarshalEncryptedObject(k.EncSymKey)
		if err != nil {
			return nil, fmt.Errorf("keyset %s encSymKey: %w", k.UUID, err)
		}
		pri, err := opcrypto.UnmarshalEncryptedObject(k.EncPriKey)
		if err != nil {
			return nil, fmt.Errorf("keyset %s encPriKey: %w", k.UUID, err)
		}
		rawKeysets = append(rawKeysets, opcrypto.RawKeyset{
			UUID:        k.UUID,
			SN:          k.SN,
			EncryptedBy: k.EncryptedBy,
			EncSymKey:   sym,
			EncPriKey:   pri,
		})
	}
	keyring, ksWarnings, err := opcrypto.UnlockKeysets(rawKeysets, sk, opts.Password, opts.Email)
	if err != nil {
		return nil, fmt.Errorf("unlock keysets: %w", err)
	}
	defer keyring.Wipe()

	// 7. Fetch account & vaults.
	var acctResp struct {
		Account struct {
			UUID string `json:"uuid"`
			Type string `json:"type"`
		} `json:"account"`
		Me struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"me"`
		Vaults []struct {
			UUID     string          `json:"uuid"`
			Type     string          `json:"type"`
			EncAttrs json.RawMessage `json:"encAttrs"`
			Access   []struct {
				ACL         *uint64         `json:"acl"`
				EncVaultKey json.RawMessage `json:"encVaultKey"`
			} `json:"access"`
		} `json:"vaults"`
	}
	if err := c.doEncrypted(ctx, http.MethodGet, "v1/account?attrs=me,vaults", nil, &acctResp); err != nil {
		return nil, fmt.Errorf("v1/account: %w", err)
	}

	export := &opmodel.AccountExport{
		AccountUUID: acctResp.Account.UUID,
		Email:       opts.Email,
		UserName:    acctResp.Me.Name,
		SignInURL:   baseURL.Host,
		Source:      "cloud",
		Warnings:    ksWarnings,
	}
	if acctResp.Me.Email != "" {
		export.Email = acctResp.Me.Email
	}

	vaultFilter := strings.TrimSpace(opts.VaultFilter)

	// 8. Decrypt each readable vault and paginate all items.
	for _, rv := range acctResp.Vaults {
		var vaultKey *opcrypto.SymmetricKey
		for _, acc := range rv.Access {
			if acc.ACL != nil && (*acc.ACL&32) == 0 {
				continue // no read permission
			}
			evk, err := opcrypto.UnmarshalEncryptedObject(acc.EncVaultKey)
			if err != nil || evk == nil {
				continue
			}
			if k, err := keyring.UnwrapVaultKey(evk); err == nil {
				vaultKey = k
				break
			}
		}
		if vaultKey == nil {
			export.Warnings = append(export.Warnings, fmt.Sprintf("vault %s: skipped (no readable key)", rv.UUID))
			continue
		}

		vaultName := rv.UUID
		if encAttrs, err := opcrypto.UnmarshalEncryptedObject(rv.EncAttrs); err == nil && encAttrs != nil {
			if plain, err := opcrypto.DecryptAESGCM(encAttrs, vaultKey.Key); err == nil {
				var attrs struct {
					Name string `json:"name"`
				}
				if json.Unmarshal(plain, &attrs) == nil && strings.TrimSpace(attrs.Name) != "" {
					vaultName = strings.TrimSpace(attrs.Name)
				}
				opcrypto.WipeBytes(plain)
			}
		}
		if vaultName == rv.UUID && rv.Type == "P" {
			vaultName = "Private"
		}

		if vaultFilter != "" && !strings.EqualFold(vaultName, vaultFilter) && rv.UUID != vaultFilter {
			vaultKey.Wipe()
			continue
		}

		vault := opmodel.Vault{
			UUID:      rv.UUID,
			Name:      vaultName,
			VaultType: rv.Type,
		}

		var batch uint64
		completed := false
		for page := 0; page < maxItemPages; page++ {
			var batchResp struct {
				ContentVersion uint64 `json:"contentVersion"`
				BatchComplete  *bool  `json:"batchComplete"`
				Items          []struct {
					UUID         string          `json:"uuid"`
					TemplateUUID string          `json:"templateUuid"`
					Trashed      string          `json:"trashed"`
					FaveIndex    int             `json:"faveIndex"`
					CreatedAt    string          `json:"createdAt"`
					UpdatedAt    string          `json:"updatedAt"`
					EncOverview  json.RawMessage `json:"encOverview"`
					EncDetails   json.RawMessage `json:"encDetails"`
				} `json:"items"`
			}
			endpoint := fmt.Sprintf("v1/vault/%s/%d/items", url.PathEscape(rv.UUID), batch)
			if err := c.doEncrypted(ctx, http.MethodGet, endpoint, nil, &batchResp); err != nil {
				vaultKey.Wipe()
				return nil, fmt.Errorf("fetch items for vault %q: %w", vaultName, err)
			}

			for _, it := range batchResp.Items {
				if it.Trashed == "Y" && !opts.IncludeTrashed {
					continue
				}
				encOv, err := opcrypto.UnmarshalEncryptedObject(it.EncOverview)
				if err != nil {
					export.Warnings = append(export.Warnings, fmt.Sprintf("vault %q item %s: parse encOverview: %v", vaultName, it.UUID, err))
					continue
				}
				encDet, err := opcrypto.UnmarshalEncryptedObject(it.EncDetails)
				if err != nil {
					export.Warnings = append(export.Warnings, fmt.Sprintf("vault %q item %s: parse encDetails: %v", vaultName, it.UUID, err))
					continue
				}

				var ovPlain, detPlain []byte
				if encOv != nil {
					ovPlain, err = opcrypto.DecryptAESGCM(encOv, vaultKey.Key)
					if err != nil {
						export.Warnings = append(export.Warnings, fmt.Sprintf("vault %q item %s: decrypt overview: %v", vaultName, it.UUID, err))
						continue
					}
				}
				if encDet != nil {
					detPlain, err = opcrypto.DecryptAESGCM(encDet, vaultKey.Key)
					if err != nil {
						opcrypto.WipeBytes(ovPlain)
						export.Warnings = append(export.Warnings, fmt.Sprintf("vault %q item %s: decrypt details: %v", vaultName, it.UUID, err))
						continue
					}
				}

				createdUnix := parseRFC3339Unix(it.CreatedAt)
				updatedUnix := parseRFC3339Unix(it.UpdatedAt)
				item, itemWarns, err := opmodel.ExtractItem(
					rv.UUID, vaultName, it.UUID, it.TemplateUUID,
					createdUnix, updatedUnix, it.FaveIndex > 0,
					ovPlain, detPlain,
				)
				opcrypto.WipeBytes(ovPlain)
				opcrypto.WipeBytes(detPlain)
				if err != nil {
					export.Warnings = append(export.Warnings, fmt.Sprintf("vault %q item %s: parse item: %v", vaultName, it.UUID, err))
					continue
				}
				export.Warnings = append(export.Warnings, itemWarns...)
				vault.Items = append(vault.Items, *item)
			}

			if batchResp.BatchComplete == nil || *batchResp.BatchComplete || batchResp.ContentVersion <= batch {
				completed = true
				break
			}
			batch = batchResp.ContentVersion
		}
		if !completed {
			export.Warnings = append(export.Warnings, fmt.Sprintf("vault %q (%s): hit max pagination limit (%d pages); some items may be omitted", vaultName, rv.UUID, maxItemPages))
		}

		vaultKey.Wipe()
		export.Vaults = append(export.Vaults, vault)
	}

	return export, nil
}

type restClient struct {
	http       *http.Client
	base       *url.URL
	deviceUUID string
	clientID   string
	opUA       string
	sessionID  string
	sessionKey []byte
	requestID  atomic.Uint32
}

type startResponse struct {
	Status           string `json:"status"`
	SessionID        string `json:"sessionID"`
	AccountKeyFormat string `json:"accountKeyFormat"`
	AccountKeyUUID   string `json:"accountKeyUuid"`
	UserAuth         struct {
		Method     string `json:"method"`
		Salt       string `json:"salt"`
		Iterations int    `json:"iterations"`
	} `json:"userAuth"`
}

func (c *restClient) deviceBody() map[string]any {
	return map[string]any{
		"uuid":          c.deviceUUID,
		"clientName":    defaultClientName,
		"clientVersion": defaultClientVersion,
		"name":          defaultDeviceName,
		"osName":        defaultOSName,
		"userAgent":     c.clientID,
	}
}

func (c *restClient) startSession(ctx context.Context, email string, sk *opcrypto.SecretKey) (*startResponse, error) {
	for range 3 {
		var resp startResponse
		err := c.doPlain(ctx, http.MethodPost, "v3/auth/start", map[string]any{
			"email":      strings.TrimSpace(email),
			"skFormat":   sk.Format,
			"skid":       sk.AccountID,
			"deviceUuid": c.deviceUUID,
			"userUuid":   "",
		}, &resp)
		if err != nil {
			return nil, fmt.Errorf("v3/auth/start: %w", err)
		}
		switch resp.Status {
		case "ok":
			return &resp, nil
		case "device-not-registered":
			c.sessionID = resp.SessionID
			var ignored any
			if err := c.doPlain(ctx, http.MethodPost, "v1/device", c.deviceBody(), &ignored); err != nil {
				return nil, fmt.Errorf("v1/device registration: %w", err)
			}
		case "device-deleted":
			c.sessionID = resp.SessionID
			var ignored any
			if err := c.doPlain(ctx, http.MethodPut, fmt.Sprintf("v1/device/%s/reauthorize", url.PathEscape(c.deviceUUID)), nil, &ignored); err != nil {
				return nil, fmt.Errorf("v1/device reauthorize: %w", err)
			}
		default:
			return nil, fmt.Errorf("unexpected auth/start status %q", resp.Status)
		}
	}
	return nil, errors.New("device registration did not complete after retries")
}

func (c *restClient) handleMFA(ctx context.Context, mfa map[string]any, prompt func() (string, error)) error {
	if len(mfa) == 0 {
		return nil
	}
	enabled := func(key string) bool {
		sub, ok := mfa[key].(map[string]any)
		if !ok {
			return false
		}
		b, _ := sub["enabled"].(bool)
		return b
	}
	if enabled("totp") {
		if prompt == nil {
			return errors.New("account requires authenticator-app (TOTP) 2FA code")
		}
		code, err := prompt()
		if err != nil {
			return fmt.Errorf("read 2FA code: %w", err)
		}
		return c.doEncryptedDiscard(ctx, http.MethodPost, "v1/auth/mfa", map[string]any{
			"sessionID": c.sessionID,
			"client":    c.clientID,
			"totp":      map[string]any{"code": strings.TrimSpace(code)},
		})
	}
	for k := range mfa {
		if enabled(k) {
			return fmt.Errorf("unsupported 2FA method %q (only authenticator-app TOTP is supported for cloud login; use offline 1password.sqlite instead)", k)
		}
	}
	return nil
}

func (c *restClient) signOut(ctx context.Context) error {
	var ignored any
	return c.doRaw(ctx, http.MethodPut, "v1/session/signout", nil, false, true, &ignored)
}

func (c *restClient) doPlain(ctx context.Context, method, relPath string, body any, out any) error {
	return c.doRaw(ctx, method, relPath, body, false, false, out)
}

func (c *restClient) doEncrypted(ctx context.Context, method, relPath string, body any, out any) error {
	return c.doRaw(ctx, method, relPath, body, true, false, out)
}

func (c *restClient) doEncryptedDiscard(ctx context.Context, method, relPath string, body any) error {
	var ignored any
	return c.doRaw(ctx, method, relPath, body, true, true, &ignored)
}

func (c *restClient) doRaw(ctx context.Context, method, relPath string, body any, encrypted, discardReply bool, out any) error {
	rel, err := url.Parse(relPath)
	if err != nil {
		return err
	}
	target := c.base.ResolveReference(rel)

	var bodyReader io.Reader
	if body != nil {
		payload := body
		if encrypted {
			plainBytes, err := json.Marshal(body)
			if err != nil {
				return err
			}
			env, err := opcrypto.EncryptAESGCM(c.sessionID, c.sessionKey, "b5+jwk+json", plainBytes)
			opcrypto.WipeBytes(plainBytes)
			if err != nil {
				return err
			}
			payload = env
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, target.String(), bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(headerClient, c.clientID)
	req.Header.Set("User-Agent", c.clientID)
	req.Header.Set(headerOPUserAgent, c.opUA)
	if c.sessionID != "" {
		req.Header.Set(headerSessionID, c.sessionID)
	}
	if len(c.sessionKey) == 32 && c.sessionID != "" {
		reqID := c.requestID.Add(1) - 1
		req.Header.Set(headerMAC, RequestMAC(c.sessionKey, c.sessionID, reqID, method, target))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(respBytes) > maxResponseBytes {
		return fmt.Errorf("%s: response exceeded %d bytes", relPath, maxResponseBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(respBytes)
		if len(snippet) > 300 {
			snippet = snippet[:300] + "..."
		}
		return fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, relPath, snippet)
	}

	if discardReply && len(bytes.TrimSpace(respBytes)) == 0 {
		return nil
	}

	// Check for 1Password JSON errorCode even on HTTP 200.
	var errProbe struct {
		ErrorCode    *int   `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
	}
	if json.Unmarshal(respBytes, &errProbe) == nil && errProbe.ErrorCode != nil {
		return fmt.Errorf("1Password error %d on %s: %s", *errProbe.ErrorCode, relPath, errProbe.ErrorMessage)
	}

	decoded := respBytes
	if encrypted {
		var env opcrypto.EncryptedObject
		if err := json.Unmarshal(respBytes, &env); err != nil || env.Enc == "" || env.Data == "" {
			if discardReply {
				return nil
			}
			return fmt.Errorf("%s: expected encrypted response from server", relPath)
		}
		plain, err := opcrypto.DecryptAESGCM(&env, c.sessionKey)
		if err != nil {
			return fmt.Errorf("%s: decrypt response: %w", relPath, err)
		}
		defer opcrypto.WipeBytes(plain)
		decoded = plain
	}

	if out == nil || discardReply {
		return nil
	}
	if err := json.Unmarshal(decoded, out); err != nil {
		return fmt.Errorf("%s: parse JSON response: %w", relPath, err)
	}
	return nil
}

func randomStartRequestID() uint32 {
	var b [4]byte
	_, _ = io.ReadFull(rand.Reader, b[:])
	v := binary.BigEndian.Uint32(b[:]) & 0x3fffffff
	if v == 0 {
		v = 1
	}
	return v
}

func parseRFC3339Unix(s string) int64 {
	if s == "" {
		return 0
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Unix()
		}
	}
	return 0
}
