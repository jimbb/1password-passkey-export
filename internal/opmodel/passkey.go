package opmodel

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
)

// rawOverview matches 1Password's decrypted encOverview JSON.
type rawOverview struct {
	Title   string         `json:"title"`
	URL     string         `json:"url"`
	URLs    []rawURLEntry  `json:"URLs"`
	URLsLow []rawURLEntry  `json:"urls"`
	Tags    []string       `json:"tags"`
	Ainfo   string         `json:"ainfo"`
	Passkey map[string]any `json:"passkey"`
}

type rawURLEntry struct {
	URL   string `json:"u"`
	Label string `json:"l"`
}

type rawDetails struct {
	NotesPlain string             `json:"notesPlain"`
	Password   string             `json:"password"`
	Fields     []rawTopLevelField `json:"fields"`
	Sections   []rawSection       `json:"sections"`
	Passkey    map[string]any     `json:"passkey"`
	Passkeys   []map[string]any   `json:"passkeys"`
}

type rawTopLevelField struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Designation string `json:"designation"`
}

type rawSection struct {
	Name   string            `json:"name"`
	Title  string            `json:"title"`
	Fields []rawSectionField `json:"fields"`
}

type rawSectionField struct {
	N string          `json:"n"`
	T string          `json:"t"`
	K string          `json:"k"`
	V json.RawMessage `json:"v"`
	A *rawFieldAttrs  `json:"a"`
}

type rawFieldAttrs struct {
	SSHKeyAttributes *rawSSHKeyAttrs `json:"sshKeyAttributes"`
}

type rawSSHKeyAttrs struct {
	PrivateKey  string `json:"privateKey"`
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
}

// ExtractItem parses raw decrypted 1Password overview & details JSON into a normalized Item.
func ExtractItem(
	vaultUUID, vaultName, itemUUID, categoryUUID string,
	createdAtUnix, updatedAtUnix int64,
	favorite bool,
	rawOverviewJSON, rawDetailsJSON []byte,
) (*Item, []string, error) {
	var ov rawOverview
	if len(rawOverviewJSON) > 0 {
		if err := json.Unmarshal(rawOverviewJSON, &ov); err != nil {
			return nil, nil, fmt.Errorf("parse overview JSON: %w", err)
		}
	}
	var det rawDetails
	if len(rawDetailsJSON) > 0 {
		if err := json.Unmarshal(rawDetailsJSON, &det); err != nil {
			return nil, nil, fmt.Errorf("parse details JSON: %w", err)
		}
	}

	var warnings []string

	var createdAt, updatedAt time.Time
	if createdAtUnix > 0 {
		createdAt = unixSecondsOrMillis(createdAtUnix)
	}
	if updatedAtUnix > 0 {
		updatedAt = unixSecondsOrMillis(updatedAtUnix)
	} else {
		updatedAt = createdAt
	}

	item := &Item{
		UUID:         itemUUID,
		VaultUUID:    vaultUUID,
		VaultName:    vaultName,
		CategoryUUID: categoryUUID,
		Title:        strings.TrimSpace(ov.Title),
		Notes:        det.NotesPlain,
		Tags:         ov.Tags,
		Favorite:     favorite,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	}
	if item.Title == "" {
		item.Title = itemUUID
	}

	// Collect deduplicated URLs.
	seenURL := map[string]bool{}
	addURL := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || seenURL[u] {
			return
		}
		seenURL[u] = true
		item.URLs = append(item.URLs, u)
	}
	addURL(ov.URL)
	for _, u := range ov.URLs {
		addURL(u.URL)
	}
	for _, u := range ov.URLsLow {
		addURL(u.URL)
	}

	// Top-level fields (username, password, extra).
	for _, f := range det.Fields {
		switch f.Designation {
		case "username":
			if item.Username == "" && f.Value != "" {
				item.Username = f.Value
				continue
			}
		case "password":
			if item.Password == "" && f.Value != "" {
				item.Password = f.Value
				continue
			}
		}
		if f.Value != "" {
			name := f.Name
			if name == "" {
				name = f.Designation
			}
			if name == "" {
				name = f.ID
			}
			item.CustomFields = append(item.CustomFields, CustomField{
				Name:      name,
				Value:     f.Value,
				Concealed: f.Type == "P",
			})
		}
	}
	if item.Password == "" && det.Password != "" {
		item.Password = det.Password
	}

	seenCredIDs := map[string]bool{}
	appendPasskey := func(pk *Passkey, diag *PasskeyDiagnostic, warn string) {
		if diag != nil {
			item.PasskeyInspect = append(item.PasskeyInspect, *diag)
		}
		if warn != "" {
			warnings = append(warnings, warn)
		}
		if pk == nil {
			return
		}
		key := string(pk.CredentialID)
		if seenCredIDs[key] {
			return
		}
		seenCredIDs[key] = true
		item.Passkeys = append(item.Passkeys, *pk)
	}

	// Section fields (TOTP, SSH keys, custom fields, defensive passkey scan).
	for _, sec := range det.Sections {
		for _, f := range sec.Fields {
			kLower := strings.ToLower(strings.TrimSpace(f.K))

			// Primary TOTP field
			if item.TOTP == "" && (strings.HasPrefix(f.N, "TOTP_") || kLower == "totp") {
				var s string
				if json.Unmarshal(f.V, &s) == nil && strings.TrimSpace(s) != "" {
					item.TOTP = strings.TrimSpace(s)
					continue
				}
			}

			// SSH key attributes
			if f.A != nil && f.A.SSHKeyAttributes != nil {
				if item.SSHKey == nil {
					item.SSHKey = &SSHKey{
						PrivateKey:  f.A.SSHKeyAttributes.PrivateKey,
						PublicKey:   f.A.SSHKeyAttributes.PublicKey,
						Fingerprint: f.A.SSHKeyAttributes.Fingerprint,
					}
				}
				continue
			}

			// Defensive: check if a section field ever carries an embedded passkey object.
			if strings.Contains(kLower, "passkey") || strings.Contains(kLower, "webauthn") {
				var obj map[string]any
				if json.Unmarshal(f.V, &obj) == nil && len(obj) > 0 {
					pk, diag, warn := parsePasskeyMaps(item, ov.Ainfo, nil, obj, "details.sections."+f.K)
					appendPasskey(pk, diag, warn)
					continue
				}
			}

			// Preserve remaining non-empty section fields as custom fields.
			valStr := renderSectionValue(f.V)
			if valStr == "" {
				continue
			}
			label := strings.TrimSpace(f.T)
			if label == "" {
				label = strings.TrimSpace(f.N)
			}
			if label == "" {
				continue
			}
			concealed := isSensitiveFieldKind(kLower, f.N)
			item.CustomFields = append(item.CustomFields, CustomField{
				Section:   sec.Title,
				Name:      label,
				Value:     valStr,
				Concealed: concealed,
			})
		}
	}

	// Primary 1Password 8 passkey storage: overview.passkey + details.passkey
	if len(ov.Passkey) > 0 || len(det.Passkey) > 0 {
		pk, diag, warn := parsePasskeyMaps(item, ov.Ainfo, ov.Passkey, det.Passkey, "overview.passkey+details.passkey")
		appendPasskey(pk, diag, warn)
	}

	// Future-proofing: details.passkeys array if 1Password adds multi-passkey support.
	for i, pkMap := range det.Passkeys {
		pk, diag, warn := parsePasskeyMaps(item, ov.Ainfo, nil, pkMap, fmt.Sprintf("details.passkeys[%d]", i))
		appendPasskey(pk, diag, warn)
	}

	// If item has passkeys and no URL yet, synthesize https://<rpId> so password managers match it.
	if len(item.URLs) == 0 {
		for _, pk := range item.Passkeys {
			if pk.RPID != "" && strings.Contains(pk.RPID, ".") && !strings.HasPrefix(pk.RPID, "http") {
				addURL("https://" + pk.RPID)
			}
		}
	}

	return item, warnings, nil
}

func isSensitiveFieldKind(kLower, fieldID string) bool {
	if strings.HasPrefix(fieldID, "TOTP_") {
		return true
	}
	switch kLower {
	case "concealed", "totp", "otp", "sshkey", "password":
		return true
	}
	return strings.Contains(kLower, "passkey") || strings.Contains(kLower, "webauthn")
}

func unixSecondsOrMillis(v int64) time.Time {
	// Treat timestamps > 1e12 as milliseconds (year 33658 in seconds, ~2001+ in ms).
	if v > 1_000_000_000_000 {
		return time.UnixMilli(v).UTC()
	}
	return time.Unix(v, 0).UTC()
}

func parseAlgField(m map[string]any) string {
	if s := firstString(m, "alg", "algorithm"); s != "" {
		return s
	}
	// Support numeric COSE algorithm IDs (e.g. -7 = ES256, -8 = EdDSA, -35 = ES384, -36 = ES512, -257 = RS256).
	if m == nil {
		return ""
	}
	for _, k := range []string{"alg", "algorithm"} {
		v, ok := m[k]
		if !ok {
			continue
		}
		var n int64
		switch tv := v.(type) {
		case float64:
			n = int64(tv)
		case int64:
			n = tv
		case json.Number:
			if parsed, err := tv.Int64(); err == nil {
				n = parsed
			} else {
				continue
			}
		default:
			continue
		}
		switch n {
		case -7:
			return "ES256"
		case -8:
			return "EdDSA"
		case -35:
			return "ES384"
		case -36:
			return "ES512"
		case -257:
			return "RS256"
		default:
			return fmt.Sprintf("%d", n)
		}
	}
	return ""
}

func parsePasskeyMaps(
	item *Item,
	ainfo string,
	ovMap map[string]any,
	detMap map[string]any,
	location string,
) (*Passkey, *PasskeyDiagnostic, string) {
	diag := &PasskeyDiagnostic{
		ItemUUID:     item.UUID,
		VaultName:    item.VaultName,
		ItemTitle:    item.Title,
		Location:     location,
		OverviewKeys: sortedMapKeys(ovMap),
		DetailsKeys:  sortedMapKeys(detMap),
	}

	pkType := firstString(detMap, "type")
	if pkType == "" {
		pkType = "webauthn"
	}
	diag.Type = pkType

	algHint := parseAlgField(detMap)
	diag.Alg = algHint

	rpID := firstString(ovMap, "rpId", "rp_id")
	if rpID == "" {
		rpID = firstString(detMap, "rpId", "rp_id")
	}
	diag.RPID = rpID

	credIDStr := firstString(ovMap, "credentialId", "credential_id")
	if credIDStr == "" {
		credIDStr = firstString(detMap, "credentialId", "credential_id")
	}
	userHandleStr := firstString(detMap, "userHandle", "user_handle")
	if userHandleStr == "" {
		userHandleStr = firstString(ovMap, "userHandle", "user_handle")
	}
	privKeyStr := firstString(detMap, "privateKey", "private_key", "key", "keyValue")

	if pkType != "webauthn" && privKeyStr == "" {
		diag.Error = fmt.Sprintf("non-webauthn passkey type %q without privateKey", pkType)
		return nil, diag, fmt.Sprintf("item %q (%s): skipped passkey of type %q (no privateKey)", item.Title, item.UUID, pkType)
	}
	if privKeyStr == "" {
		diag.Error = fmt.Sprintf("missing privateKey at %s", location)
		return nil, diag, fmt.Sprintf("item %q (%s): passkey metadata present at %s, but missing privateKey", item.Title, item.UUID, location)
	}
	if credIDStr == "" {
		diag.Error = "missing credentialId"
		return nil, diag, fmt.Sprintf("item %q (%s): skipped passkey at %s (missing credentialId)", item.Title, item.UUID, location)
	}
	if rpID == "" {
		diag.Error = "missing rpId"
		return nil, diag, fmt.Sprintf("item %q (%s): skipped passkey at %s (missing rpId)", item.Title, item.UUID, location)
	}

	credIDBytes, err := opcrypto.Base64URLDecode(credIDStr)
	if err != nil || len(credIDBytes) == 0 {
		diag.Error = fmt.Sprintf("decode credentialId: %v", err)
		return nil, diag, fmt.Sprintf("item %q (%s): failed to decode credentialId: %v", item.Title, item.UUID, err)
	}
	diag.CredIDBytes = len(credIDBytes)

	var warnings []string
	var userHandleBytes []byte
	if userHandleStr != "" {
		userHandleBytes, err = opcrypto.Base64URLDecode(userHandleStr)
		if err != nil {
			userHandleBytes = []byte(userHandleStr)
			warnings = append(warnings, fmt.Sprintf("item %q (%s): userHandle was not valid base64url; preserved as raw UTF-8 bytes", item.Title, item.UUID))
		}
	}
	diag.UserHandleBytes = len(userHandleBytes)

	if rawPriv, err := opcrypto.Base64URLDecode(privKeyStr); err == nil {
		diag.PrivateKeyBytes = len(rawPriv)
		opcrypto.WipeBytes(rawPriv)
	} else {
		diag.PrivateKeyBytes = len(privKeyStr)
	}

	normKey, err := NormalizePrivateKey(privKeyStr, algHint)
	if err != nil {
		diag.Error = err.Error()
		return nil, diag, fmt.Sprintf("item %q (%s): failed to parse passkey privateKey: %v", item.Title, item.UUID, err)
	}
	diag.DetectedFormat = normKey.SourceFormat
	diag.KeyAlgorithm = normKey.KeyAlgorithm
	diag.KeyCurve = normKey.KeyCurve

	// Optional PRF / hmac-secret extension (1Password background.js: { alg: "HMAC_SHA256", credWithUv: "<b64url>" })
	var prf *PRFData
	if prfObj, ok := detMap["prf"].(map[string]any); ok {
		credWithUVStr := firstString(prfObj, "credWithUv", "cred_with_uv", "credWithUV")
		if credWithUVStr != "" {
			if b, err := opcrypto.Base64URLDecode(credWithUVStr); err == nil && len(b) > 0 {
				prfAlg := firstString(prfObj, "alg", "algorithm")
				if prfAlg == "" {
					prfAlg = "HMAC_SHA256"
				}
				prf = &PRFData{
					Algorithm:  prfAlg,
					CredWithUV: b,
				}
				diag.HasPRF = true
			}
		}
	}

	userName := firstString(detMap, "username", "userName")
	if userName == "" {
		userName = item.Username
	}
	if userName == "" {
		userName = strings.TrimSpace(ainfo)
	}
	userDisplayName := firstString(detMap, "userDisplayName", "user_display_name")
	if userDisplayName == "" {
		userDisplayName = userName
	}

	rpName := firstString(detMap, "rpName", "rp_name")
	if rpName == "" {
		rpName = item.Title
	}
	if rpName == "" {
		rpName = rpID
	}

	pkCreatedAt := item.CreatedAt
	if ts := firstInt64(detMap, "createdAt", "created_at"); ts > 0 {
		pkCreatedAt = unixSecondsOrMillis(ts)
	}

	rawCounter := firstInt64(detMap, "counter")
	var counter uint32
	if rawCounter < 0 {
		warnings = append(warnings, fmt.Sprintf("item %q (%s): negative passkey counter %d clamped to 0", item.Title, item.UUID, rawCounter))
	} else if rawCounter > math.MaxUint32 {
		counter = math.MaxUint32
		warnings = append(warnings, fmt.Sprintf("item %q (%s): oversized passkey counter %d clamped to uint32 max", item.Title, item.UUID, rawCounter))
	} else {
		counter = uint32(rawCounter)
	}

	sourceAlg := algHint
	if sourceAlg == "" {
		sourceAlg = normKey.KeyAlgorithm
	}

	return &Passkey{
		CredentialID:       credIDBytes,
		RPID:               rpID,
		RPName:             rpName,
		UserHandle:         userHandleBytes,
		UserName:           userName,
		UserDisplayName:    userDisplayName,
		Counter:            counter,
		Discoverable:       true,
		CreatedAt:          pkCreatedAt,
		PrivateKeyPKCS8DER: normKey.PKCS8DER,
		PrivateKeyPEM:      normKey.PKCS8PEM,
		KeyAlgorithm:       normKey.KeyAlgorithm,
		KeyCurve:           normKey.KeyCurve,
		SourceAlg:          sourceAlg,
		SourceFormat:       normKey.SourceFormat,
		PRF:                prf,
	}, diag, strings.Join(warnings, "; ")
}

func firstString(m map[string]any, keys ...string) string {
	if m == nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func firstInt64(m map[string]any, keys ...string) int64 {
	if m == nil {
		return 0
	}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case float64:
				return int64(n)
			case int64:
				return n
			case json.Number:
				if i, err := n.Int64(); err == nil {
					return i
				}
			}
		}
	}
	return 0
}

func sortedMapKeys(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func renderSectionValue(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed == `""` {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	return trimmed
}
