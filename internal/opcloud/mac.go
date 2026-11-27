package opcloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"

	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
)

const macDerivationMessage = "He never wears a Mac, in the pouring rain. Very strange."

// RequestMAC computes 1Password's X-AgileBits-MAC request header value.
// Matches 1Password's burp-1password-session-analyzer specification:
//
//	mac_key = HMAC-SHA256(sessionKey, "He never wears a Mac, in the pouring rain. Very strange.")
//	message = "{sessionID}|{METHOD}|{host}/{path without leading /}?{query}|v1|{requestId}"
//	header  = "v1|{requestId}|" + base64url(HMAC-SHA256(mac_key, message)[:12])
func RequestMAC(sessionKey []byte, sessionID string, requestID uint32, method string, u *url.URL) string {
	derive := hmac.New(sha256.New, sessionKey)
	derive.Write([]byte(macDerivationMessage))
	macKey := derive.Sum(nil)

	host := strings.ToLower(u.Hostname())
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	query := u.RawQuery
	msg := fmt.Sprintf("%s|%s|%s/%s?%s|v1|%d", sessionID, strings.ToUpper(method), host, path, query, requestID)

	m := hmac.New(sha256.New, macKey)
	m.Write([]byte(msg))
	tag := m.Sum(nil)
	return fmt.Sprintf("v1|%d|%s", requestID, opcrypto.Base64URLEncode(tag[:12]))
}
