package opcloud

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/jimbb/1password-passkey-export/internal/opcrypto"
)

// RFC 5054 / RFC 3526 Group 16 (4096-bit prime N, generator g = 5) used by 1Password SRPg-4096.
const rfc5054N4096Hex = "" +
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
	"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
	"302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
	"A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
	"49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
	"FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
	"180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
	"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
	"04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
	"B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
	"1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
	"E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26" +
	"99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB" +
	"04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
	"233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127" +
	"D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
	"FFFFFFFFFFFFFFFF"

var (
	srpN4096 = mustHexBigInt(rfc5054N4096Hex)
	srpG4096 = big.NewInt(5)
	srpNLen  = (srpN4096.BitLen() + 7) / 8 // 512 bytes
)

func mustHexBigInt(h string) *big.Int {
	v, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic("invalid hex prime")
	}
	return v
}

// SRPClient implements 1Password's current SRP-6a ("Standard" / SRPg-4096) client exchange.
type SRPClient struct {
	n    *big.Int
	g    *big.Int
	k    *big.Int
	x    *big.Int
	a    *big.Int
	bigA *big.Int
}

// standardK computes k = SHA256(N || PAD(g)) for RFC 5054 4096-bit group.
func standardK() *big.Int {
	kh := sha256.New()
	kh.Write(srpN4096.Bytes())
	kh.Write(padModN(srpG4096, srpN4096))
	return new(big.Int).SetBytes(kh.Sum(nil))
}

// NewSRPClient creates an SRP-6a client for 1Password's SRPg-4096 login flow.
func NewSRPClient(xBytes []byte) (*SRPClient, error) {
	aBytes := make([]byte, 38)
	if _, err := io.ReadFull(rand.Reader, aBytes); err != nil {
		return nil, fmt.Errorf("random SRP exponent: %w", err)
	}
	defer opcrypto.WipeBytes(aBytes)
	return newSRPClientWithParams(xBytes, aBytes, standardK()), nil
}

func newSRPClientWithParams(xBytes, aBytes []byte, k *big.Int) *SRPClient {
	n := new(big.Int).Set(srpN4096)
	g := new(big.Int).Set(srpG4096)
	x := new(big.Int).SetBytes(xBytes)
	a := new(big.Int).SetBytes(aBytes)
	bigA := new(big.Int).Exp(g, a, n)
	return &SRPClient{n: n, g: g, k: new(big.Int).Set(k), x: x, a: a, bigA: bigA}
}

// Wipe overwrites secret SRP exponents in memory (best-effort in Go).
func (c *SRPClient) Wipe() {
	if c == nil {
		return
	}
	for _, z := range []*big.Int{c.x, c.a} {
		if z != nil {
			bits := z.Bits()
			for i := range bits {
				bits[i] = 0
			}
			z.SetInt64(0)
		}
	}
}

// Verifier computes v = g^x mod N (used in known-answer tests).
func (c *SRPClient) Verifier() *big.Int {
	return new(big.Int).Exp(c.g, c.x, c.n)
}

// PublicAHex returns A encoded as lowercase hex with leading zeros stripped (1Password wire format).
func (c *SRPClient) PublicAHex() string {
	return bigIntToServerHex(c.bigA)
}

// SessionKey computes the 32-byte SRP session key K = SHA256(hex(S)) from the server's B.
func (c *SRPClient) SessionKey(bigB *big.Int) ([]byte, error) {
	if bigB == nil || bigB.Sign() <= 0 || bigB.Cmp(c.n) >= 0 || bigB.Cmp(big.NewInt(1)) == 0 {
		return nil, errors.New("server sent invalid SRP public value B (must satisfy 1 < B < N)")
	}

	// Standard u = SHA256(PAD(A) || PAD(B))
	uh := sha256.New()
	uh.Write(padModN(c.bigA, c.n))
	uh.Write(padModN(bigB, c.n))
	u := new(big.Int).SetBytes(uh.Sum(nil))
	return c.sessionKeyWithU(bigB, u)
}

func (c *SRPClient) sessionKeyWithU(bigB, u *big.Int) ([]byte, error) {
	if bigB == nil || bigB.Sign() <= 0 || bigB.Cmp(c.n) >= 0 || bigB.Cmp(big.NewInt(1)) == 0 {
		return nil, errors.New("server sent invalid SRP public value B")
	}
	if u == nil || u.Sign() == 0 {
		return nil, errors.New("SRP scrambling parameter u is zero")
	}

	// base = (B - k * g^x) mod N
	gx := new(big.Int).Exp(c.g, c.x, c.n)
	kgx := new(big.Int).Mul(c.k, gx)
	kgx.Mod(kgx, c.n)
	base := new(big.Int).Sub(bigB, kgx)
	base.Mod(base, c.n)

	// exp = u*x + a
	exp := new(big.Int).Mul(u, c.x)
	exp.Add(exp, c.a)

	// S = base^exp mod N
	s := new(big.Int).Exp(base, exp, c.n)
	sHex := bigIntToServerHex(s)
	sum := sha256.Sum256([]byte(sHex))
	out := make([]byte, 32)
	copy(out, sum[:])
	return out, nil
}

// SRPIdentity computes 1Password's SRP identity I:
// base64url(SHA256(SHA256(accountID) || SHA256(lowercase(NFKD(trim(email)))))).
func SRPIdentity(email, accountID string) string {
	hAcct := sha256.Sum256([]byte(accountID))
	hEmail := sha256.Sum256([]byte(opcrypto.NormalizeEmail(email)))
	var buf [64]byte
	copy(buf[:32], hAcct[:])
	copy(buf[32:], hEmail[:])
	sum := sha256.Sum256(buf[:])
	return opcrypto.Base64URLEncode(sum[:])
}

// ClientProof computes M1 = SHA256((H(N) XOR H(g)) || H(I) || salt || A || B || K).
func (c *SRPClient) ClientProof(bigB *big.Int, sessionKey []byte, identity string, salt []byte) []byte {
	hn := sha256.Sum256(c.n.Bytes())
	hg := sha256.Sum256(c.g.Bytes())
	var xor [32]byte
	for i := range 32 {
		xor[i] = hn[i] ^ hg[i]
	}
	hi := sha256.Sum256([]byte(identity))

	h := sha256.New()
	h.Write(xor[:])
	h.Write(hi[:])
	h.Write(salt)
	h.Write(c.bigA.Bytes())
	h.Write(bigB.Bytes())
	h.Write(sessionKey)
	return h.Sum(nil)
}

// VerifyServerConfirmation checks serverVerifyHash == SHA256(A || M1 || K).
func (c *SRPClient) VerifyServerConfirmation(m1, sessionKey, serverHash []byte) error {
	h := sha256.New()
	h.Write(c.bigA.Bytes())
	h.Write(m1)
	h.Write(sessionKey)
	expected := h.Sum(nil)
	if subtle.ConstantTimeCompare(expected, serverHash) != 1 {
		return errors.New("server SRP confirmation hash did not verify")
	}
	return nil
}

func padModN(v, n *big.Int) []byte {
	mod := new(big.Int).Mod(v, n)
	b := mod.Bytes()
	if len(b) >= srpNLen {
		return b
	}
	out := make([]byte, srpNLen)
	copy(out[srpNLen-len(b):], b)
	return out
}

func bigIntToServerHex(v *big.Int) string {
	h := strings.TrimLeft(fmt.Sprintf("%x", v), "0")
	if h == "" {
		return "0"
	}
	return h
}

func parseServerHex(h string) (*big.Int, error) {
	h = strings.TrimSpace(h)
	if h == "" || len(h) > 1024 {
		return nil, errors.New("invalid SRP hex value from server")
	}
	v, ok := new(big.Int).SetString(h, 16)
	if !ok {
		return nil, errors.New("malformed SRP hex value from server")
	}
	return v, nil
}
