package huudis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the typed view over a Huudis-issued JWT. Every Huudis token
// carries the Forjio-specific fields below alongside the standard OIDC
// claims.
type Claims struct {
	Iss          string `json:"iss"`
	Aud          string `json:"aud"`
	Sub          string `json:"sub"`
	Exp          int64  `json:"exp"`
	Iat          int64  `json:"iat"`
	AccountID    string `json:"accountId"`
	IdentityID   string `json:"identityId"`
	IdentityType string `json:"identityType"` // "user" | "service_account"
	Scope        string `json:"scope"`
	MfaVerified  bool   `json:"mfaVerified,omitempty"`
	Email        string `json:"email,omitempty"`
	EmailVerif   bool   `json:"email_verified,omitempty"`
	Name         string `json:"name,omitempty"`
	// Raw contains every claim exactly as decoded — use this for custom fields.
	Raw map[string]any `json:"-"`
}

// VerifyOptions customizes verification. Zero-value is fine: issuer +
// audience will be read from HUUDIS_ISSUER / HUUDIS_AUDIENCE env vars.
type VerifyOptions struct {
	Issuer     string
	Audience   string
	RequireMFA bool
}

// VerifyAccessToken verifies a Huudis-issued JWT against the issuer's
// JWKS. Strips a leading `Bearer ` if present, so you can pass
// `r.Header.Get("Authorization")` directly.
//
// Reads `HUUDIS_ISSUER` and `HUUDIS_AUDIENCE` from env when the fields
// on VerifyOptions are empty — same convenience the Node + Python SDKs
// have.
func VerifyAccessToken(ctx context.Context, tokenOrHeader string, opts VerifyOptions) (*Claims, error) {
	if tokenOrHeader == "" {
		return nil, newErr("MISSING_TOKEN", "no Authorization header / token provided")
	}
	tokenStr := stripBearer(tokenOrHeader)

	issuer := opts.Issuer
	if issuer == "" {
		issuer = os.Getenv("HUUDIS_ISSUER")
	}
	audience := opts.Audience
	if audience == "" {
		audience = os.Getenv("HUUDIS_AUDIENCE")
	}
	if issuer == "" {
		return nil, newErr("MISSING_ISSUER", "set HUUDIS_ISSUER env or VerifyOptions.Issuer")
	}
	if audience == "" {
		return nil, newErr("MISSING_AUDIENCE", "set HUUDIS_AUDIENCE env or VerifyOptions.Audience")
	}

	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return globalJwks.key(ctx, issuer, kid)
	}, jwt.WithValidMethods([]string{"ES256", "RS256"}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience))
	if err != nil {
		return nil, newErr("INVALID_TOKEN", err.Error())
	}
	if !parsed.Valid {
		return nil, newErr("INVALID_TOKEN", "token failed validation")
	}

	raw, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, newErr("INVALID_TOKEN", "unexpected claims shape")
	}
	c, err := mapToClaims(raw)
	if err != nil {
		return nil, err
	}
	if opts.RequireMFA && !c.MfaVerified {
		return nil, newErr("MFA_REQUIRED", "this operation requires an MFA-verified token")
	}
	return c, nil
}

func stripBearer(v string) string {
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return strings.TrimSpace(v)
}

func mapToClaims(m jwt.MapClaims) (*Claims, error) {
	c := &Claims{Raw: m}
	required := []string{"accountId", "identityId", "identityType", "scope"}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return nil, newErr("INCOMPLETE_CLAIMS", "token is missing required Huudis claim: "+k)
		}
	}
	c.Iss, _ = m["iss"].(string)
	switch aud := m["aud"].(type) {
	case string:
		c.Aud = aud
	case []any:
		if len(aud) > 0 {
			if s, ok := aud[0].(string); ok {
				c.Aud = s
			}
		}
	}
	c.Sub, _ = m["sub"].(string)
	c.Exp = toInt64(m["exp"])
	c.Iat = toInt64(m["iat"])
	c.AccountID, _ = m["accountId"].(string)
	c.IdentityID, _ = m["identityId"].(string)
	c.IdentityType, _ = m["identityType"].(string)
	c.Scope, _ = m["scope"].(string)
	if v, ok := m["mfaVerified"].(bool); ok {
		c.MfaVerified = v
	}
	c.Email, _ = m["email"].(string)
	if v, ok := m["email_verified"].(bool); ok {
		c.EmailVerif = v
	}
	c.Name, _ = m["name"].(string)
	return c, nil
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	}
	return 0
}

// ─── JWKS caching ───────────────────────────────────────────────────────

type jwksEntry struct {
	keys      map[string]any // kid → *ecdsa.PublicKey or *rsa.PublicKey
	fetchedAt time.Time
}

type jwksCache struct {
	mu      sync.Mutex
	entries map[string]*jwksEntry
	ttl     time.Duration
}

var globalJwks = &jwksCache{entries: map[string]*jwksEntry{}, ttl: time.Hour}

type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type jwksDoc struct {
	Keys []jwksKey `json:"keys"`
}

func (c *jwksCache) key(ctx context.Context, issuer, kid string) (any, error) {
	c.mu.Lock()
	entry := c.entries[issuer]
	c.mu.Unlock()
	if entry == nil || time.Since(entry.fetchedAt) > c.ttl {
		fresh, err := fetchJwks(ctx, issuer)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.entries[issuer] = fresh
		c.mu.Unlock()
		entry = fresh
	}
	k, ok := entry.keys[kid]
	if !ok {
		// Kid might be newly rotated — bypass the TTL once and refetch.
		fresh, err := fetchJwks(ctx, issuer)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.entries[issuer] = fresh
		c.mu.Unlock()
		k, ok = fresh.keys[kid]
		if !ok {
			return nil, newErr("UNKNOWN_KID", fmt.Sprintf("no signing key matches kid %q", kid))
		}
	}
	return k, nil
}

func fetchJwks(ctx context.Context, issuer string) (*jwksEntry, error) {
	url := strings.TrimRight(issuer, "/") + "/.well-known/jwks.json"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, newErr("JWKS_FETCH_FAILED", err.Error())
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return nil, newErr("JWKS_FETCH_FAILED", fmt.Sprintf("HTTP %d", res.StatusCode))
	}
	var doc jwksDoc
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return nil, newErr("JWKS_FETCH_FAILED", err.Error())
	}
	out := &jwksEntry{keys: map[string]any{}, fetchedAt: time.Now()}
	for _, k := range doc.Keys {
		key, err := jwksKeyToPublic(k)
		if err != nil {
			continue
		}
		out.keys[k.Kid] = key
	}
	return out, nil
}

func jwksKeyToPublic(k jwksKey) (any, error) {
	switch k.Kty {
	case "EC":
		// ES256 — P-256 curve only (what Huudis issues).
		xBytes, err := base64URLDecode(k.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64URLDecode(k.Y)
		if err != nil {
			return nil, err
		}
		return ecdsaPub(xBytes, yBytes)
	case "RSA":
		nBytes, err := base64URLDecode(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64URLDecode(k.E)
		if err != nil {
			return nil, err
		}
		return rsaPub(nBytes, eBytes)
	default:
		return nil, newErr("UNSUPPORTED_KTY", "unsupported key type: "+k.Kty)
	}
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// Builds a big.Int from raw unsigned bytes.
func bytesToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}
