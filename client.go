package huudis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// SDKVersion is this SDK's version.
const SDKVersion = "0.6.0"

// Client is the high-level SDK surface: JWT verification, OIDC code
// flow, refresh, userinfo, authz check, plus the full Huudis admin
// resource namespaces (IAM, workspaces, MFA, billing, …) accessible as
// fields. See admin.go for the per-namespace methods.
type Client struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Audience     string
	APIBase      string
	HTTP         *http.Client

	// Admin resource namespaces — mirror the Node + Python SDKs.
	IAM                  *IamResource
	IdentityProviders    *IdentityProvidersResource
	AssumedSessions      *AssumedSessionsResource
	Authz                *AuthzResource
	Workspaces           *WorkspacesResource
	EndUsers             *EndUsersResource
	MFA                  *MfaResource
	OidcClients          *OidcClientsResource
	ConnectedApps        *ConnectedAppsResource
	Services             *ServicesResource
	WebhookSubscriptions *WebhookSubscriptionsResource
	Billing              *BillingResource
	Account              *AccountResource

	// API has every feature route, one method each (generated from the API spec:
	// api_generated.go). Each call carries the credential its route takes; see
	// ClientOptions.
	API *GeneratedAPI

	token           string
	accessKeyID     string
	secretAccessKey string
	workspaceID     string
	now             func() time.Time
}

// ClientOptions matches the env-var defaults of the Node + Python SDKs.
//
// Credentials, by route: /api/v1/app/* authenticates as your OIDC app (ClientID +
// ClientSecret, HTTP Basic). Every other call carries, in order, the per-call
// RequestAuth token, else Token (a signed-in person's bearer), else the access key
// (AccessKeyID + SecretAccessKey): each request signed Huudis-HMAC-SHA256, acting as
// the key's user within that user's IAM policies on /account/*, /iam/* and /authz/*.
type ClientOptions struct {
	Issuer       string // defaults to HUUDIS_ISSUER
	ClientID     string // defaults to HUUDIS_CLIENT_ID; optional with an access key or token
	ClientSecret string // defaults to HUUDIS_CLIENT_SECRET; empty for public clients
	Audience     string // defaults to ClientID
	APIBase      string // defaults to Issuer
	HTTP         *http.Client

	// Token is a signed-in person's bearer access token, the default for every
	// call. Defaults to HUUDIS_TOKEN.
	Token string
	// AccessKeyID and SecretAccessKey are an IAM access key, used when there is no
	// token. Default HUUDIS_ACCESS_KEY_ID and HUUDIS_SECRET_ACCESS_KEY.
	AccessKeyID     string
	SecretAccessKey string
	// WorkspaceID names the workspace to act in (X-Huudis-Workspace-Id). Defaults to
	// HUUDIS_WORKSPACE_ID, else the caller's first workspace.
	WorkspaceID string
	// Now overrides the clock used for signing (tests).
	Now func() time.Time
}

func envOr(v, name string) string {
	if v != "" {
		return v
	}
	return os.Getenv(name)
}

func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Issuer == "" {
		opts.Issuer = os.Getenv("HUUDIS_ISSUER")
	}
	if opts.ClientID == "" {
		opts.ClientID = os.Getenv("HUUDIS_CLIENT_ID")
	}
	if opts.ClientSecret == "" {
		opts.ClientSecret = os.Getenv("HUUDIS_CLIENT_SECRET")
	}
	opts.Token = envOr(opts.Token, "HUUDIS_TOKEN")
	opts.AccessKeyID = envOr(opts.AccessKeyID, "HUUDIS_ACCESS_KEY_ID")
	opts.SecretAccessKey = envOr(opts.SecretAccessKey, "HUUDIS_SECRET_ACCESS_KEY")
	opts.WorkspaceID = envOr(opts.WorkspaceID, "HUUDIS_WORKSPACE_ID")
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Issuer == "" {
		return nil, newErr("MISSING_ISSUER", "set HUUDIS_ISSUER env or ClientOptions.Issuer")
	}
	hasKey := opts.AccessKeyID != "" && opts.SecretAccessKey != ""
	if opts.ClientID == "" && !hasKey && opts.Token == "" {
		return nil, newErr("MISSING_CLIENT_ID", "set HUUDIS_CLIENT_ID env or ClientOptions.ClientID (or an access key or token)")
	}
	if opts.Audience == "" {
		opts.Audience = opts.ClientID
	}
	if opts.APIBase == "" {
		opts.APIBase = opts.Issuer
	}
	if opts.HTTP == nil {
		opts.HTTP = http.DefaultClient
	}
	c := &Client{
		Issuer:       strings.TrimRight(opts.Issuer, "/"),
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		Audience:     opts.Audience,
		APIBase:      strings.TrimRight(opts.APIBase, "/"),
		HTTP:         opts.HTTP,

		token:           opts.Token,
		accessKeyID:     opts.AccessKeyID,
		secretAccessKey: opts.SecretAccessKey,
		workspaceID:     opts.WorkspaceID,
		now:             opts.Now,
	}
	c.API = &GeneratedAPI{c: c}
	c.IAM = &IamResource{c: c}
	c.IdentityProviders = &IdentityProvidersResource{c: c}
	c.AssumedSessions = &AssumedSessionsResource{c: c}
	c.Authz = &AuthzResource{c: c}
	c.Workspaces = &WorkspacesResource{c: c}
	c.EndUsers = &EndUsersResource{c: c}
	c.MFA = &MfaResource{c: c}
	c.OidcClients = &OidcClientsResource{c: c}
	c.ConnectedApps = &ConnectedAppsResource{c: c}
	c.Services = &ServicesResource{c: c}
	c.WebhookSubscriptions = &WebhookSubscriptionsResource{c: c}
	c.Billing = &BillingResource{c: c}
	c.Account = &AccountResource{c: c}
	c.Account.Sessions = &AccountSessionsResource{c: c}
	c.Account.Linked = &AccountLinkedResource{c: c}
	return c, nil
}

// VerifyAccessToken — client-scoped convenience wrapper.
func (c *Client) VerifyAccessToken(ctx context.Context, tokenOrHeader string, requireMFA bool) (*Claims, error) {
	return VerifyAccessToken(ctx, tokenOrHeader, VerifyOptions{
		Issuer: c.Issuer, Audience: c.Audience, RequireMFA: requireMFA,
	})
}

// AuthorizationURLOptions controls the URL built for step 1 of the code flow.
type AuthorizationURLOptions struct {
	RedirectURI         string
	State               string
	Scope               string // default: "openid profile email"
	CodeChallenge       string // base64url of sha256(verifier). Strongly recommended.
	CodeChallengeMethod string // default: "S256"
	LoginHint           string // pre-fills the login form
}

// AuthorizationURL builds the /authorize redirect target.
func (c *Client) AuthorizationURL(opts AuthorizationURLOptions) string {
	if opts.Scope == "" {
		opts.Scope = "openid profile email"
	}
	if opts.CodeChallengeMethod == "" {
		opts.CodeChallengeMethod = "S256"
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", opts.RedirectURI)
	q.Set("scope", opts.Scope)
	q.Set("state", opts.State)
	if opts.CodeChallenge != "" {
		q.Set("code_challenge", opts.CodeChallenge)
		q.Set("code_challenge_method", opts.CodeChallengeMethod)
	}
	if opts.LoginHint != "" {
		q.Set("login_hint", opts.LoginHint)
	}
	return fmt.Sprintf("%s/api/v1/oidc/authorize?%s", c.Issuer, q.Encode())
}

// TokenResponse wraps every /token grant result.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope"`
}

// ExchangeCode swaps an authorization code for tokens.
func (c *Client) ExchangeCode(ctx context.Context, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	body := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {c.ClientID},
	}
	if c.ClientSecret != "" {
		body.Set("client_secret", c.ClientSecret)
	}
	if codeVerifier != "" {
		body.Set("code_verifier", codeVerifier)
	}
	return c.tokenEndpoint(ctx, body)
}

// RefreshAccessToken mints a new access token off a refresh token.
func (c *Client) RefreshAccessToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	body := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.ClientID},
	}
	if c.ClientSecret != "" {
		body.Set("client_secret", c.ClientSecret)
	}
	return c.tokenEndpoint(ctx, body)
}

// UserInfo fetches the standard OIDC userinfo for a bearer token.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.Issuer+"/api/v1/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, newErr("USERINFO_FAILED", err.Error())
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		body, _ := io.ReadAll(res.Body)
		return nil, newErr("USERINFO_FAILED", fmt.Sprintf("HTTP %d: %s", res.StatusCode, string(body)))
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, newErr("USERINFO_FAILED", err.Error())
	}
	return out, nil
}

// AuthzCheckInput — one request to /authz/check.
type AuthzCheckInput struct {
	Principal struct {
		Type        string `json:"type"` // "user" | "group" | "role" | "service_account"
		ID          string `json:"id"`
		AccountID   string `json:"accountId"`
		MfaVerified bool   `json:"mfaVerified,omitempty"`
	} `json:"principal"`
	Action   string         `json:"action"`
	Resource string         `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// AuthzCheckResult — what Huudis returns.
type AuthzCheckResult struct {
	Decision   string `json:"decision"` // "Allow" | "Deny" | "ImplicitDeny"
	Allow      bool   `json:"allow"`
	Reason     string `json:"reason,omitempty"`
	MatchedSid string `json:"matchedSid,omitempty"`
}

// AuthzCheck calls /authz/check. The access token must belong to a
// principal with iam:AuthzCheck permission.
func (c *Client) AuthzCheck(ctx context.Context, accessToken string, in AuthzCheckInput) (*AuthzCheckResult, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, newErr("SERIALIZE_FAILED", err.Error())
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		c.APIBase+"/api/v1/authz/check", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, newErr("AUTHZ_CHECK_FAILED", err.Error())
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		return nil, newErr("AUTHZ_CHECK_FAILED", fmt.Sprintf("HTTP %d: %s", res.StatusCode, string(raw)))
	}
	var wrap struct {
		Data *AuthzCheckResult `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, newErr("AUTHZ_CHECK_FAILED", err.Error())
	}
	if wrap.Data == nil {
		return nil, newErr("AUTHZ_CHECK_FAILED", "response missing data envelope")
	}
	return wrap.Data, nil
}

// ─── Internal ──────────────────────────────────────────────────────────

func (c *Client) tokenEndpoint(ctx context.Context, body url.Values) (*TokenResponse, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		c.Issuer+"/api/v1/oidc/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, newErr("TOKEN_ENDPOINT_FAILED", err.Error())
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		var errBody struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(raw, &errBody)
		msg := errBody.ErrorDescription
		if msg == "" {
			msg = errBody.Error
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", res.StatusCode)
		}
		return nil, newErr("TOKEN_ENDPOINT_FAILED", msg)
	}
	var out TokenResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, newErr("TOKEN_ENDPOINT_FAILED", err.Error())
	}
	return &out, nil
}
