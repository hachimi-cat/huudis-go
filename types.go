package huudis

// This file holds all the response/request types for Huudis admin
// resources. Field tags match the JSON wire shape exactly — the Node
// SDK is the canonical reference for naming.

// ─── Common ────────────────────────────────────────────────────────────

// ListPage is the cursor-paginated envelope used by some list endpoints
// (currently IAM users + end-users).
type ListPage[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// ─── IAM ───────────────────────────────────────────────────────────────

type IamUser struct {
	ID            string `json:"id"`
	AccountID     string `json:"accountId"`
	Email         string `json:"email"`
	Name          string `json:"name,omitempty"`
	EmailVerified bool   `json:"emailVerified"`
	MfaEnrolled   bool   `json:"mfaEnrolled"`
	Disabled      bool   `json:"disabled"`
	CreatedAt     string `json:"createdAt"`
}

type IamUserInvite struct {
	ID        string `json:"id"`
	AccountID string `json:"accountId"`
	Email     string `json:"email"`
	Role      string `json:"role,omitempty"`
	Status    string `json:"status"` // "pending" | "accepted" | "cancelled" | "expired"
	ExpiresAt string `json:"expiresAt"`
	CreatedAt string `json:"createdAt"`
}

type IamAccessKey struct {
	ID              string `json:"id"`
	AccountID       string `json:"accountId"`
	PrincipalArn    string `json:"principalArn"`
	Description     string `json:"description,omitempty"`
	Status          string `json:"status"` // "active" | "revoked"
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
	CreatedAt       string `json:"createdAt"`
	LastUsedAt      string `json:"lastUsedAt,omitempty"`
}

type IamGroup struct {
	ID          string `json:"id"`
	AccountID   string `json:"accountId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MemberCount int    `json:"memberCount,omitempty"`
	CreatedAt   string `json:"createdAt"`
}

type IamRole struct {
	ID          string         `json:"id"`
	AccountID   string         `json:"accountId"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	TrustPolicy map[string]any `json:"trustPolicy,omitempty"`
	CreatedAt   string         `json:"createdAt"`
}

type IamServiceAccount struct {
	ID          string `json:"id"`
	AccountID   string `json:"accountId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"createdAt"`
}

type IamPolicy struct {
	ID          string         `json:"id"`
	AccountID   string         `json:"accountId"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Document    map[string]any `json:"document"`
	BuiltIn     bool           `json:"builtIn,omitempty"`
	CreatedAt   string         `json:"createdAt"`
	UpdatedAt   string         `json:"updatedAt"`
}

type IamPolicyAttachment struct {
	ID           string `json:"id"`
	AccountID    string `json:"accountId"`
	PolicyID     string `json:"policyId"`
	PrincipalArn string `json:"principalArn"`
	CreatedAt    string `json:"createdAt"`
}

// ─── Identity providers ────────────────────────────────────────────────

type IdentityProvider struct {
	ID        string         `json:"id"`
	AccountID string         `json:"accountId"`
	Kind      string         `json:"kind"` // "oidc" | "saml" | "social"
	Name      string         `json:"name"`
	Enabled   bool           `json:"enabled"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt string         `json:"createdAt"`
}

// ─── Assumed sessions ──────────────────────────────────────────────────

type AssumedSession struct {
	ID        string `json:"id"`
	AccountID string `json:"accountId"`
	CallerArn string `json:"callerArn"`
	RoleArn   string `json:"roleArn"`
	ExpiresAt string `json:"expiresAt"`
	Active    bool   `json:"active"`
	CreatedAt string `json:"createdAt"`
}

// ─── Workspaces ────────────────────────────────────────────────────────

type Workspace struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug,omitempty"`
	OwnerID   string `json:"ownerId"`
	Role      string `json:"role,omitempty"` // "owner" | "admin" | "member" | "viewer"
	CreatedAt string `json:"createdAt"`
}

// ─── End-users (ops) ───────────────────────────────────────────────────

type EndUser struct {
	ID            string `json:"id"`
	AccountID     string `json:"accountId"`
	Email         string `json:"email"`
	Name          string `json:"name,omitempty"`
	EmailVerified bool   `json:"emailVerified"`
	Disabled      bool   `json:"disabled"`
	CreatedAt     string `json:"createdAt"`
	LastLoginAt   string `json:"lastLoginAt,omitempty"`
}

type ImpersonationSession struct {
	SessionID   string `json:"sessionId"`
	AccessToken string `json:"accessToken"`
	ExpiresAt   string `json:"expiresAt"`
}

// ─── MFA ───────────────────────────────────────────────────────────────

type MfaDevice struct {
	ID         string `json:"id"`
	Type       string `json:"type"` // "totp" | "webauthn" | "sms"
	Label      string `json:"label,omitempty"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
}

type MfaEnrollment struct {
	DeviceID   string `json:"deviceId"`
	Secret     string `json:"secret,omitempty"`
	OtpAuthURL string `json:"otpAuthUrl,omitempty"`
	QrCodePng  string `json:"qrCodePng,omitempty"`
}

// ─── OIDC clients ──────────────────────────────────────────────────────

type OidcClient struct {
	ID           string   `json:"id"`
	AccountID    string   `json:"accountId"`
	Name         string   `json:"name"`
	RedirectUris []string `json:"redirectUris"`
	Scopes       []string `json:"scopes"`
	ClientSecret string   `json:"clientSecret,omitempty"`
	Confidential bool     `json:"confidential"`
	CreatedAt    string   `json:"createdAt"`
	UpdatedAt    string   `json:"updatedAt"`
}

// ─── Connected apps (consents) ─────────────────────────────────────────

type ConnectedApp struct {
	ID          string   `json:"id"`
	ClientID    string   `json:"clientId"`
	ClientName  string   `json:"clientName"`
	Scopes      []string `json:"scopes"`
	ConsentedAt string   `json:"consentedAt"`
	LastUsedAt  string   `json:"lastUsedAt,omitempty"`
}

// ─── Services (Forjio product opt-in) ──────────────────────────────────

type ServiceStatus struct {
	Service   string `json:"service"`
	Enabled   bool   `json:"enabled"`
	EnabledAt string `json:"enabledAt,omitempty"`
}

// ─── Webhook subscriptions ─────────────────────────────────────────────

type WebhookSubscription struct {
	ID          string   `json:"id"`
	AccountID   string   `json:"accountId"`
	URL         string   `json:"url"`
	Events      []string `json:"events"`
	Description string   `json:"description,omitempty"`
	Active      bool     `json:"active"`
	Secret      string   `json:"secret,omitempty"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt"`
}

type WebhookDelivery struct {
	ID             string `json:"id"`
	SubscriptionID string `json:"subscriptionId"`
	EventID        string `json:"eventId"`
	EventType      string `json:"eventType"`
	Status         string `json:"status"` // "pending" | "success" | "failed"
	HttpStatus     int    `json:"httpStatus,omitempty"`
	ResponseBody   string `json:"responseBody,omitempty"`
	AttemptCount   int    `json:"attemptCount"`
	LastAttemptAt  string `json:"lastAttemptAt,omitempty"`
	CreatedAt      string `json:"createdAt"`
}

type WebhookEventCatalogEntry struct {
	Type          string         `json:"type"`
	Description   string         `json:"description,omitempty"`
	PayloadSchema map[string]any `json:"payloadSchema,omitempty"`
}

// ─── Billing ───────────────────────────────────────────────────────────

type BillingPlan struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Amount   int64    `json:"amount"`
	Currency string   `json:"currency"`
	Interval string   `json:"interval"` // "month" | "year"
	Features []string `json:"features,omitempty"`
}

type BillingSubscription struct {
	ID               string `json:"id"`
	PlanID           string `json:"planId"`
	Status           string `json:"status"`
	CurrentPeriodEnd string `json:"currentPeriodEnd"`
}

type BillingUsage struct {
	Identities        int64  `json:"identities"`
	AuthzChecks       int64  `json:"authzChecks"`
	WebhookDeliveries int64  `json:"webhookDeliveries"`
	AsOf              string `json:"asOf"`
}

type BillingInvoice struct {
	ID               string `json:"id"`
	Amount           int64  `json:"amount"`
	Currency         string `json:"currency"`
	Status           string `json:"status"`
	HostedInvoiceURL string `json:"hostedInvoiceUrl,omitempty"`
	CreatedAt        string `json:"createdAt"`
}

type CheckoutSession struct {
	URL       string `json:"url"`
	SessionID string `json:"sessionId"`
}

type BillingSummary struct {
	Subscription *BillingSubscription `json:"subscription,omitempty"`
	Usage        BillingUsage         `json:"usage"`
}

// ─── Account ───────────────────────────────────────────────────────────

type AccountProfile struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
	Name          string `json:"name,omitempty"`
	Locale        string `json:"locale,omitempty"`
	MfaEnrolled   bool   `json:"mfaEnrolled"`
	CreatedAt     string `json:"createdAt"`
}

type BrowserSession struct {
	ID         string `json:"id"`
	UserAgent  string `json:"userAgent,omitempty"`
	IPAddress  string `json:"ipAddress,omitempty"`
	CreatedAt  string `json:"createdAt"`
	LastSeenAt string `json:"lastSeenAt"`
	Current    bool   `json:"current,omitempty"`
}

type LinkedAccount struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
	Email    string `json:"email,omitempty"`
	LinkedAt string `json:"linkedAt"`
}

type AuditEntry struct {
	ID        string         `json:"id"`
	AccountID string         `json:"accountId"`
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource,omitempty"`
	Outcome   string         `json:"outcome"` // "success" | "failure"
	Details   map[string]any `json:"details,omitempty"`
	Timestamp string         `json:"timestamp"`
}

// ─── Authz extras ──────────────────────────────────────────────────────

type AssumeRoleResult struct {
	AccessToken string `json:"accessToken"`
	ExpiresAt   string `json:"expiresAt"`
	SessionID   string `json:"sessionId"`
}

type WhoamiResult struct {
	Principal string   `json:"principal"`
	AccountID string   `json:"accountId"`
	Scopes    []string `json:"scopes"`
}

// ─── Misc helpers ──────────────────────────────────────────────────────

// PasswordResetResult is the response from /iam/users/{id}/reset-password.
type PasswordResetResult struct {
	Sent bool `json:"sent"`
}

// SwitchWorkspaceResult is the response from POST /workspaces/{id}/switch.
type SwitchWorkspaceResult struct {
	AccessToken string `json:"accessToken"`
}

// RotateSecretResult is the response from rotate-secret endpoints.
type RotateSecretResult struct {
	Secret       string `json:"secret,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
}

// MfaVerifyLoginResult is the response from MFA verify-login.
type MfaVerifyLoginResult struct {
	AccessToken string `json:"accessToken"`
}

// SessionRevokeAllResult is the response from POST /account/sessions/revoke-all.
type SessionRevokeAllResult struct {
	Revoked int `json:"revoked"`
}

// ChangeEmailResult is the response from POST /account/email-change.
type ChangeEmailResult struct {
	PendingVerification bool `json:"pendingVerification"`
}
