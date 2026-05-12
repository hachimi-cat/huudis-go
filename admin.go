package huudis

import (
	"context"
	"net/http"
)

// This file wires every Huudis admin resource to the Client as a
// dedicated namespace (e.g. c.IAM.ListUsers, c.Workspaces.Switch). Each
// method takes a context, a typed request, and a RequestAuth for the
// per-call bearer override. The shape mirrors @forjio/sdk's
// HuudisClient.iam / .workspaces / etc.

// ─── IAM ───────────────────────────────────────────────────────────────

// IamResource is the namespace for /api/v1/iam/*.
type IamResource struct{ c *Client }

// ListUsersParams scopes IAM user listings.
type ListUsersParams struct {
	Limit  int
	Cursor string
}

func (r *IamResource) ListUsers(ctx context.Context, p ListUsersParams, auth RequestAuth) (*ListPage[IamUser], error) {
	out := &ListPage[IamUser]{}
	q := buildQuery(map[string]any{"limit": p.Limit, "cursor": p.Cursor})
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/users",
		requestOptions{authToken: auth.AuthToken, query: q}, out)
	return out, err
}

// CreateUserInput is the payload for POST /iam/users.
type CreateUserInput struct {
	Email    string `json:"email"`
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role,omitempty"`
}

func (r *IamResource) CreateUser(ctx context.Context, in CreateUserInput, auth RequestAuth) (*IamUser, error) {
	out := &IamUser{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/users",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *IamResource) UpdateUser(ctx context.Context, id string, patch map[string]any, auth RequestAuth) (*IamUser, error) {
	out := &IamUser{}
	err := r.c.doRequest(ctx, http.MethodPatch, "/api/v1/iam/users/"+id,
		requestOptions{authToken: auth.AuthToken, body: patch}, out)
	return out, err
}

func (r *IamResource) DeleteUser(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/iam/users/"+id,
		requestOptions{authToken: auth.AuthToken}, nil)
}

func (r *IamResource) ResetUserPassword(ctx context.Context, id string, auth RequestAuth) (*PasswordResetResult, error) {
	out := &PasswordResetResult{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/users/"+id+"/reset-password",
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

// Invites
func (r *IamResource) ListInvites(ctx context.Context, auth RequestAuth) ([]IamUserInvite, error) {
	var out []IamUserInvite
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/invites",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

// SendInviteInput is the payload for POST /iam/invites.
type SendInviteInput struct {
	Email string `json:"email"`
	Role  string `json:"role,omitempty"`
}

func (r *IamResource) SendInvite(ctx context.Context, in SendInviteInput, auth RequestAuth) (*IamUserInvite, error) {
	out := &IamUserInvite{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/invites",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *IamResource) CancelInvite(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/iam/invites/"+id,
		requestOptions{authToken: auth.AuthToken}, nil)
}

// Access keys
type ListAccessKeysParams struct {
	PrincipalArn string
}

func (r *IamResource) ListAccessKeys(ctx context.Context, p ListAccessKeysParams, auth RequestAuth) ([]IamAccessKey, error) {
	var out []IamAccessKey
	q := buildQuery(map[string]any{"principalArn": p.PrincipalArn})
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/access-keys",
		requestOptions{authToken: auth.AuthToken, query: q}, &out)
	return out, err
}

type CreateAccessKeyInput struct {
	PrincipalArn string `json:"principalArn"`
	Description  string `json:"description,omitempty"`
}

func (r *IamResource) CreateAccessKey(ctx context.Context, in CreateAccessKeyInput, auth RequestAuth) (*IamAccessKey, error) {
	out := &IamAccessKey{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/access-keys",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *IamResource) RevokeAccessKey(ctx context.Context, id string, auth RequestAuth) (*IamAccessKey, error) {
	out := &IamAccessKey{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/access-keys/"+id+"/revoke",
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

func (r *IamResource) DeleteAccessKey(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/iam/access-keys/"+id,
		requestOptions{authToken: auth.AuthToken}, nil)
}

// Groups
func (r *IamResource) ListGroups(ctx context.Context, auth RequestAuth) ([]IamGroup, error) {
	var out []IamGroup
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/groups",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

func (r *IamResource) GetGroup(ctx context.Context, id string, auth RequestAuth) (*IamGroup, error) {
	out := &IamGroup{}
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/groups/"+id,
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

type CreateGroupInput struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (r *IamResource) CreateGroup(ctx context.Context, in CreateGroupInput, auth RequestAuth) (*IamGroup, error) {
	out := &IamGroup{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/groups",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *IamResource) DeleteGroup(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/iam/groups/"+id,
		requestOptions{authToken: auth.AuthToken}, nil)
}

func (r *IamResource) AddGroupMember(ctx context.Context, groupID, userID string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/groups/"+groupID+"/members",
		requestOptions{authToken: auth.AuthToken, body: map[string]any{"userId": userID}}, nil)
}

func (r *IamResource) RemoveGroupMember(ctx context.Context, groupID, userID string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/iam/groups/"+groupID+"/members/"+userID,
		requestOptions{authToken: auth.AuthToken}, nil)
}

// Roles
func (r *IamResource) ListRoles(ctx context.Context, auth RequestAuth) ([]IamRole, error) {
	var out []IamRole
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/roles",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

func (r *IamResource) GetRole(ctx context.Context, id string, auth RequestAuth) (*IamRole, error) {
	out := &IamRole{}
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/roles/"+id,
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

type CreateRoleInput struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	TrustPolicy map[string]any `json:"trustPolicy"`
}

func (r *IamResource) CreateRole(ctx context.Context, in CreateRoleInput, auth RequestAuth) (*IamRole, error) {
	out := &IamRole{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/roles",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *IamResource) DeleteRole(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/iam/roles/"+id,
		requestOptions{authToken: auth.AuthToken}, nil)
}

// Service accounts
func (r *IamResource) ListServiceAccounts(ctx context.Context, auth RequestAuth) ([]IamServiceAccount, error) {
	var out []IamServiceAccount
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/service-accounts",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

func (r *IamResource) GetServiceAccount(ctx context.Context, id string, auth RequestAuth) (*IamServiceAccount, error) {
	out := &IamServiceAccount{}
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/service-accounts/"+id,
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

type CreateServiceAccountInput struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (r *IamResource) CreateServiceAccount(ctx context.Context, in CreateServiceAccountInput, auth RequestAuth) (*IamServiceAccount, error) {
	out := &IamServiceAccount{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/service-accounts",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *IamResource) DeleteServiceAccount(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/iam/service-accounts/"+id,
		requestOptions{authToken: auth.AuthToken}, nil)
}

// Policies
type ListPoliciesParams struct {
	Kind string // "custom" | "canned"
}

func (r *IamResource) ListPolicies(ctx context.Context, p ListPoliciesParams, auth RequestAuth) ([]IamPolicy, error) {
	var out []IamPolicy
	q := buildQuery(map[string]any{"kind": p.Kind})
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/policies",
		requestOptions{authToken: auth.AuthToken, query: q}, &out)
	return out, err
}

func (r *IamResource) GetPolicy(ctx context.Context, id string, auth RequestAuth) (*IamPolicy, error) {
	out := &IamPolicy{}
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/policies/"+id,
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

type CreatePolicyInput struct {
	Name        string         `json:"name"`
	Document    map[string]any `json:"document"`
	Description string         `json:"description,omitempty"`
}

func (r *IamResource) CreatePolicy(ctx context.Context, in CreatePolicyInput, auth RequestAuth) (*IamPolicy, error) {
	out := &IamPolicy{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/policies",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *IamResource) UpdatePolicy(ctx context.Context, id string, patch map[string]any, auth RequestAuth) (*IamPolicy, error) {
	out := &IamPolicy{}
	err := r.c.doRequest(ctx, http.MethodPatch, "/api/v1/iam/policies/"+id,
		requestOptions{authToken: auth.AuthToken, body: patch}, out)
	return out, err
}

func (r *IamResource) DeletePolicy(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/iam/policies/"+id,
		requestOptions{authToken: auth.AuthToken}, nil)
}

// Policy attachments
type ListPolicyAttachmentsParams struct {
	PolicyID     string
	PrincipalArn string
}

func (r *IamResource) ListPolicyAttachments(ctx context.Context, p ListPolicyAttachmentsParams, auth RequestAuth) ([]IamPolicyAttachment, error) {
	var out []IamPolicyAttachment
	q := buildQuery(map[string]any{"policyId": p.PolicyID, "principalArn": p.PrincipalArn})
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/policy-attachments",
		requestOptions{authToken: auth.AuthToken, query: q}, &out)
	return out, err
}

type AttachPolicyInput struct {
	PolicyID     string `json:"policyId"`
	PrincipalArn string `json:"principalArn"`
}

func (r *IamResource) AttachPolicy(ctx context.Context, in AttachPolicyInput, auth RequestAuth) (*IamPolicyAttachment, error) {
	out := &IamPolicyAttachment{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/policy-attachments",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *IamResource) DetachPolicy(ctx context.Context, attachmentID string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/iam/policy-attachments/"+attachmentID,
		requestOptions{authToken: auth.AuthToken}, nil)
}

// ─── Identity providers ────────────────────────────────────────────────

type IdentityProvidersResource struct{ c *Client }

func (r *IdentityProvidersResource) List(ctx context.Context, auth RequestAuth) ([]IdentityProvider, error) {
	var out []IdentityProvider
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/identity-providers",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

type CreateIdentityProviderInput struct {
	Kind     string         `json:"kind"` // "oidc" | "saml" | "social"
	Name     string         `json:"name"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

func (r *IdentityProvidersResource) Create(ctx context.Context, in CreateIdentityProviderInput, auth RequestAuth) (*IdentityProvider, error) {
	out := &IdentityProvider{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/identity-providers",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *IdentityProvidersResource) Update(ctx context.Context, id string, patch map[string]any, auth RequestAuth) (*IdentityProvider, error) {
	out := &IdentityProvider{}
	err := r.c.doRequest(ctx, http.MethodPatch, "/api/v1/iam/identity-providers/"+id,
		requestOptions{authToken: auth.AuthToken, body: patch}, out)
	return out, err
}

func (r *IdentityProvidersResource) Delete(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/iam/identity-providers/"+id,
		requestOptions{authToken: auth.AuthToken}, nil)
}

// ─── Assumed sessions ──────────────────────────────────────────────────

type AssumedSessionsResource struct{ c *Client }

type ListAssumedSessionsParams struct {
	ActiveOnly *bool
}

func (r *AssumedSessionsResource) List(ctx context.Context, p ListAssumedSessionsParams, auth RequestAuth) ([]AssumedSession, error) {
	var out []AssumedSession
	q := buildQuery(map[string]any{"activeOnly": p.ActiveOnly})
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/iam/assumed-sessions",
		requestOptions{authToken: auth.AuthToken, query: q}, &out)
	return out, err
}

func (r *AssumedSessionsResource) Revoke(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodPost, "/api/v1/iam/assumed-sessions/"+id+"/revoke",
		requestOptions{authToken: auth.AuthToken}, nil)
}

// ─── Authz ─────────────────────────────────────────────────────────────

type AuthzResource struct{ c *Client }

// Check is the namespace version of the legacy client.AuthzCheck helper.
// Identical wire shape — uses the same envelope unwrap as every other
// resource so callers get error.Code branching for free.
func (r *AuthzResource) Check(ctx context.Context, in AuthzCheckInput, auth RequestAuth) (*AuthzCheckResult, error) {
	out := &AuthzCheckResult{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/authz/check",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

type AssumeRoleInput struct {
	RoleArn         string `json:"roleArn"`
	SessionName     string `json:"sessionName,omitempty"`
	DurationSeconds int    `json:"durationSeconds,omitempty"`
}

func (r *AuthzResource) AssumeRole(ctx context.Context, in AssumeRoleInput, auth RequestAuth) (*AssumeRoleResult, error) {
	out := &AssumeRoleResult{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/authz/assume-role",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *AuthzResource) Whoami(ctx context.Context, auth RequestAuth) (*WhoamiResult, error) {
	out := &WhoamiResult{}
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/authz/whoami",
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

// ─── Workspaces ────────────────────────────────────────────────────────

type WorkspacesResource struct{ c *Client }

func (r *WorkspacesResource) List(ctx context.Context, auth RequestAuth) ([]Workspace, error) {
	var out []Workspace
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/workspaces",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

type CreateWorkspaceInput struct {
	Name string `json:"name"`
	Slug string `json:"slug,omitempty"`
}

func (r *WorkspacesResource) Create(ctx context.Context, in CreateWorkspaceInput, auth RequestAuth) (*Workspace, error) {
	out := &Workspace{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/account/workspaces",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *WorkspacesResource) Update(ctx context.Context, id string, patch map[string]any, auth RequestAuth) (*Workspace, error) {
	out := &Workspace{}
	err := r.c.doRequest(ctx, http.MethodPatch, "/api/v1/account/workspaces/"+id,
		requestOptions{authToken: auth.AuthToken, body: patch}, out)
	return out, err
}

func (r *WorkspacesResource) Switch(ctx context.Context, id string, auth RequestAuth) (*SwitchWorkspaceResult, error) {
	out := &SwitchWorkspaceResult{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/account/workspaces/"+id+"/switch",
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

// ─── End-users (ops) ───────────────────────────────────────────────────

type EndUsersResource struct{ c *Client }

type ListEndUsersParams struct {
	Limit  int
	Cursor string
	Search string
}

func (r *EndUsersResource) List(ctx context.Context, p ListEndUsersParams, auth RequestAuth) (*ListPage[EndUser], error) {
	out := &ListPage[EndUser]{}
	q := buildQuery(map[string]any{"limit": p.Limit, "cursor": p.Cursor, "search": p.Search})
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/ops/end-users",
		requestOptions{authToken: auth.AuthToken, query: q}, out)
	return out, err
}

func (r *EndUsersResource) Get(ctx context.Context, id string, auth RequestAuth) (*EndUser, error) {
	out := &EndUser{}
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/ops/end-users/"+id,
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

func (r *EndUsersResource) Revoke(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodPost, "/api/v1/ops/end-users/"+id+"/revoke",
		requestOptions{authToken: auth.AuthToken}, nil)
}

func (r *EndUsersResource) SendPasswordReset(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodPost, "/api/v1/ops/end-users/"+id+"/send-password-reset",
		requestOptions{authToken: auth.AuthToken}, nil)
}

func (r *EndUsersResource) VerifyEmail(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodPost, "/api/v1/ops/end-users/"+id+"/verify-email",
		requestOptions{authToken: auth.AuthToken}, nil)
}

// ImpersonateInput optionally carries a reason that ops records in the
// audit log.
type ImpersonateInput struct {
	Reason string `json:"reason,omitempty"`
}

func (r *EndUsersResource) Impersonate(ctx context.Context, id string, in *ImpersonateInput, auth RequestAuth) (*ImpersonationSession, error) {
	out := &ImpersonationSession{}
	var body any
	if in != nil {
		body = in
	}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/ops/end-users/"+id+"/impersonate",
		requestOptions{authToken: auth.AuthToken, body: body}, out)
	return out, err
}

func (r *EndUsersResource) StopImpersonation(ctx context.Context, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodPost, "/api/v1/ops/end-users/stop-impersonation",
		requestOptions{authToken: auth.AuthToken}, nil)
}

type DisableEndUserInput struct {
	Reason string `json:"reason,omitempty"`
}

func (r *EndUsersResource) Disable(ctx context.Context, id string, in *DisableEndUserInput, auth RequestAuth) error {
	var body any
	if in != nil {
		body = in
	}
	return r.c.doRequest(ctx, http.MethodPost, "/api/v1/ops/end-users/"+id+"/disable",
		requestOptions{authToken: auth.AuthToken, body: body}, nil)
}

func (r *EndUsersResource) Enable(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodPost, "/api/v1/ops/end-users/"+id+"/enable",
		requestOptions{authToken: auth.AuthToken}, nil)
}

// ─── MFA ───────────────────────────────────────────────────────────────

type MfaResource struct{ c *Client }

type MfaEnrollInput struct {
	Type  string `json:"type"` // "totp" | "webauthn" | "sms"
	Label string `json:"label,omitempty"`
}

func (r *MfaResource) Enroll(ctx context.Context, in MfaEnrollInput, auth RequestAuth) (*MfaEnrollment, error) {
	out := &MfaEnrollment{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/mfa/enroll",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

type MfaVerifyEnrollmentInput struct {
	DeviceID string `json:"deviceId"`
	Code     string `json:"code"`
}

func (r *MfaResource) VerifyEnrollment(ctx context.Context, in MfaVerifyEnrollmentInput, auth RequestAuth) (*MfaDevice, error) {
	out := &MfaDevice{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/mfa/verify-enrollment",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

type MfaVerifyLoginInput struct {
	Code string `json:"code"`
}

func (r *MfaResource) VerifyLogin(ctx context.Context, in MfaVerifyLoginInput, auth RequestAuth) (*MfaVerifyLoginResult, error) {
	out := &MfaVerifyLoginResult{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/mfa/verify-login",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *MfaResource) ListDevices(ctx context.Context, auth RequestAuth) ([]MfaDevice, error) {
	var out []MfaDevice
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/mfa/devices",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

func (r *MfaResource) DeleteDevice(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/mfa/devices/"+id,
		requestOptions{authToken: auth.AuthToken}, nil)
}

// ─── OIDC clients ──────────────────────────────────────────────────────

type OidcClientsResource struct{ c *Client }

func (r *OidcClientsResource) List(ctx context.Context, auth RequestAuth) ([]OidcClient, error) {
	var out []OidcClient
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/oidc/clients",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

type CreateOidcClientInput struct {
	Name         string   `json:"name"`
	RedirectUris []string `json:"redirectUris"`
	Scopes       []string `json:"scopes,omitempty"`
	Confidential *bool    `json:"confidential,omitempty"`
}

func (r *OidcClientsResource) Create(ctx context.Context, in CreateOidcClientInput, auth RequestAuth) (*OidcClient, error) {
	out := &OidcClient{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/oidc/clients",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *OidcClientsResource) Update(ctx context.Context, id string, patch map[string]any, auth RequestAuth) (*OidcClient, error) {
	out := &OidcClient{}
	err := r.c.doRequest(ctx, http.MethodPatch, "/api/v1/oidc/clients/"+id,
		requestOptions{authToken: auth.AuthToken, body: patch}, out)
	return out, err
}

func (r *OidcClientsResource) RotateSecret(ctx context.Context, id string, auth RequestAuth) (*RotateSecretResult, error) {
	out := &RotateSecretResult{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/oidc/clients/"+id+"/rotate-secret",
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

func (r *OidcClientsResource) Delete(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/oidc/clients/"+id,
		requestOptions{authToken: auth.AuthToken}, nil)
}

// ─── Connected apps ────────────────────────────────────────────────────

type ConnectedAppsResource struct{ c *Client }

func (r *ConnectedAppsResource) List(ctx context.Context, auth RequestAuth) ([]ConnectedApp, error) {
	var out []ConnectedApp
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/connected-apps",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

func (r *ConnectedAppsResource) Revoke(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/account/connected-apps/"+id,
		requestOptions{authToken: auth.AuthToken}, nil)
}

// ─── Services ──────────────────────────────────────────────────────────

type ServicesResource struct{ c *Client }

func (r *ServicesResource) List(ctx context.Context, auth RequestAuth) ([]ServiceStatus, error) {
	var out []ServiceStatus
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/services",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

type ServiceToggleInput struct {
	Service string `json:"service"`
}

func (r *ServicesResource) Enable(ctx context.Context, in ServiceToggleInput, auth RequestAuth) (*ServiceStatus, error) {
	out := &ServiceStatus{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/account/services/enable",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *ServicesResource) Disable(ctx context.Context, in ServiceToggleInput, auth RequestAuth) (*ServiceStatus, error) {
	out := &ServiceStatus{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/account/services/disable",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

// ─── Webhook subscriptions ─────────────────────────────────────────────

type WebhookSubscriptionsResource struct{ c *Client }

func (r *WebhookSubscriptionsResource) List(ctx context.Context, auth RequestAuth) ([]WebhookSubscription, error) {
	var out []WebhookSubscription
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/webhook-subscriptions",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

type CreateWebhookSubscriptionInput struct {
	URL         string   `json:"url"`
	Events      []string `json:"events"`
	Description string   `json:"description,omitempty"`
}

func (r *WebhookSubscriptionsResource) Create(ctx context.Context, in CreateWebhookSubscriptionInput, auth RequestAuth) (*WebhookSubscription, error) {
	out := &WebhookSubscription{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/account/webhook-subscriptions",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *WebhookSubscriptionsResource) Get(ctx context.Context, id string, auth RequestAuth) (*WebhookSubscription, error) {
	out := &WebhookSubscription{}
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/webhook-subscriptions/"+id,
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

func (r *WebhookSubscriptionsResource) Update(ctx context.Context, id string, patch map[string]any, auth RequestAuth) (*WebhookSubscription, error) {
	out := &WebhookSubscription{}
	err := r.c.doRequest(ctx, http.MethodPatch, "/api/v1/account/webhook-subscriptions/"+id,
		requestOptions{authToken: auth.AuthToken, body: patch}, out)
	return out, err
}

func (r *WebhookSubscriptionsResource) Delete(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/account/webhook-subscriptions/"+id,
		requestOptions{authToken: auth.AuthToken}, nil)
}

func (r *WebhookSubscriptionsResource) RotateSecret(ctx context.Context, id string, auth RequestAuth) (*RotateSecretResult, error) {
	out := &RotateSecretResult{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/account/webhook-subscriptions/"+id+"/rotate-secret",
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

type ListWebhookDeliveriesParams struct {
	Status string
	Limit  int
}

func (r *WebhookSubscriptionsResource) ListDeliveries(ctx context.Context, id string, p ListWebhookDeliveriesParams, auth RequestAuth) ([]WebhookDelivery, error) {
	var out []WebhookDelivery
	q := buildQuery(map[string]any{"status": p.Status, "limit": p.Limit})
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/webhook-subscriptions/"+id+"/deliveries",
		requestOptions{authToken: auth.AuthToken, query: q}, &out)
	return out, err
}

func (r *WebhookSubscriptionsResource) ReplayDelivery(ctx context.Context, deliveryID string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodPost,
		"/api/v1/account/webhook-subscriptions/deliveries/"+deliveryID+"/replay",
		requestOptions{authToken: auth.AuthToken}, nil)
}

func (r *WebhookSubscriptionsResource) EventsCatalog(ctx context.Context, auth RequestAuth) ([]WebhookEventCatalogEntry, error) {
	var out []WebhookEventCatalogEntry
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/webhook-subscriptions/events/catalog",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

// ─── Billing ───────────────────────────────────────────────────────────

type BillingResource struct{ c *Client }

func (r *BillingResource) Summary(ctx context.Context, auth RequestAuth) (*BillingSummary, error) {
	out := &BillingSummary{}
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/billing",
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

func (r *BillingResource) Plans(ctx context.Context, auth RequestAuth) ([]BillingPlan, error) {
	var out []BillingPlan
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/billing/plans",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

func (r *BillingResource) Usage(ctx context.Context, auth RequestAuth) (*BillingUsage, error) {
	out := &BillingUsage{}
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/billing/usage",
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

type ListInvoicesParams struct {
	Limit int
}

func (r *BillingResource) Invoices(ctx context.Context, p ListInvoicesParams, auth RequestAuth) ([]BillingInvoice, error) {
	var out []BillingInvoice
	q := buildQuery(map[string]any{"limit": p.Limit})
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/billing/invoices",
		requestOptions{authToken: auth.AuthToken, query: q}, &out)
	return out, err
}

type BillingCheckoutInput struct {
	PlanID     string `json:"planId"`
	SuccessURL string `json:"successUrl,omitempty"`
	CancelURL  string `json:"cancelUrl,omitempty"`
}

func (r *BillingResource) Checkout(ctx context.Context, in BillingCheckoutInput, auth RequestAuth) (*CheckoutSession, error) {
	out := &CheckoutSession{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/account/billing/checkout",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

func (r *BillingResource) Cancel(ctx context.Context, auth RequestAuth) (*BillingSubscription, error) {
	out := &BillingSubscription{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/account/billing/cancel",
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

// ─── Account ───────────────────────────────────────────────────────────

type AccountResource struct {
	c *Client

	// Nested namespaces.
	Sessions *AccountSessionsResource
	Linked   *AccountLinkedResource
}

func (r *AccountResource) Get(ctx context.Context, auth RequestAuth) (*AccountProfile, error) {
	out := &AccountProfile{}
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account",
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

func (r *AccountResource) Update(ctx context.Context, patch map[string]any, auth RequestAuth) (*AccountProfile, error) {
	out := &AccountProfile{}
	err := r.c.doRequest(ctx, http.MethodPatch, "/api/v1/account",
		requestOptions{authToken: auth.AuthToken, body: patch}, out)
	return out, err
}

type ChangeEmailInput struct {
	NewEmail string `json:"newEmail"`
	Password string `json:"password"`
}

func (r *AccountResource) ChangeEmail(ctx context.Context, in ChangeEmailInput, auth RequestAuth) (*ChangeEmailResult, error) {
	out := &ChangeEmailResult{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/account/email-change",
		requestOptions{authToken: auth.AuthToken, body: in}, out)
	return out, err
}

type ChangePasswordInput struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (r *AccountResource) ChangePassword(ctx context.Context, in ChangePasswordInput, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodPost, "/api/v1/account/password-change",
		requestOptions{authToken: auth.AuthToken, body: in}, nil)
}

type AuditParams struct {
	EventType string
	Since     string
	Limit     int
}

func (r *AccountResource) Audit(ctx context.Context, p AuditParams, auth RequestAuth) ([]AuditEntry, error) {
	var out []AuditEntry
	q := buildQuery(map[string]any{"eventType": p.EventType, "since": p.Since, "limit": p.Limit})
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/audit",
		requestOptions{authToken: auth.AuthToken, query: q}, &out)
	return out, err
}

// AccountSessionsResource — /api/v1/account/sessions
type AccountSessionsResource struct{ c *Client }

func (r *AccountSessionsResource) List(ctx context.Context, auth RequestAuth) ([]BrowserSession, error) {
	var out []BrowserSession
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/sessions",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

func (r *AccountSessionsResource) Revoke(ctx context.Context, id string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodPost, "/api/v1/account/sessions/"+id+"/revoke",
		requestOptions{authToken: auth.AuthToken}, nil)
}

func (r *AccountSessionsResource) RevokeAll(ctx context.Context, auth RequestAuth) (*SessionRevokeAllResult, error) {
	out := &SessionRevokeAllResult{}
	err := r.c.doRequest(ctx, http.MethodPost, "/api/v1/account/sessions/revoke-all",
		requestOptions{authToken: auth.AuthToken}, out)
	return out, err
}

// AccountLinkedResource — /api/v1/account/linked-accounts
type AccountLinkedResource struct{ c *Client }

func (r *AccountLinkedResource) List(ctx context.Context, auth RequestAuth) ([]LinkedAccount, error) {
	var out []LinkedAccount
	err := r.c.doRequest(ctx, http.MethodGet, "/api/v1/account/linked-accounts",
		requestOptions{authToken: auth.AuthToken}, &out)
	return out, err
}

func (r *AccountLinkedResource) Unlink(ctx context.Context, provider string, auth RequestAuth) error {
	return r.c.doRequest(ctx, http.MethodDelete, "/api/v1/account/linked-accounts/"+provider,
		requestOptions{authToken: auth.AuthToken}, nil)
}
