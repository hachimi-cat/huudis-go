package huudis

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ─── Test helpers ──────────────────────────────────────────────────────

// envelope helpers — backend always wraps success in {data,error:null,meta:{...}}
// and errors in {data:null,error:{code,message},meta:{...}}.
func writeData(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":  data,
		"error": nil,
		"meta":  map[string]any{"requestId": "req_test", "timestamp": time.Now().UTC().Format(time.RFC3339)},
	})
}

func writeErr(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":  nil,
		"error": map[string]any{"code": code, "message": message},
		"meta":  map[string]any{"requestId": "req_err", "timestamp": time.Now().UTC().Format(time.RFC3339)},
	})
}

type recordedReq struct {
	Method string
	Path   string
	Query  string
	Auth   string
	Body   string
}

// newTestClient stands up an httptest.Server and returns a Client wired to it
// plus a pointer-to-slice of recorded requests for assertions.
func newTestClient(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, rec *recordedReq)) (*Client, *[]recordedReq, *httptest.Server) {
	t.Helper()
	var recs []recordedReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		rec := recordedReq{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.RawQuery,
			Auth:   r.Header.Get("Authorization"),
			Body:   string(bodyBytes),
		}
		handler(w, r, &rec)
		recs = append(recs, rec)
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(ClientOptions{
		Issuer:   srv.URL,
		ClientID: "oc_test",
		APIBase:  srv.URL,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, &recs, srv
}

const testToken = "admin_test_token"

func wantBearer(t *testing.T, got string) {
	t.Helper()
	if got != "Bearer "+testToken {
		t.Fatalf("expected Authorization=Bearer %s, got %q", testToken, got)
	}
}

// ─── IAM: Users ────────────────────────────────────────────────────────

func TestIAM_ListUsers_HappyPath(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		wantBearer(t, rec.Auth)
		if r.URL.Path != "/api/v1/iam/users" {
			t.Fatalf("path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "50" {
			t.Fatalf("limit param: %q", r.URL.Query().Get("limit"))
		}
		if r.URL.Query().Get("cursor") != "abc" {
			t.Fatalf("cursor param: %q", r.URL.Query().Get("cursor"))
		}
		writeData(w, 200, map[string]any{
			"items":      []map[string]any{{"id": "usr_1", "accountId": "acc_x", "email": "a@b.com", "emailVerified": true, "mfaEnrolled": false, "disabled": false, "createdAt": "2026-01-01T00:00:00Z"}},
			"nextCursor": "next123",
		})
	})

	got, err := c.IAM.ListUsers(context.Background(), ListUsersParams{Limit: 50, Cursor: "abc"}, RequestAuth{AuthToken: testToken})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(got.Items) != 1 || got.Items[0].ID != "usr_1" {
		t.Fatalf("unexpected items: %+v", got)
	}
	if got.NextCursor != "next123" {
		t.Fatalf("nextCursor: %q", got.NextCursor)
	}
}

func TestIAM_ListUsers_Error(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		writeErr(w, 401, "UNAUTHORIZED", "missing or invalid token")
	})

	_, err := c.IAM.ListUsers(context.Background(), ListUsersParams{}, RequestAuth{AuthToken: "bad"})
	if err == nil {
		t.Fatal("expected error")
	}
	huudisErr, ok := err.(*Error)
	if !ok || huudisErr.Code != "UNAUTHORIZED" {
		t.Fatalf("expected *Error with code UNAUTHORIZED, got %v", err)
	}
}

func TestIAM_CreateUser(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		if r.Method != "POST" {
			t.Fatalf("method: %s", r.Method)
		}
		if !strings.Contains(rec.Body, `"email":"new@example.com"`) {
			t.Fatalf("body missing email: %s", rec.Body)
		}
		writeData(w, 201, map[string]any{"id": "usr_new", "accountId": "acc_x", "email": "new@example.com", "emailVerified": false, "mfaEnrolled": false, "disabled": false, "createdAt": "2026-01-01"})
	})

	got, err := c.IAM.CreateUser(context.Background(), CreateUserInput{Email: "new@example.com", Name: "Alice"}, RequestAuth{AuthToken: testToken})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if got.ID != "usr_new" {
		t.Fatalf("id: %q", got.ID)
	}
}

func TestIAM_UpdateUser(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		if r.Method != "PATCH" {
			t.Fatalf("method: %s", r.Method)
		}
		if rec.Path != "/api/v1/iam/users/usr_1" {
			t.Fatalf("path: %s", rec.Path)
		}
		writeData(w, 200, map[string]any{"id": "usr_1", "name": "Bob"})
	})
	got, err := c.IAM.UpdateUser(context.Background(), "usr_1", map[string]any{"name": "Bob"}, RequestAuth{AuthToken: testToken})
	if err != nil || got.ID != "usr_1" {
		t.Fatalf("UpdateUser: %v / %+v", err, got)
	}
}

func TestIAM_DeleteUser(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		if r.Method != "DELETE" {
			t.Fatalf("method: %s", r.Method)
		}
		w.WriteHeader(204)
	})
	if err := c.IAM.DeleteUser(context.Background(), "usr_1", RequestAuth{AuthToken: testToken}); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
}

func TestIAM_ResetUserPassword(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		if rec.Path != "/api/v1/iam/users/usr_1/reset-password" {
			t.Fatalf("path: %s", rec.Path)
		}
		writeData(w, 200, map[string]any{"sent": true})
	})
	got, err := c.IAM.ResetUserPassword(context.Background(), "usr_1", RequestAuth{AuthToken: testToken})
	if err != nil || !got.Sent {
		t.Fatalf("ResetUserPassword: %v / %+v", err, got)
	}
}

// ─── IAM: Invites ──────────────────────────────────────────────────────

func TestIAM_ListInvites(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		writeData(w, 200, []map[string]any{{"id": "inv_1", "accountId": "acc_x", "email": "x@y", "status": "pending", "expiresAt": "", "createdAt": ""}})
	})
	got, err := c.IAM.ListInvites(context.Background(), RequestAuth{AuthToken: testToken})
	if err != nil || len(got) != 1 || got[0].ID != "inv_1" {
		t.Fatalf("ListInvites: %v / %+v", err, got)
	}
}

func TestIAM_SendInvite(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		writeData(w, 201, map[string]any{"id": "inv_new", "email": "x@y", "status": "pending"})
	})
	got, err := c.IAM.SendInvite(context.Background(), SendInviteInput{Email: "x@y"}, RequestAuth{AuthToken: testToken})
	if err != nil || got.ID != "inv_new" {
		t.Fatalf("SendInvite: %v / %+v", err, got)
	}
}

func TestIAM_CancelInvite(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		writeData(w, 200, nil)
	})
	if err := c.IAM.CancelInvite(context.Background(), "inv_1", RequestAuth{AuthToken: testToken}); err != nil {
		t.Fatalf("CancelInvite: %v", err)
	}
}

// ─── IAM: Access keys ──────────────────────────────────────────────────

func TestIAM_AccessKeys_LifeCycle(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1: // list with filter
			if r.URL.Query().Get("principalArn") != "forjio:huudis::acc_x:user/usr_1" {
				t.Fatalf("principalArn: %q", r.URL.Query().Get("principalArn"))
			}
			writeData(w, 200, []map[string]any{{"id": "ak_1", "principalArn": "forjio:huudis::acc_x:user/usr_1", "status": "active"}})
		case 2: // create
			writeData(w, 201, map[string]any{"id": "ak_new", "principalArn": "forjio:huudis::acc_x:user/usr_1", "secretAccessKey": "sk_seekrit", "status": "active"})
		case 3: // revoke
			writeData(w, 200, map[string]any{"id": "ak_new", "status": "revoked"})
		case 4: // delete
			w.WriteHeader(204)
		}
	})

	list, err := c.IAM.ListAccessKeys(context.Background(), ListAccessKeysParams{PrincipalArn: "forjio:huudis::acc_x:user/usr_1"}, RequestAuth{AuthToken: testToken})
	if err != nil || len(list) != 1 {
		t.Fatalf("ListAccessKeys: %v / %+v", err, list)
	}
	created, err := c.IAM.CreateAccessKey(context.Background(), CreateAccessKeyInput{PrincipalArn: "forjio:huudis::acc_x:user/usr_1"}, RequestAuth{AuthToken: testToken})
	if err != nil || created.SecretAccessKey != "sk_seekrit" {
		t.Fatalf("CreateAccessKey: %v / %+v", err, created)
	}
	revoked, err := c.IAM.RevokeAccessKey(context.Background(), "ak_new", RequestAuth{AuthToken: testToken})
	if err != nil || revoked.Status != "revoked" {
		t.Fatalf("RevokeAccessKey: %v / %+v", err, revoked)
	}
	if err := c.IAM.DeleteAccessKey(context.Background(), "ak_new", RequestAuth{AuthToken: testToken}); err != nil {
		t.Fatalf("DeleteAccessKey: %v", err)
	}
}

// ─── IAM: Groups ───────────────────────────────────────────────────────

func TestIAM_Groups(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, []map[string]any{{"id": "grp_1", "name": "admins"}})
		case 2:
			writeData(w, 200, map[string]any{"id": "grp_1", "name": "admins"})
		case 3:
			writeData(w, 201, map[string]any{"id": "grp_new", "name": "viewers"})
		case 4:
			w.WriteHeader(204)
		case 5:
			if !strings.Contains(rec.Body, `"userId":"usr_42"`) {
				t.Fatalf("AddGroupMember body: %s", rec.Body)
			}
			writeData(w, 200, nil)
		case 6:
			if rec.Path != "/api/v1/iam/groups/grp_1/members/usr_42" {
				t.Fatalf("RemoveGroupMember path: %s", rec.Path)
			}
			writeData(w, 200, nil)
		}
	})

	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.IAM.ListGroups(context.Background(), auth); err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if _, err := c.IAM.GetGroup(context.Background(), "grp_1", auth); err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if _, err := c.IAM.CreateGroup(context.Background(), CreateGroupInput{Name: "viewers"}, auth); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := c.IAM.DeleteGroup(context.Background(), "grp_new", auth); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if err := c.IAM.AddGroupMember(context.Background(), "grp_1", "usr_42", auth); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	if err := c.IAM.RemoveGroupMember(context.Background(), "grp_1", "usr_42", auth); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}
}

// ─── IAM: Roles ────────────────────────────────────────────────────────

func TestIAM_Roles(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, []map[string]any{{"id": "rl_1", "name": "billing-admin"}})
		case 2:
			writeData(w, 200, map[string]any{"id": "rl_1", "name": "billing-admin"})
		case 3:
			if !strings.Contains(rec.Body, `"trustPolicy"`) {
				t.Fatalf("CreateRole body missing trustPolicy: %s", rec.Body)
			}
			writeData(w, 201, map[string]any{"id": "rl_new", "name": "support"})
		case 4:
			w.WriteHeader(204)
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.IAM.ListRoles(context.Background(), auth); err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if _, err := c.IAM.GetRole(context.Background(), "rl_1", auth); err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if _, err := c.IAM.CreateRole(context.Background(), CreateRoleInput{Name: "support", TrustPolicy: map[string]any{"Version": "2025-01-01"}}, auth); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := c.IAM.DeleteRole(context.Background(), "rl_new", auth); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
}

// ─── IAM: Service accounts ─────────────────────────────────────────────

func TestIAM_ServiceAccounts(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, []map[string]any{{"id": "sa_1", "name": "ci-runner"}})
		case 2:
			writeData(w, 200, map[string]any{"id": "sa_1", "name": "ci-runner"})
		case 3:
			writeData(w, 201, map[string]any{"id": "sa_new", "name": "deploy-bot"})
		case 4:
			w.WriteHeader(204)
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.IAM.ListServiceAccounts(context.Background(), auth); err != nil {
		t.Fatalf("ListServiceAccounts: %v", err)
	}
	if _, err := c.IAM.GetServiceAccount(context.Background(), "sa_1", auth); err != nil {
		t.Fatalf("GetServiceAccount: %v", err)
	}
	if _, err := c.IAM.CreateServiceAccount(context.Background(), CreateServiceAccountInput{Name: "deploy-bot"}, auth); err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	if err := c.IAM.DeleteServiceAccount(context.Background(), "sa_new", auth); err != nil {
		t.Fatalf("DeleteServiceAccount: %v", err)
	}
}

// ─── IAM: Policies ─────────────────────────────────────────────────────

func TestIAM_Policies(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			if r.URL.Query().Get("kind") != "custom" {
				t.Fatalf("kind: %q", r.URL.Query().Get("kind"))
			}
			writeData(w, 200, []map[string]any{{"id": "pol_1", "name": "billing-read"}})
		case 2:
			writeData(w, 200, map[string]any{"id": "pol_1", "name": "billing-read", "document": map[string]any{}})
		case 3:
			writeData(w, 201, map[string]any{"id": "pol_new"})
		case 4:
			writeData(w, 200, map[string]any{"id": "pol_1", "name": "billing-write"})
		case 5:
			w.WriteHeader(204)
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.IAM.ListPolicies(context.Background(), ListPoliciesParams{Kind: "custom"}, auth); err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if _, err := c.IAM.GetPolicy(context.Background(), "pol_1", auth); err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if _, err := c.IAM.CreatePolicy(context.Background(), CreatePolicyInput{Name: "billing-read", Document: map[string]any{"Version": "2025-01-01"}}, auth); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := c.IAM.UpdatePolicy(context.Background(), "pol_1", map[string]any{"name": "billing-write"}, auth); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	if err := c.IAM.DeletePolicy(context.Background(), "pol_new", auth); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
}

// ─── IAM: Policy attachments ───────────────────────────────────────────

func TestIAM_PolicyAttachments(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			if r.URL.Query().Get("policyId") != "pol_1" {
				t.Fatalf("policyId: %q", r.URL.Query().Get("policyId"))
			}
			writeData(w, 200, []map[string]any{{"id": "pa_1", "policyId": "pol_1"}})
		case 2:
			writeData(w, 201, map[string]any{"id": "pa_new", "policyId": "pol_1", "principalArn": "forjio:huudis::acc_x:user/usr_1"})
		case 3:
			w.WriteHeader(204)
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.IAM.ListPolicyAttachments(context.Background(), ListPolicyAttachmentsParams{PolicyID: "pol_1"}, auth); err != nil {
		t.Fatalf("ListPolicyAttachments: %v", err)
	}
	if _, err := c.IAM.AttachPolicy(context.Background(), AttachPolicyInput{PolicyID: "pol_1", PrincipalArn: "forjio:huudis::acc_x:user/usr_1"}, auth); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}
	if err := c.IAM.DetachPolicy(context.Background(), "pa_new", auth); err != nil {
		t.Fatalf("DetachPolicy: %v", err)
	}
}

// ─── Identity providers ────────────────────────────────────────────────

func TestIdentityProviders(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, []map[string]any{{"id": "idp_1", "kind": "oidc", "name": "google"}})
		case 2:
			writeData(w, 201, map[string]any{"id": "idp_new", "kind": "saml", "name": "okta"})
		case 3:
			writeData(w, 200, map[string]any{"id": "idp_1", "kind": "oidc", "name": "google", "enabled": false})
		case 4:
			w.WriteHeader(204)
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.IdentityProviders.List(context.Background(), auth); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := c.IdentityProviders.Create(context.Background(), CreateIdentityProviderInput{Kind: "saml", Name: "okta"}, auth); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := c.IdentityProviders.Update(context.Background(), "idp_1", map[string]any{"enabled": false}, auth); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := c.IdentityProviders.Delete(context.Background(), "idp_new", auth); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// ─── Assumed sessions ──────────────────────────────────────────────────

func TestAssumedSessions(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			if r.URL.Query().Get("activeOnly") != "true" {
				t.Fatalf("activeOnly: %q", r.URL.Query().Get("activeOnly"))
			}
			writeData(w, 200, []map[string]any{{"id": "as_1", "active": true}})
		case 2:
			writeData(w, 200, nil)
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	active := true
	if _, err := c.AssumedSessions.List(context.Background(), ListAssumedSessionsParams{ActiveOnly: &active}, auth); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := c.AssumedSessions.Revoke(context.Background(), "as_1", auth); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

// ─── Authz ─────────────────────────────────────────────────────────────

func TestAuthz_Resource(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, map[string]any{"decision": "Allow", "allow": true})
		case 2:
			writeData(w, 200, map[string]any{"accessToken": "tk_assumed", "expiresAt": "2026-01-01", "sessionId": "as_1"})
		case 3:
			writeData(w, 200, map[string]any{"principal": "forjio:huudis::acc_x:user/usr_1", "accountId": "acc_x", "scopes": []string{"openid"}})
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	in := AuthzCheckInput{Action: "iam:ListUsers", Resource: "forjio:huudis::acc_x:*"}
	in.Principal.Type = "user"
	in.Principal.ID = "usr_1"
	in.Principal.AccountID = "acc_x"
	res, err := c.Authz.Check(context.Background(), in, auth)
	if err != nil || !res.Allow {
		t.Fatalf("Check: %v / %+v", err, res)
	}
	assume, err := c.Authz.AssumeRole(context.Background(), AssumeRoleInput{RoleArn: "forjio:huudis::acc_x:role/billing"}, auth)
	if err != nil || assume.SessionID != "as_1" {
		t.Fatalf("AssumeRole: %v / %+v", err, assume)
	}
	who, err := c.Authz.Whoami(context.Background(), auth)
	if err != nil || who.AccountID != "acc_x" {
		t.Fatalf("Whoami: %v / %+v", err, who)
	}
}

// Sanity check that the legacy client.AuthzCheck path still works (v0.2.0 callers).
func TestLegacy_AuthzCheck_Compat(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		writeData(w, 200, map[string]any{"decision": "Allow", "allow": true})
	})
	in := AuthzCheckInput{Action: "iam:ListUsers", Resource: "forjio:huudis::acc_x:*"}
	in.Principal.Type = "user"
	in.Principal.ID = "usr_1"
	in.Principal.AccountID = "acc_x"
	res, err := c.AuthzCheck(context.Background(), testToken, in)
	if err != nil {
		t.Fatalf("AuthzCheck: %v", err)
	}
	if !res.Allow {
		t.Fatal("expected Allow=true")
	}
}

// ─── Workspaces ────────────────────────────────────────────────────────

func TestWorkspaces(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, []map[string]any{{"id": "ws_1", "name": "Personal", "ownerId": "usr_1", "createdAt": ""}})
		case 2:
			writeData(w, 201, map[string]any{"id": "ws_new", "name": "Pawpado", "ownerId": "usr_1"})
		case 3:
			writeData(w, 200, map[string]any{"id": "ws_1", "name": "Renamed"})
		case 4:
			writeData(w, 200, map[string]any{"accessToken": "tk_switched"})
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.Workspaces.List(context.Background(), auth); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := c.Workspaces.Create(context.Background(), CreateWorkspaceInput{Name: "Pawpado"}, auth); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := c.Workspaces.Update(context.Background(), "ws_1", map[string]any{"name": "Renamed"}, auth); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := c.Workspaces.Switch(context.Background(), "ws_1", auth)
	if err != nil || got.AccessToken != "tk_switched" {
		t.Fatalf("Switch: %v / %+v", err, got)
	}
}

// ─── End-users ─────────────────────────────────────────────────────────

func TestEndUsers(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			if r.URL.Query().Get("search") != "alice" {
				t.Fatalf("search: %q", r.URL.Query().Get("search"))
			}
			writeData(w, 200, map[string]any{"items": []map[string]any{{"id": "eu_1", "email": "alice@example.com"}}, "nextCursor": ""})
		case 2:
			writeData(w, 200, map[string]any{"id": "eu_1", "email": "alice@example.com"})
		case 3:
			writeData(w, 200, nil)
		case 4:
			writeData(w, 200, nil)
		case 5:
			writeData(w, 200, nil)
		case 6:
			writeData(w, 200, map[string]any{"sessionId": "is_1", "accessToken": "tk_imp", "expiresAt": "2026-01-01"})
		case 7:
			writeData(w, 200, nil)
		case 8:
			if !strings.Contains(rec.Body, `"reason":"abuse"`) {
				t.Fatalf("Disable body: %s", rec.Body)
			}
			writeData(w, 200, nil)
		case 9:
			writeData(w, 200, nil)
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.EndUsers.List(context.Background(), ListEndUsersParams{Search: "alice"}, auth); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := c.EndUsers.Get(context.Background(), "eu_1", auth); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := c.EndUsers.Revoke(context.Background(), "eu_1", auth); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := c.EndUsers.SendPasswordReset(context.Background(), "eu_1", auth); err != nil {
		t.Fatalf("SendPasswordReset: %v", err)
	}
	if err := c.EndUsers.VerifyEmail(context.Background(), "eu_1", auth); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	imp, err := c.EndUsers.Impersonate(context.Background(), "eu_1", &ImpersonateInput{Reason: "support"}, auth)
	if err != nil || imp.AccessToken != "tk_imp" {
		t.Fatalf("Impersonate: %v / %+v", err, imp)
	}
	if err := c.EndUsers.StopImpersonation(context.Background(), auth); err != nil {
		t.Fatalf("StopImpersonation: %v", err)
	}
	if err := c.EndUsers.Disable(context.Background(), "eu_1", &DisableEndUserInput{Reason: "abuse"}, auth); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if err := c.EndUsers.Enable(context.Background(), "eu_1", auth); err != nil {
		t.Fatalf("Enable: %v", err)
	}
}

// ─── MFA ───────────────────────────────────────────────────────────────

func TestMFA(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 201, map[string]any{"deviceId": "dev_1", "secret": "JBSWY3DPEHPK3PXP", "otpAuthUrl": "otpauth://totp/..."})
		case 2:
			writeData(w, 200, map[string]any{"id": "dev_1", "type": "totp"})
		case 3:
			writeData(w, 200, map[string]any{"accessToken": "tk_mfa"})
		case 4:
			writeData(w, 200, []map[string]any{{"id": "dev_1", "type": "totp"}})
		case 5:
			w.WriteHeader(204)
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	enroll, err := c.MFA.Enroll(context.Background(), MfaEnrollInput{Type: "totp"}, auth)
	if err != nil || enroll.DeviceID != "dev_1" {
		t.Fatalf("Enroll: %v / %+v", err, enroll)
	}
	if _, err := c.MFA.VerifyEnrollment(context.Background(), MfaVerifyEnrollmentInput{DeviceID: "dev_1", Code: "123456"}, auth); err != nil {
		t.Fatalf("VerifyEnrollment: %v", err)
	}
	if _, err := c.MFA.VerifyLogin(context.Background(), MfaVerifyLoginInput{Code: "654321"}, auth); err != nil {
		t.Fatalf("VerifyLogin: %v", err)
	}
	if _, err := c.MFA.ListDevices(context.Background(), auth); err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if err := c.MFA.DeleteDevice(context.Background(), "dev_1", auth); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
}

// ─── OIDC clients ──────────────────────────────────────────────────────

func TestOidcClients(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, []map[string]any{{"id": "oc_1", "name": "main"}})
		case 2:
			writeData(w, 201, map[string]any{"id": "oc_new", "name": "cli"})
		case 3:
			writeData(w, 200, map[string]any{"id": "oc_1", "name": "renamed"})
		case 4:
			writeData(w, 200, map[string]any{"clientSecret": "cs_rotated"})
		case 5:
			w.WriteHeader(204)
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.OidcClients.List(context.Background(), auth); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := c.OidcClients.Create(context.Background(), CreateOidcClientInput{Name: "cli", RedirectUris: []string{"http://localhost/cb"}}, auth); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := c.OidcClients.Update(context.Background(), "oc_1", map[string]any{"name": "renamed"}, auth); err != nil {
		t.Fatalf("Update: %v", err)
	}
	rot, err := c.OidcClients.RotateSecret(context.Background(), "oc_1", auth)
	if err != nil || rot.ClientSecret != "cs_rotated" {
		t.Fatalf("RotateSecret: %v / %+v", err, rot)
	}
	if err := c.OidcClients.Delete(context.Background(), "oc_new", auth); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// ─── Connected apps ────────────────────────────────────────────────────

func TestConnectedApps(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, []map[string]any{{"id": "ca_1", "clientId": "oc_1", "clientName": "Pawpado", "scopes": []string{"openid"}, "consentedAt": ""}})
		case 2:
			w.WriteHeader(204)
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	got, err := c.ConnectedApps.List(context.Background(), auth)
	if err != nil || len(got) != 1 {
		t.Fatalf("List: %v / %+v", err, got)
	}
	if err := c.ConnectedApps.Revoke(context.Background(), "ca_1", auth); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

// ─── Services ──────────────────────────────────────────────────────────

func TestServices(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, []map[string]any{{"service": "plugipay", "enabled": true}})
		case 2:
			writeData(w, 200, map[string]any{"service": "fulkruma", "enabled": true})
		case 3:
			writeData(w, 200, map[string]any{"service": "fulkruma", "enabled": false})
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.Services.List(context.Background(), auth); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := c.Services.Enable(context.Background(), ServiceToggleInput{Service: "fulkruma"}, auth); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if _, err := c.Services.Disable(context.Background(), ServiceToggleInput{Service: "fulkruma"}, auth); err != nil {
		t.Fatalf("Disable: %v", err)
	}
}

// ─── Webhook subscriptions ─────────────────────────────────────────────

func TestWebhookSubscriptions(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, []map[string]any{{"id": "wh_1", "url": "https://hook"}})
		case 2:
			writeData(w, 201, map[string]any{"id": "wh_new", "url": "https://hook", "events": []string{"huudis.user.created.v1"}})
		case 3:
			writeData(w, 200, map[string]any{"id": "wh_1", "url": "https://hook"})
		case 4:
			writeData(w, 200, map[string]any{"id": "wh_1", "url": "https://hook2"})
		case 5:
			w.WriteHeader(204)
		case 6:
			writeData(w, 200, map[string]any{"secret": "whsec_rotated"})
		case 7:
			if r.URL.Query().Get("status") != "failed" {
				t.Fatalf("status filter: %q", r.URL.Query().Get("status"))
			}
			writeData(w, 200, []map[string]any{{"id": "wd_1", "status": "failed"}})
		case 8:
			writeData(w, 200, nil)
		case 9:
			writeData(w, 200, []map[string]any{{"type": "huudis.user.created.v1", "description": "A new user"}})
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.WebhookSubscriptions.List(context.Background(), auth); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := c.WebhookSubscriptions.Create(context.Background(), CreateWebhookSubscriptionInput{URL: "https://hook", Events: []string{"huudis.user.created.v1"}}, auth); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := c.WebhookSubscriptions.Get(context.Background(), "wh_1", auth); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := c.WebhookSubscriptions.Update(context.Background(), "wh_1", map[string]any{"url": "https://hook2"}, auth); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := c.WebhookSubscriptions.Delete(context.Background(), "wh_1", auth); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	rot, err := c.WebhookSubscriptions.RotateSecret(context.Background(), "wh_1", auth)
	if err != nil || rot.Secret != "whsec_rotated" {
		t.Fatalf("RotateSecret: %v / %+v", err, rot)
	}
	if _, err := c.WebhookSubscriptions.ListDeliveries(context.Background(), "wh_1", ListWebhookDeliveriesParams{Status: "failed"}, auth); err != nil {
		t.Fatalf("ListDeliveries: %v", err)
	}
	if err := c.WebhookSubscriptions.ReplayDelivery(context.Background(), "wd_1", auth); err != nil {
		t.Fatalf("ReplayDelivery: %v", err)
	}
	if _, err := c.WebhookSubscriptions.EventsCatalog(context.Background(), auth); err != nil {
		t.Fatalf("EventsCatalog: %v", err)
	}
}

// ─── Billing ───────────────────────────────────────────────────────────

func TestBilling(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, map[string]any{"subscription": map[string]any{"id": "sub_1", "planId": "free", "status": "active", "currentPeriodEnd": "2026-12-31"}, "usage": map[string]any{"identities": 100, "authzChecks": 0, "webhookDeliveries": 0, "asOf": "2026-01-01"}})
		case 2:
			writeData(w, 200, []map[string]any{{"id": "free", "name": "Free", "amount": 0, "currency": "USD", "interval": "month"}})
		case 3:
			writeData(w, 200, map[string]any{"identities": 100, "authzChecks": 200, "webhookDeliveries": 50, "asOf": "2026-01-01"})
		case 4:
			if r.URL.Query().Get("limit") != "10" {
				t.Fatalf("limit: %q", r.URL.Query().Get("limit"))
			}
			writeData(w, 200, []map[string]any{{"id": "in_1", "amount": 1000, "currency": "USD", "status": "paid"}})
		case 5:
			writeData(w, 200, map[string]any{"url": "https://checkout/x", "sessionId": "cs_1"})
		case 6:
			writeData(w, 200, map[string]any{"id": "sub_1", "status": "canceled"})
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.Billing.Summary(context.Background(), auth); err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if _, err := c.Billing.Plans(context.Background(), auth); err != nil {
		t.Fatalf("Plans: %v", err)
	}
	if _, err := c.Billing.Usage(context.Background(), auth); err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if _, err := c.Billing.Invoices(context.Background(), ListInvoicesParams{Limit: 10}, auth); err != nil {
		t.Fatalf("Invoices: %v", err)
	}
	if _, err := c.Billing.Checkout(context.Background(), BillingCheckoutInput{PlanID: "pro"}, auth); err != nil {
		t.Fatalf("Checkout: %v", err)
	}
	if _, err := c.Billing.Cancel(context.Background(), auth); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
}

// ─── Account ───────────────────────────────────────────────────────────

func TestAccount_Core(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, map[string]any{"id": "usr_1", "email": "me@example.com", "emailVerified": true, "mfaEnrolled": false})
		case 2:
			writeData(w, 200, map[string]any{"id": "usr_1", "email": "me@example.com", "name": "Adi"})
		case 3:
			writeData(w, 200, map[string]any{"pendingVerification": true})
		case 4:
			writeData(w, 200, nil)
		case 5:
			if r.URL.Query().Get("limit") != "20" {
				t.Fatalf("limit: %q", r.URL.Query().Get("limit"))
			}
			writeData(w, 200, []map[string]any{{"id": "au_1", "actor": "usr_1", "action": "iam:ListUsers", "outcome": "success", "timestamp": "2026-01-01"}})
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.Account.Get(context.Background(), auth); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := c.Account.Update(context.Background(), map[string]any{"name": "Adi"}, auth); err != nil {
		t.Fatalf("Update: %v", err)
	}
	em, err := c.Account.ChangeEmail(context.Background(), ChangeEmailInput{NewEmail: "new@example.com", Password: "pw"}, auth)
	if err != nil || !em.PendingVerification {
		t.Fatalf("ChangeEmail: %v / %+v", err, em)
	}
	if err := c.Account.ChangePassword(context.Background(), ChangePasswordInput{CurrentPassword: "old", NewPassword: "new"}, auth); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if _, err := c.Account.Audit(context.Background(), AuditParams{Limit: 20}, auth); err != nil {
		t.Fatalf("Audit: %v", err)
	}
}

func TestAccount_Sessions(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, []map[string]any{{"id": "s_1", "lastSeenAt": "2026-01-01", "createdAt": "2025-12-01"}})
		case 2:
			writeData(w, 200, nil)
		case 3:
			writeData(w, 200, map[string]any{"revoked": 3})
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.Account.Sessions.List(context.Background(), auth); err != nil {
		t.Fatalf("Sessions.List: %v", err)
	}
	if err := c.Account.Sessions.Revoke(context.Background(), "s_1", auth); err != nil {
		t.Fatalf("Sessions.Revoke: %v", err)
	}
	got, err := c.Account.Sessions.RevokeAll(context.Background(), auth)
	if err != nil || got.Revoked != 3 {
		t.Fatalf("Sessions.RevokeAll: %v / %+v", err, got)
	}
}

func TestAccount_Linked(t *testing.T) {
	step := 0
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		step++
		switch step {
		case 1:
			writeData(w, 200, []map[string]any{{"provider": "google", "subject": "12345", "linkedAt": "2026-01-01"}})
		case 2:
			w.WriteHeader(204)
		}
	})
	auth := RequestAuth{AuthToken: testToken}
	if _, err := c.Account.Linked.List(context.Background(), auth); err != nil {
		t.Fatalf("Linked.List: %v", err)
	}
	if err := c.Account.Linked.Unlink(context.Background(), "google", auth); err != nil {
		t.Fatalf("Linked.Unlink: %v", err)
	}
}

// ─── HTTP layer edge cases ─────────────────────────────────────────────

func TestEnvelope_ErrorWith4xx(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		writeErr(w, 403, "FORBIDDEN", "you can't see this")
	})
	_, err := c.IAM.GetGroup(context.Background(), "grp_x", RequestAuth{AuthToken: testToken})
	if err == nil {
		t.Fatal("expected forbidden error")
	}
	he := err.(*Error)
	if he.Code != "FORBIDDEN" || !strings.Contains(he.Message, "you can't see this") {
		t.Fatalf("unexpected error: %+v", he)
	}
}

func TestEnvelope_NonEnvelope4xx(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error":{"code":"INTERNAL","message":"boom"}}`))
	})
	_, err := c.IAM.GetGroup(context.Background(), "grp_x", RequestAuth{AuthToken: testToken})
	if err == nil {
		t.Fatal("expected server error")
	}
	he := err.(*Error)
	if he.Code != "INTERNAL" {
		t.Fatalf("expected INTERNAL got %q", he.Code)
	}
}

func TestEnvelope_EmptyBody2xx(t *testing.T) {
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		w.WriteHeader(204)
	})
	if err := c.IAM.DeleteUser(context.Background(), "usr_x", RequestAuth{AuthToken: testToken}); err != nil {
		t.Fatalf("expected success on 204: %v", err)
	}
}

func TestAuth_HeaderSent(t *testing.T) {
	c, recs, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request, rec *recordedReq) {
		writeData(w, 200, []map[string]any{})
	})
	if _, err := c.IAM.ListGroups(context.Background(), RequestAuth{AuthToken: "explicit_per_call_token"}); err != nil {
		t.Fatal(err)
	}
	if (*recs)[0].Auth != "Bearer explicit_per_call_token" {
		t.Fatalf("auth header: %q", (*recs)[0].Auth)
	}
}

// Sanity that v0.2.0 webhook helpers remain importable from the same package.
func TestV020_WebhookSurfaceStillExported(t *testing.T) {
	// Compile-time check is enough — if the function went away, this file
	// would fail to build.
	_ = VerifyWebhookSignature
}
