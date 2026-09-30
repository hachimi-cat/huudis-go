package huudis

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"
)

// Each route group takes its own credential: the bearer token, an IAM access key
// (Huudis-HMAC-SHA256) for programs, the OIDC client credentials for /api/v1/app/*.

const (
	keyID  = "AKIA0123456789ABCDEF01234567"
	secret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTAxMjM="
)

type apigenSeen struct {
	method, uri, auth, date, workspace, contentType string
	body                                            []byte
}

func apigenServer(t *testing.T, status int, env map[string]any) (*httptest.Server, *[]apigenSeen) {
	t.Helper()
	var seen []apigenSeen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, apigenSeen{
			r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), r.Header.Get("X-Huudis-Date"),
			r.Header.Get("X-Huudis-Workspace-Id"), r.Header.Get("Content-Type"), body,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(env)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func apigenOK(data any) map[string]any {
	return map[string]any{"data": data, "error": nil, "meta": map[string]any{"requestId": "req_ok"}}
}

// What the Huudis server computes (backend/src/services/iam-access-keys.ts), restated.
func expectedSignature(method, pathWithQuery, date string, body []byte) string {
	h := sha256.Sum256(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(method + "\n" + pathWithQuery + "\n" + date + "\n" + hex.EncodeToString(h[:])))
	return hex.EncodeToString(mac.Sum(nil))
}

var authRE = regexp.MustCompile(`^Huudis-HMAC-SHA256 Credential=([A-Z0-9]+), Signature=([a-f0-9]{64})$`)

func signatureOf(t *testing.T, r apigenSeen) string {
	t.Helper()
	m := authRE.FindStringSubmatch(r.auth)
	if m == nil || m[1] != keyID {
		t.Fatalf("authorization = %q", r.auth)
	}
	return m[2]
}

func mustClient(t *testing.T, opts ClientOptions) *Client {
	t.Helper()
	c, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func clearEnv(t *testing.T) {
	for _, k := range []string{"HUUDIS_ISSUER", "HUUDIS_TOKEN", "HUUDIS_ACCESS_KEY_ID", "HUUDIS_SECRET_ACCESS_KEY", "HUUDIS_CLIENT_ID", "HUUDIS_CLIENT_SECRET", "HUUDIS_WORKSPACE_ID"} {
		t.Setenv(k, "")
	}
}

func TestAccessKeySignsGETWithQuery(t *testing.T) {
	clearEnv(t)
	srv, seen := apigenServer(t, 200, apigenOK(map[string]any{"entries": []any{}}))
	c := mustClient(t, ClientOptions{Issuer: srv.URL, AccessKeyID: keyID, SecretAccessKey: secret})
	data, err := c.API.AccountAudit(context.Background(), &AccountAuditArgs{Limit: Ptr(5), Outcome: Ptr("denied")})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"entries":[]}` {
		t.Fatalf("data = %s", data)
	}
	r := (*seen)[0]
	if r.method != "GET" || r.uri != "/api/v1/account/audit?limit=5&outcome=denied" || len(r.body) != 0 {
		t.Fatalf("request = %+v", r)
	}
	at, err := time.Parse(time.RFC3339Nano, r.date)
	if err != nil || time.Since(at).Abs() > time.Minute {
		t.Fatalf("X-Huudis-Date = %q", r.date)
	}
	if got, want := signatureOf(t, r), expectedSignature("GET", r.uri, r.date, nil); got != want {
		t.Fatalf("signature = %s, want %s", got, want)
	}
}

func TestAccessKeySignsTheBodyBytes(t *testing.T) {
	clearEnv(t)
	srv, seen := apigenServer(t, 201, apigenOK(map[string]any{"id": "grp_1"}))
	fixed := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	c := mustClient(t, ClientOptions{Issuer: srv.URL, AccessKeyID: keyID, SecretAccessKey: secret, Now: func() time.Time { return fixed }})
	if _, err := c.API.IamCreateGroups(context.Background(), &IamCreateGroupsArgs{Name: "Ops", Description: Ptr("on call")}); err != nil {
		t.Fatal(err)
	}
	r := (*seen)[0]
	if r.method != "POST" || r.uri != "/api/v1/iam/groups" || r.contentType != "application/json" || r.date != "2026-09-30T12:00:00.000Z" {
		t.Fatalf("request = %+v", r)
	}
	if string(r.body) != `{"description":"on call","name":"Ops"}` {
		t.Fatalf("body = %s", r.body)
	}
	if got, want := signatureOf(t, r), expectedSignature("POST", "/api/v1/iam/groups", r.date, r.body); got != want {
		t.Fatalf("signature = %s, want %s", got, want)
	}
}

func TestAccessKeyFromEnvironmentAndEscapedPath(t *testing.T) {
	clearEnv(t)
	srv, seen := apigenServer(t, 200, apigenOK(nil))
	t.Setenv("HUUDIS_ISSUER", srv.URL)
	t.Setenv("HUUDIS_ACCESS_KEY_ID", keyID)
	t.Setenv("HUUDIS_SECRET_ACCESS_KEY", secret)
	t.Setenv("HUUDIS_WORKSPACE_ID", "acc_123")
	c := mustClient(t, ClientOptions{})
	if _, err := c.API.IamDeleteGroupsMembers(context.Background(), "grp 1", "usr/2"); err != nil {
		t.Fatal(err)
	}
	r := (*seen)[0]
	if r.uri != "/api/v1/iam/groups/grp%201/members/usr%2F2" || r.workspace != "acc_123" {
		t.Fatalf("request = %+v", r)
	}
	if got, want := signatureOf(t, r), expectedSignature("DELETE", r.uri, r.date, nil); got != want {
		t.Fatalf("signature = %s, want %s", got, want)
	}
}

func TestTokenWinsOverTheKey(t *testing.T) {
	clearEnv(t)
	srv, seen := apigenServer(t, 200, apigenOK([]any{}))
	c := mustClient(t, ClientOptions{Issuer: srv.URL, Token: "tok_live", AccessKeyID: keyID, SecretAccessKey: secret})
	if _, err := c.API.IamUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := (*seen)[0]; r.auth != "Bearer tok_live" || r.date != "" {
		t.Fatalf("request = %+v", r)
	}
}

func TestAppRoutesTakeClientCredentials(t *testing.T) {
	clearEnv(t)
	srv, seen := apigenServer(t, 200, apigenOK([]any{}))
	c := mustClient(t, ClientOptions{Issuer: srv.URL, Token: "tok_live", ClientID: "oc_app", ClientSecret: "s3cret"})
	if _, err := c.API.AppUsers(context.Background(), &AppUsersArgs{Status: Ptr("active")}); err != nil {
		t.Fatal(err)
	}
	r := (*seen)[0]
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("oc_app:s3cret"))
	if r.uri != "/api/v1/app/users?status=active" || r.auth != want {
		t.Fatalf("request = %+v", r)
	}
}

func TestAppRoutesSayWhatIsMissing(t *testing.T) {
	clearEnv(t)
	srv, seen := apigenServer(t, 200, apigenOK(nil))
	c := mustClient(t, ClientOptions{Issuer: srv.URL, Token: "tok_live", ClientID: "oc_app"})
	_, err := c.API.AppUsers(context.Background(), nil)
	var he *Error
	if !errors.As(err, &he) || he.Code != "MISSING_CLIENT_CREDENTIALS" {
		t.Fatalf("err = %v", err)
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestErrorEnvelope(t *testing.T) {
	clearEnv(t)
	srv, _ := apigenServer(t, 403, map[string]any{
		"data":  nil,
		"error": map[string]any{"code": "PERSON_ONLY", "message": "Sign in as the person to do this."},
		"meta":  map[string]any{"requestId": "req_x"},
	})
	c := mustClient(t, ClientOptions{Issuer: srv.URL, AccessKeyID: keyID, SecretAccessKey: secret})
	_, err := c.API.AccountPasswordChange(context.Background(), &AccountPasswordChangeArgs{CurrentPassword: Ptr("a"), NewPassword: "b"})
	var he *Error
	if !errors.As(err, &he) || he.Status != 403 || he.Code != "PERSON_ONLY" || he.RequestID != "req_x" {
		t.Fatalf("err = %#v", err)
	}
}

func TestRequiredFieldIsCheckedBeforeSending(t *testing.T) {
	clearEnv(t)
	srv, seen := apigenServer(t, 200, apigenOK(nil))
	c := mustClient(t, ClientOptions{Issuer: srv.URL, AccessKeyID: keyID, SecretAccessKey: secret})
	if _, err := c.API.IamCreateGroups(context.Background(), &IamCreateGroupsArgs{}); err == nil {
		t.Fatal("want an error for the missing name")
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestSignRequest(t *testing.T) {
	auth, date := SignRequest(keyID, secret, "post", "/api/v1/authz/check?x=1", []byte(`{"a":1}`), time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	if date != "2026-09-30T12:00:00.000Z" {
		t.Fatalf("date = %s", date)
	}
	want := "Huudis-HMAC-SHA256 Credential=" + keyID + ", Signature=" + expectedSignature("POST", "/api/v1/authz/check?x=1", date, []byte(`{"a":1}`))
	if auth != want {
		t.Fatalf("auth = %s", auth)
	}
}

func TestTypedResourcesAreSignedWithTheKeyToo(t *testing.T) {
	clearEnv(t)
	srv, seen := apigenServer(t, 200, apigenOK([]any{}))
	c := mustClient(t, ClientOptions{Issuer: srv.URL, AccessKeyID: keyID, SecretAccessKey: secret})
	if _, err := c.IAM.ListGroups(context.Background(), RequestAuth{}); err != nil {
		t.Fatal(err)
	}
	r := (*seen)[0]
	if got, want := signatureOf(t, r), expectedSignature("GET", r.uri, r.date, nil); got != want {
		t.Fatalf("signature = %s, want %s", got, want)
	}
	// A per-call token is sent as it is.
	if _, err := c.IAM.ListGroups(context.Background(), RequestAuth{AuthToken: "tok_call"}); err != nil {
		t.Fatal(err)
	}
	if r := (*seen)[1]; r.auth != "Bearer tok_call" || r.date != "" {
		t.Fatalf("request = %+v", r)
	}
}

func TestNewClientNeedsAClientIDOrACredential(t *testing.T) {
	clearEnv(t)
	if _, err := NewClient(ClientOptions{Issuer: "https://huudis.test"}); err == nil {
		t.Fatal("want MISSING_CLIENT_ID")
	}
	if _, err := NewClient(ClientOptions{Issuer: "https://huudis.test", AccessKeyID: keyID, SecretAccessKey: secret}); err != nil {
		t.Fatal(err)
	}
	if SDKVersion == "" {
		t.Fatal("SDKVersion is empty")
	}
}
