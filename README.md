# huudis (Go)

Official Go SDK for [Huudis](https://huudis.com).

`v0.5.0` — `client.API` (every API route, generated from the API spec), IAM
access keys and OIDC client credentials, on top of the v0.4.0 admin resources
and the v0.2.0 auth surface (`VerifyAccessToken`, `Client.ExchangeCode`,
`Client.AuthzCheck`, webhook signature helpers), all unchanged.

## Install

```bash
go get github.com/hachimi-cat/huudis-go@v0.5.0
```

## Quickstart

Env vars (or pass them to `NewClient`):

```bash
HUUDIS_ISSUER=https://huudis.com
HUUDIS_AUDIENCE=oc_your_client_id
HUUDIS_CLIENT_ID=oc_your_client_id
HUUDIS_CLIENT_SECRET=cs_...       # omit for public clients (PKCE)
```

### Verify an access token

```go
package main

import (
    "encoding/json"
    "net/http"

    huudis "github.com/hachimi-cat/huudis-go"
)

func main() {
    http.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
        claims, err := huudis.VerifyAccessToken(
            r.Context(),
            r.Header.Get("Authorization"),
            huudis.VerifyOptions{},
        )
        if err != nil {
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }
        _ = json.NewEncoder(w).Encode(map[string]string{
            "userId": claims.Sub,
            "email":  claims.Email,
        })
    })
    _ = http.ListenAndServe(":8080", nil)
}
```

### OIDC sign-in flow

```go
client, err := huudis.NewClient(huudis.ClientOptions{})
if err != nil { /* ... */ }

// Step 1: redirect the user
http.Redirect(w, r, client.AuthorizationURL(huudis.AuthorizationURLOptions{
    RedirectURI:   "https://yourapp.com/callback",
    State:         session.State,
    CodeChallenge: session.PKCEChallenge,
}), http.StatusFound)

// Step 2: exchange the code
tokens, err := client.ExchangeCode(r.Context(),
    r.URL.Query().Get("code"),
    "https://yourapp.com/callback",
    session.PKCEVerifier)
if err != nil { /* ... */ }

info, _ := client.UserInfo(r.Context(), tokens.AccessToken)
```

### Authorization check

```go
result, err := client.AuthzCheck(r.Context(), accessToken, huudis.AuthzCheckInput{
    Principal: struct {
        Type        string `json:"type"`
        ID          string `json:"id"`
        AccountID   string `json:"accountId"`
        MfaVerified bool   `json:"mfaVerified,omitempty"`
    }{Type: "user", ID: claims.Sub, AccountID: claims.AccountID},
    Action:   "plugipay:DeleteInvoice",
    Resource: "forjio:plugipay::acc_.../invoice/inv_9F8",
})
if err != nil || !result.Allow {
    http.Error(w, "forbidden: "+result.Reason, http.StatusForbidden)
    return
}
```

### Admin resources

Every resource group exposed by the Node + Python SDKs is mounted as a
field on `Client`. Each method takes a `RequestAuth{AuthToken: ...}` to
attach an admin bearer for that single call.

```go
client, _ := huudis.NewClient(huudis.ClientOptions{})

// IAM users (cursor pagination)
page, err := client.IAM.ListUsers(ctx,
    huudis.ListUsersParams{Limit: 50},
    huudis.RequestAuth{AuthToken: adminToken})

// Workspaces
ws, _ := client.Workspaces.Create(ctx,
    huudis.CreateWorkspaceInput{Name: "Pawpado"},
    huudis.RequestAuth{AuthToken: adminToken})

// Webhook subscriptions
sub, _ := client.WebhookSubscriptions.Create(ctx,
    huudis.CreateWebhookSubscriptionInput{
        URL:    "https://hook",
        Events: []string{"huudis.user.created.v1"},
    },
    huudis.RequestAuth{AuthToken: adminToken})

// MFA, OIDC clients, billing, account profile, …
_, _ = client.MFA.ListDevices(ctx, huudis.RequestAuth{AuthToken: adminToken})
_, _ = client.Billing.Summary(ctx, huudis.RequestAuth{AuthToken: adminToken})
_ = client.Account.Sessions.Revoke(ctx, "s_1", huudis.RequestAuth{AuthToken: adminToken})
```

Namespaces on `Client`:
`IAM`, `IdentityProviders`, `AssumedSessions`, `Authz`, `Workspaces`,
`EndUsers`, `MFA`, `OidcClients`, `ConnectedApps`, `Services`,
`WebhookSubscriptions`, `Billing`, `Account` (`.Sessions`, `.Linked`).

## Every route: `client.API`

`client.API` has one method per Huudis API route, generated from the API spec: path
parameters as arguments, then an `*<Method>Args` with the query and body fields
(optional fields are pointers — `huudis.Ptr(v)`; `Body` passes the whole JSON body).
Each returns the response's `data` as `json.RawMessage`, or an `*huudis.Error` with the
API's error code, HTTP status and request id.

```go
c, err := huudis.NewClient(huudis.ClientOptions{
	Issuer:          "https://huudis.com",
	AccessKeyID:     os.Getenv("HUUDIS_ACCESS_KEY_ID"),
	SecretAccessKey: os.Getenv("HUUDIS_SECRET_ACCESS_KEY"),
	WorkspaceID:     "acc_…", // optional: the workspace to act in
})
users, err := c.API.IamUsers(ctx)
_, err = c.API.IamCreateGroups(ctx, &huudis.IamCreateGroupsArgs{Name: "On call", Description: huudis.Ptr("pager")})
```

## Credentials

Every call — `client.API` and the admin resources — carries the credential its route
group takes:

| Routes | Credential | ClientOptions (environment) |
|---|---|---|
| `/api/v1/app/*` | Your OIDC app's client credentials (HTTP Basic) | `ClientID` + `ClientSecret` (`HUUDIS_CLIENT_ID` + `HUUDIS_CLIENT_SECRET`) |
| Everything else a signed-in person may call | A per-call `RequestAuth{AuthToken}`, else the person's bearer token | `Token` (`HUUDIS_TOKEN`) |
| `/account/*`, `/iam/*`, `/authz/*` for programs (when there is no token) | An IAM access key: each request signed `Huudis-HMAC-SHA256`; acts as the key's user within that user's IAM policies | `AccessKeyID` + `SecretAccessKey` (`HUUDIS_ACCESS_KEY_ID` + `HUUDIS_SECRET_ACCESS_KEY`) |

Routes only a signed-in person may call (password, sessions, account deletion, creating
keys, …) refuse a key with `PERSON_ONLY`, and a key is refused (`ACCESS_DENIED`) until
a policy attached to its user allows the route's action. Members, invites, SSO identity
providers and member password resets need the action named in the policy (no wildcard);
owners are emailed an undo, or must approve first — the call then returns
`approvalRequired` and the same call runs once an owner approved it. See
<https://huudis.com/docs/api/authentication>. `huudis.SignRequest` signs a request you
build yourself; `Client.Do` sends any path with the same credentials.

## What's in the box

| Symbol | Purpose |
|---|---|
| `VerifyAccessToken(ctx, hdr, VerifyOptions{})` | Package-level — reads `HUUDIS_ISSUER` / `HUUDIS_AUDIENCE` from env. |
| `Client` / `NewClient(ClientOptions{})` | Full surface — OIDC code flow, refresh, userinfo, authz check, admin namespaces. |
| `Claims` | Typed view over a Huudis JWT payload. |
| `RequestAuth{AuthToken}` | Per-call bearer override for admin resource methods. |
| `VerifyWebhookSignature(...)` | HMAC-SHA256 webhook signature verifier. |
| `*Error` | Single error type; branch on `.Code` (`UNAUTHORIZED`, `FORBIDDEN`, …). |

The admin resource layer unwraps the Forjio `{data, error, meta}` API
envelope and surfaces backend error codes through `*Error`. JWKS keys
are fetched per issuer and cached for one hour (auto-refreshed on
unknown `kid` to handle rotation).

## Docs

- Full docs: <https://huudis.com/docs>
- Source: <https://github.com/hachimi-cat/saas-huudis/tree/master/sdk/go>

## License

MIT
