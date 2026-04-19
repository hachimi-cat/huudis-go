# huudis (Go)

Official Go SDK for [Huudis](https://huudis.com).

## Install

```bash
go get github.com/hachimi-cat/huudis-go
```

> We plan to mirror this package to a dedicated `github.com/hachimi-cat/huudis-go`
> repo for shorter import paths in v0.2.

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

## What's in the box

| Symbol | Purpose |
|---|---|
| `VerifyAccessToken(ctx, hdr, VerifyOptions{})` | Package-level — reads `HUUDIS_ISSUER` / `HUUDIS_AUDIENCE` from env. |
| `Client` / `NewClient(ClientOptions{})` | Full surface — OIDC code flow, refresh, userinfo, authz check. |
| `Claims` | Typed view over a Huudis JWT payload. |
| `*Error` | Single error type; branch on `.Code`. |

JWKS keys are fetched per issuer and cached for one hour (auto-refreshed
on unknown `kid` to handle rotation).

## Docs

- Full docs: <https://huudis.com/docs>
- Source: <https://github.com/hachimi-cat/saas-huudis/tree/master/sdk/go>

## License

MIT
