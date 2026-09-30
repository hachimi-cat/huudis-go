# Changelog

## 0.5.0
- The source now lives in the Huudis monorepo (`sdk/go`), mirrored to github.com/hachimi-cat/huudis-go; this release is v0.4.0 plus the below — nothing removed or renamed.
- `client.API`: every feature route of the Huudis API, one method each, generated from the API spec (`scripts/apigen.sh`): `client.API.<Area><Action>(ctx, …)`.
- Access keys: `ClientOptions.AccessKeyID` + `SecretAccessKey` (or `HUUDIS_ACCESS_KEY_ID` + `HUUDIS_SECRET_ACCESS_KEY`) sign every call `Huudis-HMAC-SHA256` when there is no token — `client.API` and the typed resources alike. The key acts as its user on `/account/*`, `/iam/*`, `/authz/*` within the user's IAM policies. `ClientID` is optional with a key or a token.
- `ClientOptions.Token` (`HUUDIS_TOKEN`): a default bearer for every call; `RequestAuth.AuthToken` still overrides it per call.
- `/api/v1/app/*` is sent with the OIDC client credentials (`ClientID` + `ClientSecret`, HTTP Basic).
- `ClientOptions.WorkspaceID` (`HUUDIS_WORKSPACE_ID`) sends `X-Huudis-Workspace-Id`.
- `SignRequest`, `Client.Do`, `SDKVersion`; `*Error` carries `Status` and `RequestID`.

## 0.4.0
- Full admin API parity with the Node + Python SDKs (published from the mirror).
