# Changelog

## 0.8.0
- New: `client.API.IamKeyRequests`, `IamGetKeyRequests`, `IamKeyRequestsChallenge`, `IamKeyRequestsApprove`, `IamKeyRequestsDeny` (what access keys ask a workspace owner to approve) and `IamKeyActions`, `IamKeyActionsUndo` (what keys did to the workspace's members, and undoing it).
- An access key can now add, invite, re-role and remove members, reset another member's password and manage SSO identity providers, when its user's policy names the action itself (`huudis:AddMember`, `huudis:InviteMember`, `huudis:UpdateMember`, `huudis:RemoveMember`, `huudis:ResetMemberPassword`, `huudis:CreateIdentityProvider`, `huudis:UpdateIdentityProvider`, `huudis:DeleteIdentityProvider`; a wildcard such as `huudis:*` does not grant them). Member changes run at once and every workspace owner is emailed a link to undo them. SSO, password resets and anything about the owner role answer `{"approvalRequired": true, "request": …}` (HTTP 202) until an owner approves with a second-factor code; then the same call runs once. A key never sets or sees a member's password.

## 0.7.0
- `OpsEndUsersImpersonateArgs` has `Reason`; the audit log and the `huudis.ops.impersonation_*` webhook events carry it.
- Huudis now delivers every webhook event its catalog lists (they were reserved): verify them with `VerifyWebhookSignature` as before; see /docs/api/webhooks for who receives which.

## 0.6.0
- A route read by id next to its list is named `get` + the list's name: `client.API.AccountGetWebhookSubscriptions` (was `client.API.AccountWebhookSubscriptions2`), `client.API.IamGetGroups` (was `client.API.IamGroups2`), `client.API.IamGetPolicies` (was `client.API.IamPolicies2`), `client.API.IamGetRoles` (was `client.API.IamRoles2`), `client.API.IamGetServiceAccounts` (was `client.API.IamServiceAccounts2`), `client.API.OpsGetEndUsers` (was `client.API.OpsEndUsers2`). Each old name stays as a deprecated alias.

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
