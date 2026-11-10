# Local Keycloak operator integration

Scope: Windows loopback laboratory, Keycloak 26.8.2, the Go BFF and the existing console. Decision: [ADR-0026](../decisions/ADR-0026.md). This implements the existing [operator contract](console-auth-contract.md); it does not change API shapes, SQL migrations or backend JWT validation.

## Compatibility matrix

| Contract | Native provider configuration | Verification |
| --- | --- | --- |
| ES256 ID/access signatures | Persistent managed P-256 key provider; id.token.signed.response.alg and access.token.signed.response.alg | BFF verifier; independent jose signature/JWKS check; key preserved on reconciliation |
| at+jwt access header | access.token.header.type.rfc9068=true | BFF and real-provider gate |
| Exact scalar operator audience | Single explicit audience mapper; no default roles scope | BFF and real-provider gate |
| Registered client_id | Dedicated client mapper | BFF and real-provider gate |
| hukid_token_class=operator | Dedicated client mapper | BFF and real-provider gate |
| Original authorization_code grant | Dedicated mapping plus Code+refresh-only client configuration | Disabled alternative grants, refresh and startup verification |
| amr pwd+otp | Reference values on completed password/OTP executions | Real password/OTP journey; wrong factors rejected |
| acr 2 | LoA 2 condition in the OTP subflow; client minimum/default ACR 2 | Real tokens and step-up |
| auth_time and freshness | Native authentication evidence, unchanged by refresh | Backend comparison and real refresh/step-up |
| Five-minute token ceiling | Client/realm lifespan 300 seconds | Backend and signed-token assertions |
| ID audience and nonce | Native OIDC ID token | Backend and independent signed-token assertions |
| Refresh rotation | revokeRefreshToken=true, refreshTokenMaxReuse=0 | BFF refresh and its rotated session cookie |

The contract's strict scalar audience and private claims remain application-specific. A client administrator who can modify the trusted IdP configuration can break these invariants; client provisioning/startup checks detect the supported configuration, not compromise of that trust boundary.

## Provisioning and drift

[local-keycloak.mjs](../../scripts/local-keycloak.mjs) reconciles client settings, a dedicated flow, authenticator configuration, scopes and five client mappers. It updates existing managed resources instead of only testing their names. Unexpected extra flow executions or client mappers fail with a diagnostic rather than being deleted silently. Repeated invocation preserves identities, credentials, OTP factors and resource counts.

Administrative commands authenticate against the loopback master realm using credentials kept outside Git. Tokens remain in memory. There is no dependency on a kcadm configuration file. HTTP redirects are rejected by the administrative client.

The class/grant constants are valid only for this restricted client. They must not be copied to integration, wallet, password or service-account flows. No static mapping is used for AMR, ACR or auth_time.

## First-time TOTP enrollment

The initial required action verifies and stores the TOTP credential, but does not constitute completion of the browser flow's OTP execution. A callback without the required evidence cannot create a HukID session.

After enrollment, if the callback shows **No se pudo completar el acceso**:

1. Select **Volver a HukID**.
2. Select **Iniciar sesión de nuevo** if the bounded recovery screen is shown.
3. Enter the password and a fresh OTP, then grant consent when requested.

Subsequent normal logins and step-up require the completed password/OTP flow. Refresh preserves the original authentication time and does not perform or pretend to perform MFA. The test waits for a new OTP time step before reuse, because Keycloak may reject a previously accepted code.

## Persistent local environment

From the repository root, with the [documented toolchains](../04-engineering/local-development.md):

```sh
node scripts/local-env.mjs init
node scripts/local-env.mjs keycloak-init
node scripts/local-env.mjs start
```

With Keycloak active, in a second terminal:

```sh
node scripts/local-env.mjs bootstrap
```

`init` is also the upgrade command for existing local state: it applies existing forward-only migrations, provisions missing runtime credentials and creates missing keys without replacing existing material. It does not reset the database. `keycloak-init` reconciles the provider profile and preserves an existing operator's credentials and factors. `start` verifies the critical provider settings before starting the API; liveness alone is not readiness.

| Runtime login | Granted role | Purpose |
| --- | --- | --- |
| hukid_local_session | hukid_session_runtime | Session persistence |
| hukid_local_context | hukid_context_runtime | Identity/context discovery |
| hukid_local_tenant | hukid_tenant_runtime | Current actor's authorized tenant data |
| hukid_local_members | hukid_members_runtime | Members and invitations |
| hukid_local_dashboard | hukid_dashboard_runtime | Read-only dashboard sources |

The script passes the members/dashboard configurations and distinct cursor keys to the API, plus the invitation encryption/HMAC keys. The existing numeric laboratory policies are reused, as already described in ADR-0025; delivery remains synthetic. The worker is not a scheduled production mail service.

Stop with `node scripts/local-env.mjs stop`. Data and keys are retained. If startup fails, newly spawned child processes are stopped; a PostgreSQL process reused by that invocation is not stopped by error cleanup.

## Real-provider gate

Requires the local Keycloak server to be running, initialized local administrative credentials, build artifacts, PostgreSQL 18.6 binaries, the fixed Go toolchain, Python/Playwright and Chromium:

```sh
npm run build
npm run test:keycloak
```

The Node runner creates a random realm and an independently initialized cluster containing its own hukid_local database, with free loopback ports, random credentials and five runtime roles. It does not connect to the persistent application DB. The client ID and all runtime validation rules are the same as local. The realm, API, console and cluster are owned by this execution; cleanup runs on success and failure. The shared Keycloak server is not stopped.

The browser exercises actual password/TOTP enrollment/login, tenant selection, dashboard, member reads, cross-tenant denial, refresh, step-up, invitation creation/replay/revocation, last-admin protection, live role/suspension revalidation, database outage/recovery, logout, token signature/profile checks and code replay rejection. Only test fixture changes use direct SQL, exclusively in the owned cluster. Normal commands go through the real BFF.

The report `.cache/keycloak-tests/latest.json` records source identity/digest, named checks and cleanup results. Logs remain ignored; no browser traces, token payloads, secrets or screenshots are included. This command is separate from the synthetic dashboard gate; the existing CI workflow is not made dependent on a persistent local provider. Real invitation acceptance/delivery, complete IdP/API outage matrices, load, other browsers and production require their own evidence.
