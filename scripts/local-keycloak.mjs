// Keycloak 26.8.2 native operator profile. No MFA claims are hardcoded.
import { readFileSync } from 'node:fs';
// Mode selects the realm profile: "local" (default, unchanged) or "staging" (remote, HTTPS).
// Only timing values come from the policy file; origins and secrets never do.
const policyFiles = { local: 'auth.local.json', staging: 'auth.staging.example.json' };
const policies = {};
export function selectMode(env = process.env) {
  const mode = env.HUKID_KEYCLOAK_MODE ?? 'local';
  if (!Object.hasOwn(policyFiles, mode)) throw new Error('HUKID_KEYCLOAK_MODE debe ser "local" o "staging"');
  return mode;
}
function policyFor(mode) {
  if (!Object.hasOwn(policyFiles, mode)) throw new Error('Keycloak: modo desconocido');
  return policies[mode] ??= JSON.parse(readFileSync(new URL(`../src/platform/config/${policyFiles[mode]}`, import.meta.url), 'utf8'));
}
export const flowAlias = 'hukid-console-mfa-v1';
export const operatorAudience = 'https://api.hukid.pe/operator';

export async function adminClient(base, password, username = 'admin') {
  const response = await fetch(`${base}/realms/master/protocol/openid-connect/token`, {
    method: 'POST', body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username, password }),
    signal: AbortSignal.timeout(10000), redirect: 'error',
  });
  if (!response.ok) throw new Error('Keycloak: no se pudo autenticar al administrador local');
  const { access_token: token } = await response.json();
  return async (method, resource, body) => {
    const result = await fetch(`${base}/admin/realms/${resource}`, {
      method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(10000), redirect: 'error',
    });
    if (!result.ok) throw new Error(`Keycloak: ${method} ${resource.split('?')[0]} (${result.status})`);
    return result.status === 204 || result.headers.get('content-length') === '0' ? null : result.text().then(text => text ? JSON.parse(text) : null);
  };
}

function claim(name, value) {
  return { name: `hukid-${name}`, protocol: 'openid-connect', protocolMapper: 'oidc-hardcoded-claim-mapper',
    config: { 'claim.name': name, 'claim.value': value, 'jsonType.label': 'String', 'access.token.claim': 'true', 'id.token.claim': 'false', 'userinfo.token.claim': 'false' } };
}

export async function verifyKeycloak(api, { realm, client, origin, mode = 'local' }) {
  const policy = policyFor(mode);
  if (mode === 'staging' && (await api('GET', realm)).sslRequired !== 'external') throw new Error('Keycloak: staging exige sslRequired=external en el realm');
  const [model] = (await api('GET', `${realm}/clients?clientId=${encodeURIComponent(client)}`)).filter(c => c.clientId === client);
  const invalid = () => { throw new Error('Keycloak: perfil operator incompatible; ejecutar local-env.mjs keycloak-init'); };
  if (!model || !model.enabled || !model.standardFlowEnabled || model.publicClient || model.directAccessGrantsEnabled || model.serviceAccountsEnabled || model.implicitFlowEnabled || model.fullScopeAllowed) invalid();
  if (origin && (JSON.stringify(model.redirectUris) !== JSON.stringify([`${origin}/console/auth/callback`]) || JSON.stringify(model.webOrigins) !== JSON.stringify([origin]))) invalid();
  const attributes = { 'id.token.signed.response.alg': 'ES256', 'access.token.signed.response.alg': 'ES256',
    'access.token.header.type.rfc9068': 'true', 'pkce.code.challenge.method': 'S256',
    'access.token.lifespan': String(policy.accessTokenSeconds), 'minimum.acr.value': '2',
    'default.acr.values': '2', 'acr.loa.map': '{"2":2}', 'client.use.lightweight.access.token.enabled': 'false',
    'standard.token.exchange.enabled': 'false', 'oauth2.jwt.authorization.grant.enabled': 'false',
    'oauth2.device.authorization.grant.enabled': 'false', 'oidc.ciba.grant.enabled': 'false' };
  if (Object.entries(attributes).some(([key, value]) => model.attributes?.[key] !== value)) invalid();
  const flow = (await api('GET', `${realm}/authentication/flows`)).find(f => f.alias === flowAlias);
  if (!flow || model.authenticationFlowBindingOverrides?.browser !== flow.id) invalid();
  const executions = await api('GET', `${realm}/authentication/flows/${flowAlias}/executions`);
  if (executions.length !== 4 || executions.filter(e => e.authenticationFlow).length !== 1) invalid();
  if (!executions.some(e => e.authenticationFlow && e.displayName === `${flowAlias}-otp` && e.requirement === 'CONDITIONAL')) invalid();
  for (const [provider, reference] of [['auth-username-password-form', 'pwd'], ['auth-otp-form', 'otp'], ['conditional-level-of-authentication', null]]) {
    const matches = executions.filter(e => e.providerId === provider);
    if (matches.length !== 1 || matches[0].requirement !== 'REQUIRED' || !matches[0].authenticationConfig) invalid();
    const { config } = await api('GET', `${realm}/authentication/config/${matches[0].authenticationConfig}`);
    if (reference ? config['default.reference.value'] !== reference || config['default.reference.maxAge'] !== String(policy.sessionAbsoluteSeconds) : config['loa-condition-level'] !== '2' || config['loa-max-age'] !== '0') invalid();
  }
  const scopes = await api('GET', `${realm}/clients/${model.id}/default-client-scopes`);
  if (scopes.some(s => !['email', 'acr', 'basic', 'operator:read'].includes(s.name)) || !scopes.some(s => s.name === 'operator:read')) invalid();
  const optional = await api('GET', `${realm}/clients/${model.id}/optional-client-scopes`);
  if (optional.length !== 1 || optional[0].name !== 'offline_access') invalid();
  const realmConfig = await api('GET', realm);
  if (realmConfig.accessTokenLifespan !== policy.accessTokenSeconds || !realmConfig.revokeRefreshToken || realmConfig.refreshTokenMaxReuse !== 0) invalid();
  const components = await api('GET', `${realm}/components?type=org.keycloak.keys.KeyProvider`);
  const signer = components.find(c => c.name === 'hukid-es256-signing');
  const keys = await api('GET', `${realm}/keys`);
  if (!signer || signer.providerId !== 'ecdsa-generated' || !keys.keys.some(key => key.providerId === signer.id && key.kid === keys.active.ES256 && key.algorithm === 'ES256')) invalid();
  const mappers = await api('GET', `${realm}/clients/${model.id}/protocol-mappers/models`);
  for (const [name, value] of [['client_id', client], ['hukid_token_class', 'operator'], ['hukid_grant', 'authorization_code']]) {
    const mapper = mappers.find(m => m.name === `hukid-${name}`);
    if (mapper?.protocolMapper !== 'oidc-hardcoded-claim-mapper' || mapper.config['claim.name'] !== name || mapper.config['claim.value'] !== value || mapper.config['access.token.claim'] !== 'true') invalid();
  }
  const amr = mappers.find(m => m.name === 'hukid-amr');
  const audience = mappers.find(m => m.name === 'hukid-audience');
  if (mappers.length !== 5 || amr?.protocolMapper !== 'oidc-amr-mapper' || amr.config['access.token.claim'] !== 'true' || amr.config['id.token.claim'] !== 'true' || audience?.protocolMapper !== 'oidc-audience-mapper' || audience.config['included.custom.audience'] !== operatorAudience || audience.config['id.token.claim'] !== 'false') invalid();
  return model;
}

export async function reconcileKeycloak(api, { realm, client, origin, clientSecret, mode = 'local' }) {
  const policy = policyFor(mode);
  const sslRequired = mode === 'staging' ? 'external' : 'none';
  if (!(await api('GET', '')).some(r => r.realm === realm)) await api('POST', '', { realm, enabled: true, sslRequired, registrationAllowed: false, bruteForceProtected: true });
  const r = encodeURIComponent(realm);
  // Staging also enforces sslRequired on an existing realm; local keeps its create-time value untouched.
  await api('PUT', r, { ...(mode === 'staging' ? { sslRequired } : {}), accessTokenLifespan: policy.accessTokenSeconds, ssoSessionIdleTimeout: policy.sessionIdleSeconds, ssoSessionMaxLifespan: policy.sessionAbsoluteSeconds,
    offlineSessionIdleTimeout: policy.refreshTokenSeconds, offlineSessionMaxLifespanEnabled: true, offlineSessionMaxLifespan: policy.refreshTokenSeconds,
    revokeRefreshToken: true, refreshTokenMaxReuse: 0 });
  // Persist an EC key provider; do not rely on Keycloak's ephemeral fallback signer.
  const realmId = (await api('GET', r)).id;
  const components = await api('GET', `${r}/components?type=org.keycloak.keys.KeyProvider`);
  const signer = components.find(c => c.name === 'hukid-es256-signing');
  const signingConfig = { priority: ['200'], enabled: ['true'], active: ['true'], ecdsaEllipticCurveKey: ['P-256'] };
  if (!signer) await api('POST', `${r}/components`, { name: 'hukid-es256-signing', parentId: realmId, providerType: 'org.keycloak.keys.KeyProvider', providerId: 'ecdsa-generated', config: signingConfig });
  else {
    if (signer.providerId !== 'ecdsa-generated') throw new Error('Keycloak: proveedor de firma administrado incompatible');
    if (Object.entries(signingConfig).some(([name, value]) => JSON.stringify(signer.config[name]) !== JSON.stringify(value))) {
      if (signer.config.ecdsaEllipticCurveKey?.[0] !== 'P-256') throw new Error('Keycloak: curva administrada incompatible; no se rota una clave implícitamente');
      await api('PUT', `${r}/components/${signer.id}`, { ...signer, config: { ...signer.config, ...signingConfig } });
    }
  }

  const flows = await api('GET', `${r}/authentication/flows`);
  if (!flows.some(f => f.alias === flowAlias)) await api('POST', `${r}/authentication/flows`, { alias: flowAlias, providerId: 'basic-flow', topLevel: true, builtIn: false });
  const root = `${r}/authentication/flows/${flowAlias}`;
  let executions = await api('GET', `${root}/executions`);
  const expected = new Set(['auth-username-password-form', 'conditional-level-of-authentication', 'auth-otp-form']);
  if (executions.some(e => !e.authenticationFlow && !expected.has(e.providerId))) throw new Error('Keycloak: ejecución inesperada en el flujo HukID');
  if (!executions.some(e => e.providerId === 'auth-username-password-form')) await api('POST', `${root}/executions/execution`, { provider: 'auth-username-password-form' });
  const subAlias = `${flowAlias}-otp`;
  if (!executions.some(e => e.displayName === subAlias)) await api('POST', `${root}/executions/flow`, { alias: subAlias, type: 'basic-flow', provider: 'basic-flow', description: 'OTP obligatorio; LoA sólo tras completar el subflujo' });
  const sub = `${r}/authentication/flows/${subAlias}`;
  executions = await api('GET', `${sub}/executions`);
  for (const provider of ['conditional-level-of-authentication', 'auth-otp-form']) {
    if (!executions.some(e => e.providerId === provider)) await api('POST', `${sub}/executions/execution`, { provider });
  }
  executions = await api('GET', `${root}/executions`);
  if (executions.length !== 4 || executions.filter(e => e.authenticationFlow).length !== 1 || executions.some(e => e.authenticationFlow ? e.displayName !== subAlias : !expected.has(e.providerId))) throw new Error('Keycloak: estructura inesperada del flujo HukID');
  for (const execution of executions) {
    const requirement = execution.authenticationFlow ? 'CONDITIONAL' : 'REQUIRED';
    await api('PUT', `${root}/executions`, { ...execution, requirement });
    let config;
    if (execution.providerId === 'auth-username-password-form' || execution.providerId === 'auth-otp-form') config = {
      'default.reference.value': execution.providerId === 'auth-otp-form' ? 'otp' : 'pwd', 'default.reference.maxAge': String(policy.sessionAbsoluteSeconds),
    };
    if (execution.providerId === 'conditional-level-of-authentication') config = { 'loa-condition-level': '2', 'loa-max-age': '0' };
    if (config) {
      const body = { alias: `hukid-${execution.providerId}`, config };
      if (execution.authenticationConfig) await api('PUT', `${r}/authentication/config/${execution.authenticationConfig}`, body);
      else await api('POST', `${r}/authentication/executions/${execution.id}/config`, body);
    }
  }
  const flow = (await api('GET', `${r}/authentication/flows`)).find(f => f.alias === flowAlias);
  const matches = await api('GET', `${r}/clients?clientId=${encodeURIComponent(client)}`);
  let model = matches.find(c => c.clientId === client);
  const attributes = { ...model?.attributes, 'pkce.code.challenge.method': 'S256',
    'id.token.signed.response.alg': 'ES256', 'access.token.signed.response.alg': 'ES256',
    'access.token.header.type.rfc9068': 'true', 'access.token.lifespan': String(policy.accessTokenSeconds),
    'standard.token.exchange.enabled': 'false', 'oauth2.jwt.authorization.grant.enabled': 'false',
    'oauth2.device.authorization.grant.enabled': 'false', 'oidc.ciba.grant.enabled': 'false',
    'client.use.lightweight.access.token.enabled': 'false', 'acr.loa.map': '{"2":2}',
    'default.acr.values': '2', 'minimum.acr.value': '2' };
  const desired = { ...model, clientId: client, enabled: true, protocol: 'openid-connect', publicClient: false,
    clientAuthenticatorType: 'client-secret', secret: clientSecret, standardFlowEnabled: true, implicitFlowEnabled: false,
    directAccessGrantsEnabled: false, serviceAccountsEnabled: false, fullScopeAllowed: false,
    consentRequired: true, redirectUris: [`${origin}/console/auth/callback`], webOrigins: [origin],
    authenticationFlowBindingOverrides: { browser: flow.id }, attributes };
  if (model) await api('PUT', `${r}/clients/${model.id}`, desired);
  else { await api('POST', `${r}/clients`, desired); model = (await api('GET', `${r}/clients?clientId=${client}`)).find(c => c.clientId === client); }
  const c = `${r}/clients/${model.id}`;
  // Remove default role/audience mappers; API permissions come from local membership.
  const allowedDefaults = new Set(['email', 'acr', 'basic', 'operator:read']);
  for (const scope of await api('GET', `${c}/default-client-scopes`)) {
    if (!allowedDefaults.has(scope.name)) await api('DELETE', `${c}/default-client-scopes/${scope.id}`);
  }
  const allScopes = await api('GET', `${r}/client-scopes`);
  const operatorScope = allScopes.find(s => s.name === 'operator:read');
  const scopeModel = { ...operatorScope, name: 'operator:read', protocol: 'openid-connect', attributes: { ...operatorScope?.attributes, 'include.in.token.scope': 'true', 'display.on.consent.screen': 'false' } };
  if (!operatorScope) await api('POST', `${r}/client-scopes`, scopeModel);
  else await api('PUT', `${r}/client-scopes/${operatorScope.id}`, scopeModel);
  for (const scope of await api('GET', `${r}/client-scopes`)) {
    if (allowedDefaults.has(scope.name)) await api('PUT', `${c}/default-client-scopes/${scope.id}`);
  }
  // Offline refresh is the sole optional scope for this dedicated Code client.
  for (const scope of await api('GET', `${c}/optional-client-scopes`)) if (scope.name !== 'offline_access') await api('DELETE', `${c}/optional-client-scopes/${scope.id}`);
  const offline = (await api('GET', `${r}/client-scopes`)).find(s => s.name === 'offline_access');
  if (!offline) throw new Error('Keycloak: scope offline_access ausente');
  await api('PUT', `${c}/optional-client-scopes/${offline.id}`);
  const mappers = [
    { name: 'hukid-amr', protocol: 'openid-connect', protocolMapper: 'oidc-amr-mapper', config: { 'access.token.claim': 'true', 'id.token.claim': 'true' } },
    { name: 'hukid-audience', protocol: 'openid-connect', protocolMapper: 'oidc-audience-mapper', config: { 'included.custom.audience': operatorAudience, 'access.token.claim': 'true', 'id.token.claim': 'false' } },
    claim('client_id', client), claim('hukid_token_class', 'operator'), claim('hukid_grant', 'authorization_code'),
  ];
  const existing = await api('GET', `${c}/protocol-mappers/models`);
  if (existing.some(m => !mappers.some(wanted => wanted.name === m.name))) throw new Error('Keycloak: mapper ajeno al perfil operator dedicado');
  for (const mapper of mappers) {
    const old = existing.find(m => m.name === mapper.name);
    if (old) await api('PUT', `${c}/protocol-mappers/models/${old.id}`, { ...mapper, id: old.id });
    else await api('POST', `${c}/protocol-mappers/models`, mapper);
  }
  await verifyKeycloak(api, { realm, client, origin, mode });
  return { clientId: model.id, flowId: flow.id };
}
