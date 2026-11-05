// Synthetic interactions only. This laboratory is not a production IdP or MFA service.
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { once } from 'node:events';
import { Provider, errors } from 'oidc-provider';
import { exportJWK, generateKeyPair } from 'jose';

export async function startTestIdp(policy) {
  if (process.env.NODE_ENV !== 'test' || process.env.HUKID_TEST_IDP !== '1' || policy.environment !== 'test') {
    throw new Error('The synthetic IdP requires explicit test isolation');
  }
  const issuer = new URL(policy.issuer);
  if (issuer.protocol !== 'http:' || issuer.hostname !== '127.0.0.1' || issuer.pathname !== '/' || !issuer.port) {
    throw new Error('The synthetic IdP may listen only on IPv4 loopback');
  }
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = { ...await exportJWK(privateKey), alg: 'ES256', use: 'sig', kid: randomBytes(16).toString('hex') };
  const clientSecret = randomBytes(32).toString('base64url');
  const interactionKey = randomBytes(32).toString('base64url');
  const provider = new Provider(policy.issuer, {
    jwks: { keys: [jwk] },
    cookies: { keys: [randomBytes(32).toString('base64url')] },
    clients: [{
      client_id: policy.clientId, client_secret: clientSecret,
      redirect_uris: [policy.redirectUri], grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'], token_endpoint_auth_method: 'client_secret_basic',
      id_token_signed_response_alg: 'ES256',
    }],
    scopes: policy.scopes,
    claims: { openid: ['sub', 'auth_time', 'acr', 'amr'] },
    acrValues: policy.acceptedAcr,
    pkce: { required: () => true, methods: ['S256'] },
    features: {
      revocation: { enabled: true },
      devInteractions: { enabled: false }, userinfo: { enabled: false },
      resourceIndicators: {
        enabled: true,
        defaultResource: () => policy.audience,
        useGrantedResource: () => true,
        getResourceServerInfo(_ctx, resource) {
          if (resource !== policy.audience) throw new errors.InvalidTarget();
          return { scope: 'operator:read', audience: policy.audience, accessTokenTTL: policy.accessTokenSeconds, accessTokenFormat: 'jwt', jwt: { sign: { alg: 'ES256' } } };
        },
      },
    },
    ttl: {
      AccessToken: policy.accessTokenSeconds, IdToken: policy.accessTokenSeconds, AuthorizationCode: policy.transactionSeconds,
      Interaction: policy.transactionSeconds, Session: policy.sessionAbsoluteSeconds, Grant: policy.sessionAbsoluteSeconds,
      RefreshToken: (_ctx, token) => Math.max(1, token.iiat + policy.refreshTokenSeconds - Math.floor(Date.now() / 1000)),
    },
    rotateRefreshToken: true,
    findAccount(_ctx, id) {
      if (id !== 'operator-test-a') return undefined;
      return { accountId: id, claims: async () => ({ sub: id }) };
    },
    extraTokenClaims(ctx, token) {
      const source = ctx.oidc.entities.AuthorizationCode || ctx.oidc.entities.RefreshToken;
      if (!source || token.accountId !== 'operator-test-a') throw new Error('No verified synthetic human grant');
      return { hukid_token_class: 'operator', hukid_grant: 'authorization_code', auth_time: source.authTime, amr: source.amr, acr: source.acr };
    },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
  });
  // Completion is accessible only to the test harness holding a per-process secret.
  provider.use(async (ctx, next) => {
    if (!ctx.path.startsWith('/interaction/')) return next();
    const supplied = Buffer.from(ctx.get('X-Hukid-Test-Interaction'));
    const expected = Buffer.from(interactionKey);
    if (ctx.method !== 'GET' || supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) { ctx.status = 404; return; }
    const details = await provider.interactionDetails(ctx.req, ctx.res);
    const result = {};
    if (details.prompt.name === 'login') result.login = { accountId: 'operator-test-a', acr: policy.acceptedAcr[0], amr: policy.requiredAmr, remember: false };
    else if (details.prompt.name === 'consent') {
      const grant = details.grantId ? await provider.Grant.find(details.grantId) : new provider.Grant({ accountId: 'operator-test-a', clientId: policy.clientId });
      grant.addOIDCScope((details.prompt.details.missingOIDCScope || []).join(' '));
      grant.addResourceScope(policy.audience, 'operator:read');
      result.consent = { grantId: await grant.save() };
    } else { ctx.status = 400; return; }
    ctx.respond = false;
    await provider.interactionFinished(ctx.req, ctx.res, result, { mergeWithLastSubmission: details.prompt.name !== 'login' });
  });
  const server = createServer(provider.callback());
  server.listen(Number(issuer.port), issuer.hostname);
  await once(server, 'listening');
  return {
    clientSecret, interactionKey,
    async close() { server.closeAllConnections(); await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); },
  };
}
