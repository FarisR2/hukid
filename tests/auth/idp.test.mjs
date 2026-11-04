import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { createLocalJWKSet, jwtVerify } from 'jose';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { startTestIdp } from '../fixtures/oidc-provider.mjs';

const read = file => JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
const policy = read('../../src/platform/config/auth.test.json');
const ajv = new Ajv(); addFormats(ajv);
const checkClaims = ajv.compile(read('../../src/platform/contracts/operator-token.schema.json'));
let idp, metadata, keys;
before(async () => {
  idp = await startTestIdp(policy);
  metadata = await (await fetch(`${policy.issuer}/.well-known/openid-configuration`)).json();
  assert.equal(metadata.issuer, policy.issuer);
  assert.ok(metadata.code_challenge_methods_supported.includes('S256'));
  assert.equal(metadata.authorization_response_iss_parameter_supported, true);
  const publicKeys = await (await fetch(metadata.jwks_uri)).json();
  assert.ok(publicKeys.keys.length > 0);
  assert.ok(publicKeys.keys.every(key => !Object.hasOwn(key,'d')), 'JWKS must not expose private key material');
  keys = createLocalJWKSet(publicKeys);
});
after(async () => { await idp?.close(); });

function authorization(overrides = {}) {
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(32).toString('base64url');
  const nonce = randomBytes(32).toString('base64url');
  const url = new URL(metadata.authorization_endpoint);
  url.search = new URLSearchParams({
    client_id:policy.clientId, redirect_uri:policy.redirectUri, response_type:'code',
    scope:policy.scopes.join(' '), resource:policy.audience, state, nonce,
    code_challenge:createHash('sha256').update(verifier).digest('base64url'), code_challenge_method:'S256',
    acr_values:policy.acceptedAcr[0], prompt:'consent', ...overrides,
  });
  return {url,verifier,state,nonce};
}

// A minimal HTTP user agent, not a browser test. Never logs codes or tokens.
async function authorize(overrides = {}) {
  const request = authorization(overrides);
  let current = request.url;
  const cookies = new Map();
  for (let count = 0; count < 12; count++) {
    if (current.origin !== policy.issuer) {
      assert.ok(current.href.startsWith(`${policy.redirectUri}?`));
      assert.equal(current.searchParams.get('state'), request.state);
      assert.equal(current.searchParams.get('iss'), policy.issuer);
      return {...request, result:current};
    }
    const headers = {cookie:[...cookies].map(([name,value]) => `${name}=${value}`).join('; ')};
    if (current.pathname.startsWith('/interaction/')) headers['X-Hukid-Test-Interaction'] = idp.interactionKey;
    const response = await fetch(current, {redirect:'manual',headers});
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(';')[0]; const equal = pair.indexOf('=');
      cookies.set(pair.slice(0,equal),pair.slice(equal+1));
    }
    assert.ok([302,303].includes(response.status), `unexpected IdP status ${response.status}`);
    current = new URL(response.headers.get('location'), current);
  }
  throw new Error('IdP redirect loop');
}

async function exchange(parameters, secret = idp.clientSecret) {
  const response = await fetch(metadata.token_endpoint, {
    method:'POST', headers:{'content-type':'application/x-www-form-urlencoded',authorization:`Basic ${Buffer.from(`${policy.clientId}:${secret}`).toString('base64')}`},
    body:new URLSearchParams(parameters),
  });
  return {status:response.status,body:await response.json()};
}
async function login() {
  const request = await authorize();
  assert.equal(request.result.searchParams.has('error'), false);
  const parameters = {grant_type:'authorization_code',code:request.result.searchParams.get('code'),redirect_uri:policy.redirectUri,code_verifier:request.verifier,resource:policy.audience};
  const response = await exchange(parameters);
  assert.equal(response.status, 200, response.body.error);
  assert.equal(typeof response.body.refresh_token, 'string', 'offline access requires an explicit consent grant');
  return {...response.body, request, parameters};
}
async function verifyAccess(token) {
  const verified = await jwtVerify(token, keys, {algorithms:['ES256'],typ:'at+jwt',issuer:policy.issuer,audience:policy.audience,requiredClaims:['sub','jti','client_id','auth_time','amr','acr','exp','iat']});
  assert.equal(verified.payload.client_id, policy.clientId);
  assert.equal(checkClaims(verified.payload), true, JSON.stringify(checkClaims.errors));
  assert.equal(verified.payload.exp-verified.payload.iat, policy.accessTokenSeconds);
  return verified.payload;
}

test('real code/PKCE exchange emits signed operator token and a distinct ID token', async () => {
  const tokens = await login();
  await verifyAccess(tokens.access_token);
  const identity = await jwtVerify(tokens.id_token, keys, {issuer:policy.issuer,audience:policy.clientId,algorithms:['ES256']});
  assert.equal(identity.payload.nonce, tokens.request.nonce);
  assert.equal(identity.payload.acr, policy.acceptedAcr[0]);
  assert.deepEqual(identity.payload.amr, policy.requiredAmr);
  assert.ok(Number.isInteger(identity.payload.auth_time));
  await assert.rejects(jwtVerify(tokens.id_token, keys, {typ:'at+jwt',issuer:policy.issuer,audience:policy.audience}));
  await assert.rejects(jwtVerify(tokens.access_token, keys, {typ:'at+jwt',issuer:policy.issuer,audience:'https://api.hukid.pe/integration'}));
  await assert.rejects(jwtVerify(tokens.access_token, keys, {typ:'at+jwt',issuer:'http://127.0.0.1:19091',audience:policy.audience}));
  const current = await verifyAccess(tokens.access_token);
  await jwtVerify(tokens.access_token, keys, {issuer:policy.issuer,audience:policy.audience,currentDate:new Date((current.exp-1)*1000)});
  await assert.rejects(jwtVerify(tokens.access_token, keys, {issuer:policy.issuer,audience:policy.audience,currentDate:new Date(current.exp*1000)}));
  const parts = tokens.access_token.split('.');
  const altered = JSON.parse(Buffer.from(parts[1],'base64url')); altered.sub = 'operator-test-other';
  parts[1] = Buffer.from(JSON.stringify(altered)).toString('base64url');
  await assert.rejects(jwtVerify(parts.join('.'), keys, {issuer:policy.issuer,audience:policy.audience}));
});

test('refresh keeps original auth_time/MFA/grant and rotates; reuse fails', async () => {
  const initial = await login();
  const before = await verifyAccess(initial.access_token);
  const refreshed = await exchange({grant_type:'refresh_token',refresh_token:initial.refresh_token,resource:policy.audience});
  assert.equal(refreshed.status,200,refreshed.body.error);
  const after = await verifyAccess(refreshed.body.access_token);
  assert.equal(after.auth_time,before.auth_time);
  assert.deepEqual(after.amr,before.amr);
  assert.ok(refreshed.body.refresh_token !== initial.refresh_token);
  const reused = await exchange({grant_type:'refresh_token',refresh_token:initial.refresh_token,resource:policy.audience});
  assert.equal(reused.body.error,'invalid_grant');
  const revokedFamily = await exchange({grant_type:'refresh_token',refresh_token:refreshed.body.refresh_token,resource:policy.audience});
  assert.equal(revokedFamily.body.error,'invalid_grant');
});

test('wrong PKCE, repeated code and unauthorized client grant are rejected', async () => {
  const request = await authorize();
  const wrong = await exchange({grant_type:'authorization_code',code:request.result.searchParams.get('code'),redirect_uri:policy.redirectUri,code_verifier:randomBytes(32).toString('base64url')});
  assert.equal(wrong.body.error,'invalid_grant');
  const tokens = await login();
  const replay = await exchange(tokens.parameters);
  assert.equal(replay.body.error,'invalid_grant');
  const clientCredentials = await exchange({grant_type:'client_credentials',scope:'operator:read'});
  assert.ok(['unauthorized_client','unsupported_grant_type'].includes(clientCredentials.body.error));
  const foreign = await authorize({resource:'https://api.hukid.pe/integration'});
  assert.equal(foreign.result.searchParams.get('error'),'invalid_target');
  const wrongClient = await exchange({grant_type:'authorization_code',code:'not-a-valid-code',redirect_uri:policy.redirectUri,code_verifier:'invalid'},'not-the-client-secret');
  assert.equal(wrongClient.body.error,'invalid_client');
  const missingPKCE = await authorize({code_challenge:'',code_challenge_method:''});
  assert.equal(missingPKCE.result.searchParams.get('error'),'invalid_request');
  const interaction = await fetch(`${policy.issuer}/interaction/not-a-real-interaction`);
  assert.equal(interaction.status,404);
});

test('claim schema rejects cross-surface class, missing class, array audience and insufficient MFA', async () => {
  const tokens = await login();
  const claims = await verifyAccess(tokens.access_token);
  for (const change of [
    {hukid_token_class:'integration'}, {hukid_token_class:'oid4vci'},
    {aud:[policy.audience]}, {aud:[policy.audience,'https://api.hukid.pe/integration']},
    {amr:['pwd']}, {acr:'unknown'}, {hukid_grant:'client_credentials'},
  ]) assert.equal(checkClaims({...claims,...change}),false);
  const missing = {...claims}; delete missing.hukid_token_class;
  assert.equal(checkClaims(missing),false);
});

test('synthetic fixture cannot start under production flags', async () => {
  const previous = process.env.NODE_ENV;
  try { process.env.NODE_ENV='production'; await assert.rejects(startTestIdp(policy),/test isolation/); }
  finally { process.env.NODE_ENV=previous; }
});
