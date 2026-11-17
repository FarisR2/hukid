import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import SwaggerParser from '@apidevtools/swagger-parser';

const root = new URL('../../', import.meta.url);
const read = file => JSON.parse(readFileSync(new URL(file, root), 'utf8'));

test('issuance-v1 OpenAPI is valid and aligns security surfaces and capabilities matrix', async () => {
  const contractPath = fileURLToPath(new URL('src/platform/contracts/issuance-v1.openapi.json', root));
  const api = await SwaggerParser.validate(contractPath);
  const matrix = read('src/platform/contracts/capabilities.json');
  const allCapabilities = new Set(Object.values(matrix.roles).flat());

  assert.equal(api.openapi, '3.0.3');

  const requiredPaths = [
    '/.well-known/oauth-authorization-server',
    '/{slug}/.well-known/jwks.json',
    '/{slug}/.well-known/openid-credential-issuer',
    '/{slug}/offers/{ref}',
    '/oauth2/token',
    '/{slug}/nonce',
    '/{slug}/credential',
    '/{slug}/deferred_credential',
    '/{slug}/status-lists/{purpose}/{listId}',
    '/{slug}/schemas/{definitionId}/{version}',
    '/{slug}/contexts/{definitionId}/{version}',
    '/v1/issuance-requests',
    '/v1/issuance-requests/{id}',
    '/v1/credentials/{id}/suspension',
    '/v1/credentials/{id}/revocation',
    '/v1/operator/tenants/{tenantId}/issuers',
    '/v1/operator/tenants/{tenantId}/issuers/{issuerId}/keys/rotate',
    '/v1/operator/tenants/{tenantId}/issuers/{issuerId}/keys/{kid}/compromise',
    '/v1/operator/tenants/{tenantId}/issuers/{issuerId}/credential-definitions',
    '/v1/operator/tenants/{tenantId}/issuers/{issuerId}/credential-definitions/{definitionId}/versions/{version}',
    '/v1/operator/tenants/{tenantId}/issuers/{issuerId}/credential-definitions/{definitionId}/versions/{version}/publish',
    '/v1/operator/tenants/{tenantId}/issuers/{issuerId}/credential-definitions/{definitionId}/versions/{version}/retire',
    '/v1/operator/tenants/{tenantId}/clients',
    '/v1/operator/tenants/{tenantId}/clients/{clientId}/rotate-secret',
    '/v1/operator/tenants/{tenantId}/clients/{clientId}/revoke',
    '/v1/operator/tenants/{tenantId}/audit',
  ];
  for (const p of requiredPaths) {
    assert.ok(api.paths[p], `Missing OpenAPI path: ${p}`);
  }

  for (const [route, methods] of Object.entries(api.paths)) {
    for (const [method, op] of Object.entries(methods)) {
      if (method === 'parameters') continue;
      if (route.startsWith('/v1/operator/')) {
        assert.deepEqual(op.security, [{ operatorBearer: [] }], `${method} ${route} must require operatorBearer`);
        assert.ok(Array.isArray(op['x-required-capabilities']) && op['x-required-capabilities'].length >= 1, `${method} ${route} missing x-required-capabilities`);
        for (const cap of op['x-required-capabilities']) {
          assert.ok(allCapabilities.has(cap), `Capability ${cap} not in capabilities.json`);
          if (method !== 'get') {
            assert.equal(op['x-step-up-required'], true, `${method} ${route} must require step-up MFA`);
            assert.ok(matrix.stepUpRequired.includes(cap), `Step-up capability ${cap} missing from stepUpRequired`);
          }
        }
        for (const resp of Object.values(op.responses)) {
          assert.ok(resp.headers?.['Cache-Control'], `${method} ${route} response missing Cache-Control header`);
        }
      } else if (route.startsWith('/v1/issuance-requests') || route.startsWith('/v1/credentials')) {
        assert.deepEqual(op.security, [{ integrationBearer: [] }], `${method} ${route} must require integrationBearer`);
      } else if (route.endsWith('/credential') || route.endsWith('/deferred_credential')) {
        assert.deepEqual(op.security, [{ oid4vciBearer: [] }], `${method} ${route} must require oid4vciBearer`);
      }
    }
  }
});
