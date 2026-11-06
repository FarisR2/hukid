import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import SwaggerParser from '@apidevtools/swagger-parser';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const root = new URL('../../', import.meta.url);
const read = file => JSON.parse(readFileSync(new URL(file, root), 'utf8'));
const contract = read('src/platform/contracts/console-auth.openapi.json');
const ajv = new Ajv({ allErrors: true, allowUnionTypes: true });
addFormats(ajv);
const defs = JSON.parse(JSON.stringify(contract.components.schemas).replaceAll('#/components/schemas/', '#/$defs/'));
const validate = schema => ajv.compile({ ...JSON.parse(JSON.stringify(schema).replaceAll('#/components/schemas/', '#/$defs/')), $defs: defs });

test('AUTH-T02 OpenAPI is valid and keeps browser and operator security separate', async () => {
  await SwaggerParser.validate(fileURLToPath(new URL('src/platform/contracts/console-auth.openapi.json', root)));
  const operations = Object.entries(contract.paths).flatMap(([route, methods]) => Object.entries(methods).map(([method, op]) => ({ route, method, op })));
  assert.equal(operations.length, 9);
  assert.deepEqual(contract.paths['/console/auth/callback'].get.security, [{oidcTransaction:[]}]);
  assert.ok(contract.paths['/console/auth/callback'].get.parameters.find(p => p.name === 'iss' && p.required));
  for (const {route, method, op} of operations) {
    assert.equal(op['x-implementation-status'], 'implemented-test-only');
    if (route.startsWith('/v1/')) {
      assert.deepEqual(op.security, [{operatorBearer:[]}]);
      assert.deepEqual(op['x-required-scopes'], ['operator:read']);
    } else if (method === 'post') {
      assert.deepEqual(op.security, [{consoleSession:[],csrfToken:[]}]);
      assert.ok(op.parameters.find(p => p.name === 'Origin' && p.required));
    }
    for (const response of Object.values(op.responses)) assert.equal(response.headers['Cache-Control'].schema.const, 'no-store');
  }
});

test('all request/response examples validate; extra fields cannot carry tokens or browser roles', () => {
  let count = 0;
  for (const methods of Object.values(contract.paths)) {
    for (const op of Object.values(methods)) {
      for (const message of [op.requestBody, ...Object.values(op.responses)]) {
        for (const media of Object.values(message?.content || {})) {
          const check = validate(media.schema);
          assert.equal(check(media.example), true, JSON.stringify(check.errors));
          if (typeof media.example === 'object') {
            assert.equal(check({...media.example,accessToken:'synthetic-not-a-token'}), false);
            if (!media.schema?.$ref?.endsWith('/Context')) assert.equal(check({...media.example,roles:['tenant_admin']}), false);
          }
          count++;
        }
      }
    }
  }
  assert.ok(count >= 30);
  const selection = validate({$ref:'#/components/schemas/TenantSelection'});
  assert.equal(selection({tenantId:''}), false);
  const context = validate({$ref:'#/components/schemas/Context'});
  assert.equal(context({tenantId:'tenant-test-a',capabilities:['global:admin'],issuerIds:[],authorizationRevision:1}), false);
  const base = {tenantId:'tenant-test-a',capabilities:['dashboard:read'],issuerIds:[],authorizationRevision:1};
  assert.equal(context({...base,roles:['support_readonly']}), true);
  assert.equal(context({...base,roles:['global_admin']}), false);
  assert.equal(selection({tenantId:'tenant-test-a',roles:['tenant_admin']}), false);
});

test('test policy requires every field and cannot be promoted to production', () => {
  const schema = read('src/platform/contracts/auth-policy.schema.json');
  const check = ajv.compile(schema);
  const policy = read('src/platform/config/auth.test.json');
  assert.equal(check(policy), true, JSON.stringify(check.errors));
  for (const name of Object.keys(policy)) {
    const missing = {...policy}; delete missing[name];
    assert.equal(check(missing), false, `missing ${name}`);
  }
  assert.equal(check({...policy, environment:'production'}), false);
  assert.equal(check({...policy, issuer:'https://idp.example.invalid'}), false);
});

test('capability matrix agrees with context enum and never grants a directory to issuer/support', () => {
  const matrix = read('src/platform/contracts/capabilities.json');
  assert.deepEqual(Object.keys(matrix.roles).sort(), ['issuer_operator','security_admin','support_readonly','tenant_admin']);
  assert.deepEqual([...new Set(Object.values(matrix.roles).flat())].sort(), contract.components.schemas.Context.properties.capabilities.items.enum);
  for (const role of ['issuer_operator','support_readonly']) assert.deepEqual(matrix.roles[role], ['dashboard:read']);
  assert.ok(!matrix.roles.security_admin.includes('members:update'));
  assert.ok(matrix.stepUpRequired.every(capability => matrix.roles.tenant_admin.includes(capability)));
});
