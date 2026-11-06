import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import SwaggerParser from '@apidevtools/swagger-parser';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const root=new URL('../../',import.meta.url);
const read=path=>JSON.parse(readFileSync(new URL(path,root),'utf8'));
const schema=read('src/platform/contracts/dashboard.schema.json');
const fixtures=read('tests/fixtures/dashboard/responses.json');
const metrics=read('src/platform/contracts/dashboard-metrics.json');
const ajv=new Ajv({allErrors:true,strictRequired:false});
addFormats(ajv);ajv.addSchema(schema);
const check=name=>ajv.compile({$ref:schema.$id+'#/$defs/'+name});
const contractPath=fileURLToPath(new URL('src/platform/contracts/console-dashboard.openapi.json',root));
const contract=await SwaggerParser.dereference(contractPath);

test('DASH-T01 defines four contract-only reads with matching API/BFF payloads and effective gates',async()=>{
  await SwaggerParser.validate(contractPath);
  const matrix=read('src/platform/contracts/capabilities.json');
  const auth=read('src/platform/config/auth.test.json');
  assert.equal(contract.components.securitySchemes.consoleSession.name,auth.cookieName);
  const ids=[];
  for(const [route,methods] of Object.entries(contract.paths)){
    assert.deepEqual(Object.keys(methods),['get']);
    const op=methods.get;ids.push(op.operationId);
    const browser=route.startsWith('/console/'),activity=route.endsWith('/activity');
    assert.equal(op['x-implementation-status'],'contract-only');
    assert.equal(op['x-read-only'],true);
    assert.deepEqual(op['x-required-scopes'],['operator:read']);
    assert.deepEqual(op['x-required-capabilities'],activity?['dashboard:read','audit:read']:['dashboard:read']);
    assert.deepEqual(op.security,browser?[{consoleSession:[]}]:[{operatorBearer:[]}]);
    for(const cap of op['x-required-capabilities'])assert.ok(matrix.roles.tenant_admin.includes(cap));
    for(const response of Object.values(op.responses)){
      assert.equal(response.headers['Cache-Control'].schema.const,'no-store');
      assert.equal(response.headers['Referrer-Policy'].schema.const,'no-referrer');
      assert.equal(response.headers['X-Correlation-Id'].required,true);
      for(const media of Object.values(response.content)){
        const validate=ajv.compile(media.schema);
        assert.ok(validate(media.example),JSON.stringify(validate.errors));
      }
    }
    for(const status of [400,401,403,404,422,429,503])assert.ok(op.responses[status]);
    if(!browser){
      assert.equal(op.responses[401].headers['WWW-Authenticate'].schema.const,'Bearer');
      const peer=contract.paths[route.replace('/v1/operator','/console/api')].get;
      assert.deepEqual(op.responses[200],peer.responses[200]);
      assert.deepEqual(op.parameters,peer.parameters);
    }
  }
  assert.equal(ids.length,4);assert.equal(new Set(ids).size,4);
  for(const cap of metrics.reservedCapabilities)for(const caps of Object.values(matrix.roles))assert.ok(!caps.includes(cap));
  assert.equal(metrics.metrics.pendingStatusChanges.capability,'status:read');
  assert.deepEqual(Object.keys(metrics.metrics).sort(),Object.keys(schema.$defs.Overview.properties.sections.properties).sort());
});

test('DASH schemas validate fixtures and reject false zeros, hidden metadata and sensitive activity',()=>{
  assert.equal(fixtures.synthetic,true);assert.equal(fixtures.contractOnly,true);
  for(const fixture of fixtures.cases){
    const validate=check(fixture.schema);
    assert.ok(validate(fixture.value),fixture.name+JSON.stringify(validate.errors));
    for(const field of ['email','claims','accessToken','invitationCode','tenantOverride'])assert.equal(validate({...fixture.value,[field]:'private'}),false);
  }
  const section=check('Section');
  for(const state of ['unavailable','error','notAuthorized']){
    const reasonCode={unavailable:'source_not_connected',error:'source_failed',notAuthorized:'capability_required'}[state];
    const value={state,value:null,asOf:null,reasonCode};
    assert.ok(section(value));
    assert.equal(section({...value,value:0}),false);
    assert.equal(section({...value,asOf:'2026-11-06T12:00:00Z'}),false);
  }
  assert.equal(section({state:'available',value:null,asOf:null,reasonCode:null}),false);
  assert.equal(section({state:'available',value:-1,asOf:'2026-11-06T12:00:00Z',reasonCode:null}),false);
  const event=fixtures.cases.find(f=>f.name==='activity').value.items[0];
  for(const field of ['email','recipientHint','claims','correlationId','issuerId','token'])assert.equal(check('ActivityEvent')({...event,[field]:'private'}),false);
  assert.equal(check('ActivityEvent')({...event,action:'auth.request.denied'}),false);
  assert.equal(check('ActivityEvent')({...event,outcome:'denied'}),false);
  const problem=fixtures.cases.find(f=>f.name==='forbidden').value;
  assert.equal(check('Problem')({...problem,status:200}),false);
});

test('DASH policy is complete, test-only and bounded',()=>{
  const policy=read('src/platform/config/dashboard.test.json');
  const validate=ajv.compile(read('src/platform/contracts/dashboard-policy.schema.json'));
  assert.ok(validate(policy));
  for(const key of Object.keys(policy)){
    const missing={...policy};delete missing[key];assert.equal(validate(missing),false,key);
  }
  for(const change of [{environment:'production'},{maxWindowSeconds:0},{maxPageSize:101},{cursorSeconds:0},{staleAfterSeconds:0}])assert.equal(validate({...policy,...change}),false);
});

test('synthetic dataset pins tenant/issuer boundaries, UTC edges and desired versus published',()=>{
  const data=read('tests/fixtures/dashboard/dataset.json');
  assert.equal(data.synthetic,true);
  const {tenantId,issuerId,from,to}=data.query;
  const inWindow=row=>row.occurredAt>=from&&row.occurredAt<to;
  const members=data.memberships.filter(row=>row.tenantId===tenantId&&row.state==='active');
  assert.equal(members.length,data.expected.activeMembers);
  const events=data.events.filter(row=>row.tenantId===tenantId&&inWindow(row)&&metrics.activity.actions.includes(row.action));
  assert.deepEqual(events.map(row=>row.eventId),data.expected.tenantEventIds);
  const scoped=events.filter(row=>row.issuerId===issuerId);
  assert.deepEqual(scoped.map(row=>row.eventId),data.expected.issuerEventIds);
  const pending=data.status.filter(row=>row.tenantId===tenantId&&row.issuerId===issuerId&&row.desired!==row.published);
  assert.equal(pending.length,data.expected.pendingStatusChanges);
  assert.equal(pending[0].published,'valid');
  assert.equal(data.events.find(row=>row.occurredAt===to).eventId,data.expected.excludedAtTo);
  assert.ok(data.events.some(row=>row.tenantId!==tenantId));
  assert.ok(data.events.some(row=>row.tenantId===tenantId&&row.issuerId!==issuerId&&row.issuerId!==null));
});
