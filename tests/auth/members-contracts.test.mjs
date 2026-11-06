import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import SwaggerParser from '@apidevtools/swagger-parser';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const root=new URL('../../',import.meta.url);
const read=file=>JSON.parse(readFileSync(new URL(file,root),'utf8'));
const contract=await SwaggerParser.dereference(fileURLToPath(new URL('src/platform/contracts/console-members.openapi.json',root)));
const schema=read('src/platform/contracts/user-management.schema.json');
const policy=read('src/platform/config/user-management.test.json');
const ajv=new Ajv({allErrors:true,allowUnionTypes:true,strictRequired:false});
addFormats(ajv);
ajv.addSchema(schema);
const check=name=>ajv.compile({$ref:schema.$id+'#/$defs/'+name});
const operations=Object.entries(contract.paths).flatMap(([route,methods])=>Object.entries(methods).map(([method,op])=>({route,method,op})));

test('USR contract resolves 12 operations: ten implemented test operations and two contract-only mutations',async()=>{
  await SwaggerParser.validate(fileURLToPath(new URL('src/platform/contracts/console-members.openapi.json',root)));
  assert.equal(operations.length,12);
  assert.equal(new Set(operations.map(({op})=>op.operationId)).size,12);
  const matrix=read('src/platform/contracts/capabilities.json');
  assert.deepEqual(schema.$defs.Role.enum,Object.keys(matrix.roles).sort());
  for(const {route,method,op} of operations){
    assert.equal(op['x-implementation-status'],(method==='get'||route.endsWith('/invitations')||route.endsWith('/revocations')||route.endsWith('/invitation-acceptances'))?'implemented-test':'contract-only');
    if(method==='get')assert.ok(op.responses['422']);
    assert.deepEqual(op['x-required-scopes'],['operator:read']);
    const browser=route.startsWith('/console/'),mutation=method!=='get';
    assert.deepEqual(op.security,browser?[mutation?{consoleSession:[],csrfToken:[]}:{consoleSession:[]}]:[{operatorBearer:[]}]);
    const acceptance=route.endsWith('/invitation-acceptances');
    assert.equal(op['x-membership-required'],!acceptance);
    assert.equal(op['x-step-up-required'],mutation&&!acceptance);
    if(acceptance)assert.deepEqual(op['x-required-capabilities'],[]);
    if(mutation){
      assert.ok(op.parameters.some(p=>p.name==='Idempotency-Key'&&p.required));
      assert.equal(op['x-idempotency'].reauthorizeBeforeReplay,true);
      assert.equal(op['x-idempotency'].retentionSeconds,policy.idempotencySeconds);
      if(browser)assert.ok(op.parameters.some(p=>p.name==='Origin'&&p.required));
    }
    for(const cap of op['x-required-capabilities']){
      assert.ok(matrix.roles.tenant_admin.includes(cap));
      assert.ok(!matrix.roles.issuer_operator.includes(cap));
      assert.ok(!matrix.roles.support_readonly.includes(cap));
      if(mutation){assert.ok(matrix.stepUpRequired.includes(cap));assert.ok(!matrix.roles.security_admin.includes(cap));}
    }
    if(method==='patch')assert.deepEqual(op['x-conditional-capabilities'],{revoked:['members:revoke']});
    for(const [status,response] of Object.entries(op.responses)){
      assert.equal(response.headers['Cache-Control'].schema.const,'no-store');
      assert.equal(response.headers['Referrer-Policy'].schema.const,'no-referrer');
      assert.ok(response.headers['X-Correlation-Id'].required);
      if(status==='401'&&!browser)assert.equal(response.headers['WWW-Authenticate'].schema.const,'Bearer');
    }
  }
  // Every BFF consumer uses precisely the same payload/capability contract.
  for(const {route,method,op} of operations.filter(x=>x.route.startsWith('/v1/operator'))){
    const peer=contract.paths[route.replace('/v1/operator','/console/api')][method];
    assert.deepEqual(op.requestBody,peer.requestBody);
    assert.deepEqual(op['x-required-capabilities'],peer['x-required-capabilities']);
  }
});

test('USR-T01 validates every operation example and rejects secrets or authority added to responses',async()=>{
  const expanded=await SwaggerParser.dereference(fileURLToPath(new URL('src/platform/contracts/console-members.openapi.json',root)));
  let count=0;
  for(const methods of Object.values(expanded.paths))for(const op of Object.values(methods)){
    for(const message of [op.requestBody,...Object.values(op.responses)])for(const media of Object.values(message?.content??{})){
      const validate=ajv.compile(media.schema);
      assert.ok(validate(media.example),JSON.stringify(validate.errors));
      for(const field of ['accessToken','refreshToken','emailVerified','capabilities','tenantOverride'])assert.equal(validate({...media.example,[field]:'untrusted'}),false,field);
      count++;
    }
  }
  assert.ok(count>=100);
  const example=contract.paths['/v1/operator/tenants/{tenantId}/memberships'].get.responses['200'].content['application/json'].example.items[0];
  for(const field of ['email','token','invitationUrl','subject','amr','claims'])assert.equal(check('Membership')({...example,[field]:'synthetic'}),false);
});

test('strict member/invitation inputs reject escalation, partial grants, empty patches and malformed addresses',()=>{
  const invite=check('InviteMember');
  const base={email:'Admin+lab@EXAMPLE.invalid',roles:['tenant_admin'],issuerIds:[]};
  assert.ok(invite(base),JSON.stringify(invite.errors));
  for(const email of ['a..b@example.invalid',' admin@example.invalid','a@example.invalid\n','á@example.invalid','a@[127.0.0.1]','a@localhost',`${'a'.repeat(65)}@example.invalid`])assert.equal(invite({...base,email}),false,email);
  for(const roles of [[],['global_admin'],['tenant_admin','tenant_admin']])assert.equal(invite({...base,roles}),false);
  assert.equal(invite({...base,roles:['issuer_operator']}),false);
  assert.equal(invite({...base,issuerIds:['60000000-0000-4000-8000-000000000001']}),false);
  assert.equal(invite({...base,roles:['issuer_operator'],issuerIds:['60000000-0000-4000-8000-000000000001']}),true);
  const patch=check('ChangeMembership');
  for(const body of [{},{reasonCode:'access_change'},{roles:['tenant_admin'],reasonCode:'access_change'},{issuerIds:[],reasonCode:'access_change'},{state:'deleted',reasonCode:'access_change'},{state:'revoked',reasonCode:'free text with PII'}])assert.equal(patch(body),false,JSON.stringify(body));
  assert.ok(patch({state:'suspended',reasonCode:'security_response'}));
  assert.ok(patch({roles:['security_admin'],issuerIds:[],reasonCode:'access_change'}));
  const accept=check('AcceptInvitation');
  assert.ok(accept({token:'A'.repeat(43)}));
  for(const token of ['', 'a'.repeat(42),'a'.repeat(44),'='.repeat(43)])assert.equal(accept({token}),false);
  assert.equal(accept({token:'A'.repeat(43),tenantId:'guessed-tenant',emailVerified:true}),false);
});

test('invitation response state and Problem status cannot contradict their evidence',()=>{
  const invitation=contract.paths['/v1/operator/tenants/{tenantId}/invitations'].post.responses['201'].content['application/json'].example;
  const validate=check('Invitation');
  assert.ok(validate(invitation));
  assert.equal(validate({...invitation,state:'accepted'}),false);
  assert.equal(validate({...invitation,state:'revoked'}),false);
  assert.equal(validate({...invitation,token:'A'.repeat(43)}),false);
  const lastAdmin=contract.paths['/v1/operator/tenants/{tenantId}/memberships/{membershipId}'].patch.responses['409'].content['application/problem+json'].example;
  assert.equal(lastAdmin.code,'last_admin_required');assert.ok(check('Problem')(lastAdmin));
  assert.equal(check('Problem')({...lastAdmin,status:403}),false);
  const acceptance=contract.paths['/v1/operator/invitation-acceptances'].post;
  assert.equal(acceptance.responses['409'].content['application/problem+json'].example.code,'invitation_invalid');
  assert.equal(acceptance.responses['404'],undefined);
});

test('explicit test policy rejects missing values, unsafe flags and unsupported deployment profiles',()=>{
  const validate=ajv.compile(read('src/platform/contracts/user-management-policy.schema.json'));
  assert.ok(validate(policy));
  for(const name of Object.keys(policy)){const missing={...policy};delete missing[name];assert.equal(validate(missing),false,name);}
  for(const change of [{environment:'production'},{notification:'smtp'},{emailProfile:'lowercase-everything'},{maxPageSize:101},{emailEvidenceSeconds:0},{reentry:'restore-old-roles'},{defaultRoles:['tenant_admin']}])assert.equal(validate({...policy,...change}),false);
});
