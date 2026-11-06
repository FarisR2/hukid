import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const schema = JSON.parse(readFileSync(new URL('../../../src/platform/contracts/dashboard.schema.json',import.meta.url),'utf8'));
const ajv = new Ajv({allErrors:true,strictRequired:false});
addFormats(ajv);
ajv.addSchema(schema);
for (const {schema:name,value} of JSON.parse(readFileSync(0,'utf8'))) {
  const validate = ajv.compile({$ref:schema.$id+'#/$defs/'+name});
  assert.ok(validate(value),JSON.stringify(validate.errors));
}
