import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync, unlinkSync, openSync, closeSync, existsSync, createReadStream } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { once } from 'node:events';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const windows = process.platform === 'win32';
const portable = path.join(root,'.cache','toolchains','postgresql-18.6-5','pgsql','bin');
const directory = process.env.HUKID_PG_BIN || (windows && existsSync(portable) ? portable : '');
const executable = name => directory ? path.join(directory,windows ? `${name}.exe` : name) : name;
function run(name,args,options={}) {
  const result=spawnSync(executable(name),args,{cwd:root,encoding:'utf8',windowsHide:true,...options});
  if(result.error || result.status!==0) throw new Error(`${name} failed; inspect the isolated test log. PostgreSQL 18.6 is required (HUKID_PG_BIN).`);
  return result.stdout;
}
const archive=path.join(root,'.cache','toolchains','postgresql-18.6-5-windows-x64-binaries.zip');
if(directory===portable && existsSync(archive)) {
  const hash=createHash('sha256');
  for await (const chunk of createReadStream(archive)) hash.update(chunk);
  if(hash.digest('hex')!=='e2246ba91d22345bc3d017586c09ede52d9df180b1eeb480f050445f1cad84e2') throw new Error('PostgreSQL archive checksum mismatch');
}
const version=run('postgres',['--version']).trim();
if(!/\b18\.6\b/.test(version)) throw new Error('PostgreSQL 18.6 is required');
const base=path.join(root,'.cache','postgres-tests');mkdirSync(base,{recursive:true});
const scratch=mkdtempSync(path.join(base,'run-'));
const data=path.join(scratch,'data');
const password=randomBytes(32).toString('hex');
const passwordFile=path.join(scratch,'init-password');
writeFileSync(passwordFile,password,{mode:0o600});
try {run('initdb',['-D',data,'-U','hukid_test_admin','--pwfile',passwordFile,'--auth=scram-sha-256','--encoding=UTF8','--locale=C']);}
finally {unlinkSync(passwordFile);}
const probe=createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');
const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));
const logFile=path.join(scratch,'postgres.log');const log=openSync(logFile,'a');
let failure;
const server=spawn(executable('postgres'),['-D',data,'-h','127.0.0.1','-p',String(port),'-c','log_statement=none','-c','log_min_error_statement=panic'],{cwd:root,windowsHide:true,stdio:['ignore',log,log]});
server.on('error',error=>{failure=error;});
try {
  let ready=false;
  for(let attempt=0;attempt<100;attempt++) {
    if(failure || server.exitCode!==null) throw new Error('Isolated PostgreSQL failed to start');
    const probe=spawnSync(executable('pg_isready'),['-h','127.0.0.1','-p',String(port),'-U','hukid_test_admin','-d','postgres'],{windowsHide:true,stdio:'ignore'});
    if(probe.status===0){ready=true;break;}
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  if(!ready) throw new Error('PostgreSQL startup timeout');
  const admin=new URL(`postgresql://127.0.0.1:${port}/postgres?sslmode=disable`);admin.username='hukid_test_admin';admin.password=password;
  console.log(`${version}; disposable loopback cluster; no existing database is used.`);
  const result=spawnSync(process.execPath,['scripts/platform.mjs','test:postgres'],{cwd:root,env:{...process.env,HUKID_ENV:'test',HUKID_TEST_DATABASE:'1',HUKID_TEST_ADMIN_URL:admin.href},stdio:'inherit',windowsHide:true});
  if(result.error || result.status!==0) throw new Error('PostgreSQL integration tests failed');
} finally {
  // This unique data directory was created by this process; never stop another cluster.
  const stopped=spawnSync(executable('pg_ctl'),['-D',data,'-m','fast','-w','stop'],{cwd:root,windowsHide:true,stdio:'ignore',timeout:20000});
  closeSync(log);
  if(stopped.status!==0 && server.exitCode===null) throw new Error(`Could not stop the owned PostgreSQL test cluster; inspect ${logFile}`);
}
