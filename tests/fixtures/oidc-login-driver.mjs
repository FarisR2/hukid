// Private stdin/stdout protocol for Go integration tests. Never starts with Platform.
import { createInterface } from 'node:readline';
import { startTestIdp } from './oidc-provider.mjs';

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
let idp, policy;
const reply = value => process.stdout.write(`${JSON.stringify(value)}\n`);
try {
  for await (const line of lines) {
    const command = JSON.parse(line);
    if (command.action === 'start') {
      policy = command.policy;
      idp = await startTestIdp(policy);
      reply({ clientSecret: idp.clientSecret });
    } else if (command.action === 'authorize') {
      let current = new URL(command.url);
      const cookies = new Map();
      let complete = false;
      for (let count = 0; count < 12; count++) {
        if (current.origin !== policy.issuer) {
          if (!current.href.startsWith(`${policy.redirectUri}?`)) throw new Error('Unexpected callback');
          reply({ callback: current.href }); complete = true; break;
        }
        const headers = { cookie: [...cookies].map(([k,v]) => `${k}=${v}`).join('; ') };
        if (current.pathname.startsWith('/interaction/')) headers['X-Hukid-Test-Interaction'] = idp.interactionKey;
        const response = await fetch(current, { redirect: 'manual', headers, signal: AbortSignal.timeout(5000) });
        for (const cookie of response.headers.getSetCookie()) {
          const pair = cookie.split(';')[0], index = pair.indexOf('=');
          cookies.set(pair.slice(0,index),pair.slice(index+1));
        }
        if (![302,303].includes(response.status)) throw new Error('Unexpected IdP response');
        current = new URL(response.headers.get('location'), current);
      }
      if (!complete) throw new Error('Too many redirects');
    } else if (command.action === 'stop') { await idp.close(); idp = undefined; reply({ stopped: 'true' }); break; }
    else throw new Error('Unknown test command');
  }
} catch { reply({ error: 'Isolated OIDC test driver failed' }); process.exitCode = 1; }
finally { if (idp) await idp.close(); lines.close(); }
