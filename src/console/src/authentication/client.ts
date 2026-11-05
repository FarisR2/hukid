export interface Tenant { tenantId: string; displayName: string }
export interface Identity {
  actorId: string;
  tenants: Tenant[];
  activeTenantId: string | null;
  context: { tenantId: string; capabilities: string[]; issuerIds: string[]; authorizationRevision: number } | null;
  csrfToken: string;
}

export class AuthError extends Error {
  constructor(public status: number, public code: string) { super(code); }
}

export async function request(path: string, signal: AbortSignal, csrf?: string, body?: object): Promise<Response> {
  const send = () => fetch(path, {
    method: csrf ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
    redirect: 'error', signal,
    headers: { Accept: 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  // Share one request lane across tabs: /me touches activity and commands rotate
  // generations. No auth material travels through the lock manager.
  const response = await navigator.locks.request('hukid-session-request', { signal }, send);
  if (!response.ok) {
    const problem = await response.json().catch(() => null);
    throw new AuthError(response.status, typeof problem?.code === 'string' ? problem.code : 'unavailable');
  }
  return response;
}

export async function readIdentity(signal: AbortSignal): Promise<Identity> {
  const value: Identity = await (await request('/console/api/me', signal)).json();
  if (!value || typeof value.actorId !== 'string' || !Array.isArray(value.tenants) ||
      !value.tenants.every(t => t && typeof t.tenantId === 'string' && typeof t.displayName === 'string') ||
      !/^[A-Za-z0-9_-]{43}$/.test(value.csrfToken) ||
      (value.activeTenantId === null && value.context !== null) ||
      (value.activeTenantId !== null && (!value.context || value.context.tenantId !== value.activeTenantId ||
        !Array.isArray(value.context.capabilities) || !Array.isArray(value.context.issuerIds) ||
        !Number.isSafeInteger(value.context.authorizationRevision) ||
        !value.tenants.some(t => t.tenantId === value.activeTenantId)))) {
    throw new AuthError(503, 'invalid_response');
  }
  return value;
}

export async function navigate(response: Response, signal: AbortSignal): Promise<void> {
  const result: { authorizationUrl: string } = await response.json();
  const url = new URL(result.authorizationUrl);
  // The BFF constructs this URL from its configured IdP. Never take a returnTo from the address bar.
  if (url.username || url.password || (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === '127.0.0.1'))) {
    throw new AuthError(503, 'invalid_response');
  }
  signal.throwIfAborted();
  window.location.assign(url.href);
}
