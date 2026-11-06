import { useEffect, useRef, useState } from 'react';
import { Dashboard } from '../dashboard/Dashboard';
import { WorkspaceNavigation } from '../dashboard/WorkspaceNavigation';
import type { FormEvent } from 'react';
import { AuthError, navigate, readIdentity, request } from './client';
import type { Identity } from './client';
import { MemberManagement } from '../user-management/MemberManagement';
import { Acceptance } from '../user-management/forms';
import { discardInvitation, takeInvitation } from '../user-management/client';

type View = { kind: 'loading' | 'anonymous' | 'error'; title: string; message: string } |
  { kind: 'authenticated'; identity: Identity };

const loading: View = { kind: 'loading', title: 'Comprobando tu sesión', message: 'Espera un momento.' };
const anonymous: View = { kind: 'anonymous', title: 'Accede a HukID', message: 'Usa tu cuenta de operador para continuar. La verificación de identidad se realiza con tu proveedor de acceso.' };

function failure(error: unknown): View {
  if (error instanceof AuthError) {
    if (error.status === 401) return { kind: 'anonymous', title: 'Vuelve a iniciar sesión', message: 'Tu sesión no está disponible o ha vencido. Inicia sesión para continuar.' };
    if (error.code === 'step_up_required') return { kind: 'error', title: 'Verifica tu identidad', message: 'Necesitas una verificación reciente para continuar.' };
    if (error.status === 403) return { kind: 'error', title: 'No se pudo autorizar el acceso', message: 'Vuelve a comprobar tu sesión. Si persiste, inicia sesión de nuevo o contacta con tu administrador.' };
    if (error.status === 404 && error.code === 'tenant_not_found') return { kind: 'error', title: 'Organización no disponible', message: 'Tu acceso pudo cambiar. Inicia sesión de nuevo para elegir una organización autorizada.' };
    if (error.status === 429) return { kind: 'error', title: 'Demasiados intentos', message: 'Espera un momento antes de volver a intentarlo.' };
    if (error.status === 409) return { kind: 'error', title: 'Tu sesión cambió', message: 'Otra operación está actualizando la sesión. Comprueba el acceso antes de continuar.' };
  }
  return { kind: 'error', title: 'No pudimos conectar', message: 'Comprueba tu conexión y vuelve a intentarlo. No se ha confirmado el acceso.' };
}

export function AuthConsole() {
  const [view, setView] = useState<View>(loading);
  const [busy, setBusy] = useState(false);
  const [selection, setSelection] = useState('');
  const [formError, setFormError] = useState('');
  const [invitation, setInvitation] = useState('');
  const proof = useRef<string | undefined>(undefined);
  const current = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const locked = useRef(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const channel = useRef<BroadcastChannel | null>(null);

  function reset() {
    current.current?.abort();
    generation.current += 1;
    const controller = new AbortController();
    current.current = controller;
    setView(loading);
    setSelection('');
    setFormError('');
    return { controller, version: generation.current };
  }

  async function run(action: 'read' | 'login' | 'logout' | 'refresh' | 'tenant' | 'step-up', tenantId?: string) {
    if (locked.current) return;
    locked.current = true;
    setBusy(true);
    const { controller, version } = reset();
    const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(12000)]);
    const valid = () => version === generation.current && !controller.signal.aborted;
    try {
      if (action === 'login') {
        setInvitation(''); discardInvitation();
        await navigate(await request('/console/auth/login?returnTo=/', signal), signal);
        return;
      }
      if (action !== 'read') {
        if (!proof.current) throw new AuthError(401, 'invalid_session');
        const body = action === 'tenant' ? { tenantId } : action === 'step-up' ? { returnTo: '/' } : undefined;
        const path = action === 'tenant' ? 'tenant-context' : action;
        const response = await request(`/console/auth/${path}`, signal, proof.current, body);
        channel.current?.postMessage('session-changed');
        if (action === 'step-up') { setInvitation(''); discardInvitation(); await navigate(response, signal); return; }
        if (action === 'logout') {
          proof.current = undefined;
          if (valid()) setView({ kind: 'anonymous', title: 'Sesión cerrada', message: 'Has cerrado tu sesión de HukID. Puedes volver a acceder cuando lo necesites.' });
          return;
        }
      }
      const identity = await readIdentity(signal);
      if (valid()) {
        proof.current = identity.csrfToken;
        setSelection(identity.activeTenantId ?? (identity.tenants.length === 1 ? identity.tenants[0]!.tenantId : ''));
        setView({ kind: 'authenticated', identity });
      }
    } catch (error) {
      if (valid()) {
        if (error instanceof AuthError && error.status === 401 && action === 'read' && !proof.current) setView(anonymous);
        else setView(failure(error));
      }
    } finally {
      if (valid()) { locked.current = false; setBusy(false); }
    }
  }

  useEffect(() => {
    const incoming = takeInvitation();
    if (incoming) setInvitation(incoming);
    void run('read');
    const clear = () => {
      reset();
      locked.current = false;
      setBusy(false);
    };
    const restore = () => { if (!document.hidden) { clear(); void run('read'); } };
    const hide = () => { setInvitation(''); discardInvitation(); clear(); };
    const visibility = () => { if (document.hidden) hide(); else restore(); };
    const broadcast = new BroadcastChannel('hukid-session');
    channel.current = broadcast;
    broadcast.onmessage = () => { clear(); proof.current = undefined; if (!document.hidden) void run('read'); };
    document.addEventListener('visibilitychange', visibility);
    window.addEventListener('pagehide', hide);
    window.addEventListener('pageshow', restore);
    window.addEventListener('popstate', restore);
    return () => {
      current.current?.abort();
      generation.current += 1;
      locked.current = false;
      broadcast.close();
      document.removeEventListener('visibilitychange', visibility);
      window.removeEventListener('pagehide', hide);
      window.removeEventListener('pageshow', restore);
      window.removeEventListener('popstate', restore);
    };
  }, []);

  useEffect(() => {
    if (view.kind === 'anonymous' || view.kind === 'error') { setInvitation(''); discardInvitation(); }
  }, [view.kind]);

  async function updateContext() {
    const controller = current.current;
    const version = generation.current;
    if (!controller) return;
    try {
      const identity = await readIdentity(AbortSignal.any([controller.signal, AbortSignal.timeout(12000)]));
      if (version === generation.current && !controller.signal.aborted) {
        proof.current = identity.csrfToken;
        setView({ kind: 'authenticated', identity });
        setSelection(identity.activeTenantId ?? '');
        channel.current?.postMessage('session-changed');
      }
    } catch (error) {
      if (version === generation.current && !controller.signal.aborted) setView(failure(error));
    }
  }

  useEffect(() => { if (view.kind !== 'loading') heading.current?.focus(); }, [view]);

  function selectTenant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selection) { setFormError('Elige una organización para continuar.'); document.getElementById('tenant')?.focus(); return; }
    void run('tenant', selection);
  }

  const identity = view.kind === 'authenticated' ? view.identity : null;
  const active = identity?.tenants.find(t => t.tenantId === identity.activeTenantId);
  const title = view.kind === 'authenticated' ? (active ? active.displayName : identity!.tenants.length ? 'Elige una organización' : 'Acceso pendiente') : view.title;

  return <div className="app">
    <a className="skip" href="#content">Ir al contenido</a>
    <header className="header"><a className="brand" href="/" aria-label="HukID, inicio"><span className="brand-mark" aria-hidden="true">h.</span>HukID</a><span className="header-label">Consola de operadores</span></header>
    <main id="content" className="content workspace" aria-busy={busy}>
      <section className="access-panel" aria-labelledby="title">
        <span className="eyebrow">{active ? 'Tu organización' : 'Acceso de operadores'}</span>
        <h1 id="title" ref={heading} tabIndex={-1}>{title}</h1>
        {view.kind === 'loading' ? <p role="status">{view.message}</p> : view.kind !== 'authenticated' ? <>
          <p role={view.kind === 'error' ? 'alert' : 'status'}>{view.message}</p>
          <div className="actions">
            {view.kind === 'anonymous' ? <button className="primary" onClick={() => void run('login')} disabled={busy}>Iniciar sesión</button> : <>
              <button className="primary" onClick={() => void run('read')} disabled={busy}>Comprobar acceso</button>
              {proof.current && <button onClick={() => void run('refresh')} disabled={busy}>Renovar sesión</button>}
              {proof.current && <button onClick={() => void run('step-up')} disabled={busy}>Verificar identidad</button>}
              <button onClick={() => void run('login')} disabled={busy}>Iniciar sesión de nuevo</button>
            </>}
          </div>
        </> : <>
          <span className="badge">{active ? 'Sesión activa' : identity!.tenants.length ? 'Selección requerida' : 'Sin organización asignada'}</span>
          {!identity!.tenants.length ? <>
            <p>Tu identidad está verificada, pero todavía no tienes acceso a una organización. Solicita acceso a tu administrador.</p>
            <button className="primary" onClick={() => void run('read')} disabled={busy}>Comprobar acceso</button>
          </> : <>
            <p>{active ? 'Tu acceso a esta organización está confirmado. Puedes cambiar de organización o verificar de nuevo tu identidad.' : 'Selecciona la organización con la que quieres trabajar. Sólo aparecen aquellas a las que tienes acceso.'}</p>
            <form onSubmit={selectTenant} noValidate>
              <label htmlFor="tenant">Organización</label>
              <select id="tenant" value={selection} onChange={e => { setSelection(e.target.value); setFormError(''); }} aria-invalid={!!formError} aria-describedby={formError ? 'tenant-error' : undefined}>
                <option value="">Selecciona una organización</option>
                {identity!.tenants.map(tenant => <option key={tenant.tenantId} value={tenant.tenantId}>{tenant.displayName}</option>)}
              </select>
              {formError && <p id="tenant-error" className="field-error" role="alert">{formError}</p>}
              <button className={active ? '' : 'primary'} type="submit" disabled={busy}>{active ? 'Cambiar organización' : 'Continuar'}</button>
            </form>
            {active && <div className="session-details" key={`${identity!.actorId}:${active.tenantId}:${identity!.context!.authorizationRevision}`}>
              <h2>Tu sesión</h2><p>Verifica tu identidad para cambios de acceso que necesiten una confirmación reciente.</p>
              <div className="actions"><button onClick={() => void run('step-up')} disabled={busy}>Verificar identidad</button><button onClick={() => void run('refresh')} disabled={busy}>Renovar sesión</button><button onClick={() => void run('read')} disabled={busy}>Comprobar acceso</button></div>
            </div>}
          </>}
        </>}
        {proof.current && view.kind !== 'loading' && <div className="logout"><button className="quiet" onClick={() => void run('logout')} disabled={busy}>Cerrar sesión</button></div>}
      </section>
      <aside className="access-note"><span className="note-rule" aria-hidden="true"/><p>Un acceso.<br/><strong>El contexto correcto.</strong></p><p className="muted">Cada organización conserva su propio espacio de trabajo. Tu acceso se comprueba al continuar.</p></aside>
      {active && identity && <WorkspaceNavigation identity={identity} />}
      {active && identity && <Dashboard key={`${identity.actorId}:${active.tenantId}:${identity.context!.authorizationRevision}:${identity.context!.capabilities.join(',')}:${identity.context!.issuerIds.join(',')}`}
        identity={identity} onAccessError={status => {
          if (status === 401) { reset(); proof.current = undefined; locked.current = false; setBusy(false); setView(anonymous); }
          else void updateContext();
        }} />}
      {active && identity && identity.context!.capabilities.some(c => ['members:read', 'invitations:read'].includes(c)) && <MemberManagement key={`${identity.actorId}:${active.tenantId}:${identity.context!.authorizationRevision}`}
        identity={identity} onChanged={() => void updateContext()} />}
      {identity && <Acceptance key={identity.actorId} identity={identity} initialToken={invitation} onDone={() => { setInvitation(''); void updateContext(); }} />}
    </main>
    <footer className="footer">HukID · Administración de identidad</footer>
  </div>;
}
