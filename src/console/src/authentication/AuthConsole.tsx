// Spec: docs/03-design/console-auth-interface.md
import { useEffect, useRef, useState } from 'react';
import { Dashboard } from '../dashboard/Dashboard';
import { Shell } from '../shell/Shell';
import type { FormEvent } from 'react';
import { AuthError, navigate, readIdentity, request } from './client';
import type { Identity } from './client';
import { MemberManagement } from '../user-management/MemberManagement';
import { Acceptance, FormDialog } from '../user-management/forms';
import { discardInvitation, takeInvitation } from '../user-management/client';
import { restoreSection } from '../navigation';
import { Building2, Clock, KeyRound, LoaderCircle, Lock, Ticket, TriangleAlert, WifiOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Field, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';

type View = { kind: 'loading' | 'error'; title: string; message: string } |
  { kind: 'authenticated'; identity: Identity };

const loading: View = { kind: 'loading', title: 'Comprobando tu sesión', message: 'Espera un momento.' };
const interrupted: View = { kind: 'error', title: 'Acceso no completado', message: 'No se confirmó tu sesión. Inicia sesión de nuevo para continuar.' };

// There is no access page: opening the console without a session goes straight to the
// identity provider, which always asks for credentials. A second automatic attempt within
// a minute means the round trip is failing, so show the recovery view instead of looping.
const AUTO_KEY = 'hukid-auto-login';
const AUTO_WINDOW_MS = 60000;
function claimAutoLogin(): boolean {
  try {
    const last = Number(sessionStorage.getItem(AUTO_KEY));
    if (last && Date.now() - last < AUTO_WINDOW_MS) return false;
    sessionStorage.setItem(AUTO_KEY, String(Date.now()));
    return true;
  } catch { return false; }
}
function releaseAutoLogin() { try { sessionStorage.removeItem(AUTO_KEY); } catch { /* storage unavailable */ } }

function failure(error: unknown): View {
  if (error instanceof AuthError) {
    if (error.code === 'step_up_required') return { kind: 'error', title: 'Verifica tu identidad', message: 'Necesitas una verificación reciente para continuar.' };
    if (error.status === 403) return { kind: 'error', title: 'No se pudo autorizar el acceso', message: 'Vuelve a comprobar tu sesión. Si persiste, inicia sesión de nuevo o contacta con tu administrador.' };
    if (error.status === 404 && error.code === 'tenant_not_found') return { kind: 'error', title: 'Organización no disponible', message: 'Tu acceso pudo cambiar. Inicia sesión de nuevo para elegir una organización autorizada.' };
    if (error.status === 429) return { kind: 'error', title: 'Demasiados intentos', message: 'Espera un momento antes de volver a intentarlo.' };
    if (error.status === 409) return { kind: 'error', title: 'Tu sesión cambió', message: 'Otra operación está actualizando la sesión. Comprueba el acceso antes de continuar.' };
  }
  return { kind: 'error', title: 'No pudimos conectar', message: 'Comprueba tu conexión y vuelve a intentarlo. No se ha confirmado el acceso.' };
}

type Recovery = 'read' | 'login' | 'refresh' | 'step-up';
const recoveryLabels: Record<Recovery, string> = { read: 'Comprobar acceso', login: 'Iniciar sesión de nuevo', refresh: 'Renovar sesión', 'step-up': 'Verificar identidad' };

// Each recovery view offers only the actions that make sense for it, as in the prototype.
function recovery(title: string, hasSession: boolean): Recovery[] {
  if (title === 'Acceso no completado') return ['login'];
  if (title === 'Verifica tu identidad') return hasSession ? ['step-up'] : ['login'];
  if (title === 'No se pudo autorizar el acceso') return hasSession ? ['refresh', 'login'] : ['login'];
  if (title === 'Organización no disponible') return ['read', 'login'];
  return ['read'];
}

function sessionIcon(title: string) {
  if (title === 'No pudimos conectar') return { Icon: WifiOff, tone: 'warn' };
  if (title === 'Demasiados intentos') return { Icon: Clock, tone: 'warn' };
  if (title === 'No se pudo autorizar el acceso') return { Icon: Lock, tone: 'danger' };
  if (title === 'Organización no disponible') return { Icon: Building2, tone: 'warn' };
  if (title === 'Verifica tu identidad') return { Icon: KeyRound, tone: '' };
  return { Icon: TriangleAlert, tone: 'danger' };
}

export function AuthConsole() {
  const [view, setViewState] = useState<View>(loading);
  const [workspaceLayout, setWorkspaceLayout] = useState(false);
  const [busy, setBusy] = useState(false);
  const [selection, setSelection] = useState('');
  const [formError, setFormError] = useState('');
  const [invitation, setInvitation] = useState('');
  const [accepting, setAccepting] = useState(false);
  const proof = useRef<string | undefined>(undefined);
  const current = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const locked = useRef(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const channel = useRef<BroadcastChannel | null>(null);

  function setView(next: View) {
    // Keep only the public layout shape while loading, never the old private UI.
    if (next.kind !== 'loading') setWorkspaceLayout(next.kind === 'authenticated');
    setViewState(next);
  }

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
    let autoLogin = false;
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
          if (valid()) { if (claimAutoLogin()) autoLogin = true; else setView(interrupted); }
          return;
        }
      }
      const identity = await readIdentity(signal);
      if (valid()) {
        proof.current = identity.csrfToken;
        releaseAutoLogin();
        setSelection(identity.activeTenantId ?? (identity.tenants.length === 1 ? identity.tenants[0]!.tenantId : ''));
        setView({ kind: 'authenticated', identity });
      }
    } catch (error) {
      if (valid()) {
        if (error instanceof AuthError && error.status === 401) {
          proof.current = undefined;
          if (claimAutoLogin()) autoLogin = true; else setView(interrupted);
        } else setView(failure(error));
      }
    } finally {
      if (valid()) { locked.current = false; setBusy(false); }
      // Inside finally so it also runs after the early `return` of logout.
      if (autoLogin) void run('login');
    }
  }

  useEffect(() => {
    const incoming = takeInvitation();
    if (incoming) { setInvitation(incoming); setAccepting(true); }
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
    if (view.kind === 'error') { setInvitation(''); discardInvitation(); }
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

  useEffect(() => {
    if (view.kind === 'loading') return;
    if (view.kind === 'authenticated' && view.identity.activeTenantId && restoreSection()) return;
    heading.current?.focus();
  }, [view]);

  function selectTenant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selection) { setFormError('Elige una organización para continuar.'); document.getElementById('tenant')?.focus(); return; }
    void run('tenant', selection);
  }

  const identity = view.kind === 'authenticated' ? view.identity : null;
  const active = identity?.tenants.find(t => t.tenantId === identity.activeTenantId);
  const title = view.kind === 'authenticated' ? (active ? active.displayName : identity!.tenants.length ? 'Elige una organización' : 'Acceso pendiente') : view.title;

  if (view.kind === 'authenticated' && active && identity) {
    const key = `${identity.actorId}:${active.tenantId}:${identity.context!.authorizationRevision}`;
    // Closing the dialog discards the in-memory code; it is never kept for a later reopening.
    const closeAcceptance = () => { setAccepting(false); setInvitation(''); discardInvitation(); };
    const accessError = (status: number) => {
      if (status === 401) { reset(); proof.current = undefined; locked.current = false; setBusy(false); if (claimAutoLogin()) void run('login'); else setView(interrupted); }
      else void updateContext();
    };
    return <Shell identity={identity} busy={busy}
      onSelectTenant={id => void run('tenant', id)} onLogout={() => void run('logout')}
      onRefresh={() => void run('refresh')} onStepUp={() => void run('step-up')}
      onAccept={() => setAccepting(true)}>
      {current => <>
        {(current.id === 'resumen' || current.id === 'actividad') && <Dashboard key={`${key}:${identity.context!.capabilities.join(',')}:${identity.context!.issuerIds.join(',')}:${current.id}`}
          identity={identity} view={current.id} onAccessError={accessError} />}
        {(current.id === 'miembros' || current.id === 'invitaciones') && <MemberManagement key={`${key}:${current.id}`}
          identity={identity} kind={current.id === 'miembros' ? 'memberships' : 'invitations'} onChanged={() => void updateContext()} />}
        {accepting && <FormDialog label="Aceptar una invitación" onClose={closeAcceptance}>
          <Acceptance key={identity.actorId} identity={identity} initialToken={invitation} onDone={() => { setInvitation(''); void updateContext(); }} /></FormDialog>}
      </>}
    </Shell>;
  }

  // First session check: paint nothing until a view resolves, so no access-screen
  // remnant shows before the redirect. Kept in the DOM for assistive tech.
  const checking = view.kind === 'loading' && !workspaceLayout;
  const needsSelection = view.kind === 'authenticated' && !active && identity!.tenants.length > 0;
  const pending = view.kind === 'authenticated' && !identity!.tenants.length;
  const visual = view.kind === 'loading' ? { Icon: LoaderCircle, tone: '' } : view.kind === 'error' ? sessionIcon(view.title)
    : needsSelection ? { Icon: Building2, tone: '' } : { Icon: Clock, tone: '' };
  const Icon = visual.Icon;
  return <div className={checking ? 'session-screen opacity-0' : 'session-screen'}>
    <a className="skip" href="#content">Ir al contenido</a>
    <div className="sess">
      <div className="sess-brand"><span className="brand-mark" aria-hidden="true">h.</span><b>HukID</b><span>Consola de operadores</span></div>
      <main id="content" className="sess-card" role={view.kind === 'error' && visual.tone === 'danger' ? 'alert' : undefined} aria-busy={busy} tabIndex={-1}>
        <span className={`sess-ic ${visual.tone}`} aria-hidden="true"><Icon className={view.kind === 'loading' ? 'animate-spin motion-reduce:animate-none' : undefined} /></span>
        <h1 id="title" ref={heading} tabIndex={-1}>{title}</h1>
        {view.kind === 'loading' ? <p role="status">{view.message}</p> : view.kind === 'error' ? <>
          <p>{view.message}</p>
          <div className="actions">{recovery(view.title, !!proof.current).map((action, index) =>
            <Button key={action} type="button" variant={index ? 'outline' : 'default'} onClick={() => void run(action)} disabled={busy}>{recoveryLabels[action]}</Button>)}</div>
        </> : pending ? <>
          <span className="badge">Sin organización asignada</span>
          <p>Tu cuenta aún no pertenece a ninguna organización. Contacta a un administrador de tu institución para que te invite.</p>
          <div className="actions">
            <Button type="button" variant="outline" onClick={() => void run('logout')} disabled={busy}>Cerrar sesión</Button>
            <Button type="button" variant="ghost" className="max-w-full whitespace-normal" onClick={() => setAccepting(true)}><Ticket aria-hidden="true" />Tengo un código de invitación</Button>
          </div>
        </> : <>
          <span className="badge">Selección requerida</span>
          <p>Selecciona la organización con la que quieres trabajar. Sólo aparecen aquellas a las que tienes acceso. Podrás cambiarla después desde el menú lateral.</p>
          <form onSubmit={selectTenant} noValidate>
            <FieldGroup>
              <Field data-invalid={!!formError}>
                <FieldLabel htmlFor="tenant">Organización</FieldLabel>
                <NativeSelect id="tenant" value={selection} onChange={e => { setSelection(e.target.value); setFormError(''); }} aria-invalid={!!formError} aria-describedby={formError ? 'tenant-error' : undefined}>
                  <NativeSelectOption value="">Selecciona una organización</NativeSelectOption>
                  {identity!.tenants.map(tenant => <NativeSelectOption key={tenant.tenantId} value={tenant.tenantId}>{tenant.displayName}</NativeSelectOption>)}
                </NativeSelect>
                {formError && <FieldError id="tenant-error">{formError}</FieldError>}
              </Field>
              <div className="actions">
                <Button type="submit" disabled={busy}>Continuar</Button>
                <Button type="button" variant="outline" onClick={() => void run('logout')} disabled={busy}>Cerrar sesión</Button>
                <Button type="button" variant="ghost" className="max-w-full whitespace-normal" onClick={() => setAccepting(true)}><Ticket aria-hidden="true" />Tengo un código de invitación</Button>
              </div>
            </FieldGroup>
          </form>
        </>}
      </main>
      <p className="sess-foot">El inicio de sesión lo gestiona el proveedor de identidad de tu institución.</p>
    </div>
    {accepting && identity && <FormDialog label="Aceptar una invitación" onClose={() => { setAccepting(false); setInvitation(''); discardInvitation(); }}>
      <Acceptance key={identity.actorId} identity={identity} initialToken={invitation} onDone={() => { setInvitation(''); void updateContext(); }} /></FormDialog>}
  </div>;
}
