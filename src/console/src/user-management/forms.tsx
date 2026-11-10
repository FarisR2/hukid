import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { request } from '../authentication/client';
import type { Identity } from '../authentication/client';
import { directoryPath, errorMessage, isInvitationCode, itemId, list, reasons, roleNames, roles, states } from './client';
import type { Kind, Membership, Reason, RecordItem, Role } from './client';

function FormHeading({ id, children }: { id: string; children: ReactNode }) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  return <h3 id={id} tabIndex={-1} ref={heading}>{children}</h3>;
}

// Edit panel: a native modal dialog docked to the right, so focus trapping, Escape and the
// backdrop come from the platform. Focus returns to the control that opened it.
export function SidePanel({ label, onClose, children }: { label: string; onClose: () => void; children: ReactNode }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useLayoutEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    dialog.current?.showModal();
    return () => { dialog.current?.close(); if (opener?.isConnected) opener.focus(); };
  }, []);
  return <dialog ref={dialog} className="side-panel" aria-label={label}
    onCancel={e => { e.preventDefault(); onClose(); }}
    onClick={e => { if (e.target === dialog.current) onClose(); }}>{children}</dialog>;
}

// Short forms (invite, accept) open as a native modal dialog centered over the page.
export function FormDialog({ label, onClose, children }: { label: string; onClose: () => void; children: ReactNode }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useLayoutEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    dialog.current?.showModal();
    return () => { dialog.current?.close(); if (opener?.isConnected) opener.focus(); };
  }, []);
  return <dialog ref={dialog} className="form-dialog" aria-label={label}
    onCancel={e => { e.preventDefault(); onClose(); }}>{children}</dialog>;
}

export function useCommand() {
  const controller = useRef(new AbortController());
  const pending = useRef(false);
  const attempt = useRef({ fingerprint: '', key: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    controller.current = new AbortController();
    return () => controller.current.abort();
  }, []);
  async function send(path: string, identity: Identity, body: object, method: 'POST' | 'PATCH', revision?: number) {
    if (pending.current) return null;
    pending.current = true; setBusy(true); setError('');
    const signal = AbortSignal.any([controller.current.signal, AbortSignal.timeout(12000)]);
    const fingerprint = JSON.stringify([path, body, method, revision]);
    if (attempt.current.fingerprint !== fingerprint) attempt.current = { fingerprint, key: crypto.randomUUID() };
    try {
      const response = await request(path, signal, identity.csrfToken, body, { method, key: attempt.current.key, ...(revision ? { revision } : {}) });
      signal.throwIfAborted();
      attempt.current = { fingerprint: '', key: '' };
      return response;
    } catch (cause) {
      if (!controller.current.signal.aborted) setError(errorMessage(cause));
      throw cause;
    } finally {
      pending.current = false;
      if (!controller.current.signal.aborted) setBusy(false);
    }
  }
  return { send, busy, error, setError };
}

export function RoleFields({ value, onChange }: { value: Role[]; onChange: (value: Role[]) => void }) {
  return <fieldset><legend>Roles</legend><div className="role-options">{(Object.keys(roles) as Role[]).map(role =>
    <label className="check" key={role}><input type="checkbox" checked={value.includes(role)} disabled={role === 'issuer_operator' && !value.includes(role)}
      onChange={e => onChange(e.target.checked ? [...value, role].sort() : value.filter(r => r !== role))} />{roles[role]}</label>)}</div>
    <p className="muted">La asignación de emisores todavía no está disponible. Los alcances existentes se conservan al cambiar sólo el estado.</p></fieldset>;
}

export function ReasonField({ value, onChange }: { value: Reason; onChange: (value: Reason) => void }) {
  return <label>Razón del cambio<select value={value} onChange={e => onChange(e.target.value as Reason)}>
    {(Object.keys(reasons) as Reason[]).map(reason => <option key={reason} value={reason}>{reasons[reason]}</option>)}
  </select></label>;
}

export function Confirm({ children, busy, onCancel, onConfirm, destructive = false }: {
  children: ReactNode; busy: boolean; onCancel: () => void; onConfirm: () => void; destructive?: boolean;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  // Captured during render: by the time an effect runs, autoFocus has already moved focus to
  // "Volver a editar", which would make that button its own opener.
  const [opener] = useState(() => document.activeElement as HTMLElement | null);
  useEffect(() => {
    dialog.current?.showModal();
    return () => { dialog.current?.close(); if (opener?.isConnected) opener.focus(); };
  }, [opener]);
  // React bubbles `cancel` through the component tree, so without stopPropagation Escape here would
  // also reach the SidePanel that hosts this confirmation and discard the whole edit draft.
  return <dialog ref={dialog} aria-labelledby="confirm-title" onCancel={e => { e.preventDefault(); e.stopPropagation(); if (!busy) onCancel(); }}>
    <h2 id="confirm-title">Confirmar cambio de acceso</h2>{children}
    <div className="actions"><button type="button" autoFocus onClick={onCancel} disabled={busy}>Volver a editar</button>
      <button type="button" className={destructive ? 'danger' : 'primary'} onClick={onConfirm} disabled={busy}>{busy ? 'Guardando…' : 'Confirmar cambio'}</button></div>
  </dialog>;
}

export function InviteForm({ identity, onDone, onCancel }: { identity: Identity; onDone: () => void; onCancel: () => void }) {
  const [email, setEmail] = useState('');
  const [emailError, setEmailError] = useState('');
  const [selected, setSelected] = useState<Role[]>(['support_readonly']);
  const command = useCommand();
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected.length) { command.setError('Selecciona al menos un rol.'); return; }
    try {
      if (await command.send(directoryPath(identity, 'invitations'), identity, { email, roles: selected, issuerIds: [] }, 'POST')) onDone();
    } catch { /* The command owns safe error feedback and the retained attempt. */ }
  }
  return <form onSubmit={e => void submit(e)} className="editor" aria-labelledby="invite-title">
    <FormHeading id="invite-title">Invitar a una persona</FormHeading>
    <p>Una invitación nueva sustituye cualquier invitación pendiente para el mismo correo en esta organización.</p>
    <fieldset disabled={command.busy}><label>Correo del destinatario<input type="email" required maxLength={254} value={email}
      autoComplete="off" aria-invalid={!!emailError} aria-describedby={emailError ? 'email-error' : undefined}
      onBlur={e => setEmailError(e.target.validity.valid ? '' : 'Introduce un correo válido, por ejemplo persona@example.invalid.')}
      onChange={e => { setEmail(e.target.value); if (emailError) setEmailError(e.target.validity.valid ? '' : emailError); }} /></label>
      {emailError && <p id="email-error" className="field-error" role="alert">{emailError}</p>}
      <RoleFields value={selected} onChange={setSelected} /></fieldset>
    {command.error && <p role="alert" className="field-error">{command.error}</p>}
    <div className="actions"><button className="primary" disabled={command.busy}>{command.busy ? 'Creando…' : 'Crear invitación'}</button><button type="button" onClick={onCancel} disabled={command.busy}>Cancelar invitación</button></div>
  </form>;
}

export function EditForm({ identity, item, kind, onDone, onCancel }: {
  identity: Identity; item: RecordItem; kind: Kind; onDone: () => void; onCancel: () => void;
}) {
  const [base, setBase] = useState(item);
  const [selected, setSelected] = useState(item.roles);
  const [state, setState] = useState(item.state);
  const [reason, setReason] = useState<Reason>(kind === 'invitations' ? 'invitation_cancelled' : 'access_change');
  const [confirm, setConfirm] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [comparison, setComparison] = useState('');
  const [unavailable, setUnavailable] = useState(false);
  const [lastAdmin, setLastAdmin] = useState('');
  const controller = useRef(new AbortController());
  useEffect(() => { controller.current = new AbortController(); return () => controller.current.abort(); }, []);
  const command = useCommand();
  const rolesChanged = [...selected].sort().join() !== [...base.roles].sort().join();
  const destructive = kind === 'invitations' || state !== 'active' || rolesChanged;
  const target = itemId(item);
  const proposal = JSON.stringify([selected, state, reason]);
  const blocked = kind === 'memberships' && lastAdmin === proposal;

  async function reload() {
    setReloading(true);
    try {
      const signal = AbortSignal.any([controller.current.signal, AbortSignal.timeout(12000)]);
      const filters = new URLSearchParams({ limit: '100', ...(kind === 'memberships' ? { query: target } : {}) });
      let found: RecordItem | undefined;
      do {
        const page = await list(identity, kind, filters, signal);
        found = page.items.find(candidate => itemId(candidate) === target);
        if (found || !page.nextCursor) break;
        filters.set('cursor', page.nextCursor);
      } while (!signal.aborted);
      signal.throwIfAborted();
      if (!found) { setUnavailable(true); command.setError('El registro ya no está disponible. Vuelve al listado.'); return; }
      setBase(found);
      setComparison(`Versión actual ${found.revision}: ${states[found.state]}; ${roleNames(found.roles)}. Tu propuesta sigue en el formulario. Revisa las diferencias antes de confirmar.`);
      setConflict(false); command.setError('');
      if (found.state === 'revoked' || (kind === 'invitations' && found.state !== 'pending')) setUnavailable(true);
    } catch (cause) { if (!controller.current.signal.aborted) command.setError(errorMessage(cause)); }
    finally { if (!controller.current.signal.aborted) setReloading(false); }
  }

  function review(event: FormEvent) {
    event.preventDefault(); command.setError('');
    if (kind === 'memberships' && (!selected.length || (rolesChanged && selected.includes('issuer_operator')))) {
      command.setError('Selecciona al menos un rol. La asignación de emisores no está disponible.'); return;
    }
    if (kind === 'memberships' && !rolesChanged && state === base.state) { command.setError('Cambia los roles o el estado antes de guardar.'); return; }
    setConfirm(true);
  }
  async function save() {
    try {
      const body = kind === 'invitations' ? { reasonCode: reason } : { reasonCode: reason,
        ...(rolesChanged ? { roles: selected, issuerIds: [] } : {}), ...(state !== base.state ? { state } : {}) };
      const path = `${directoryPath(identity, kind)}/${target}${kind === 'invitations' ? '/revocations' : ''}`;
      if (await command.send(path, identity, body, kind === 'invitations' ? 'POST' : 'PATCH', base.revision)) onDone();
    } catch (cause) {
      if (cause instanceof Error && 'status' in cause && cause.status === 412) setConflict(true);
      if (cause instanceof Error && 'code' in cause && cause.code === 'last_admin_required') setLastAdmin(proposal);
      setConfirm(false);
    }
  }
  return <form className="editor" onSubmit={review} aria-labelledby="edit-title">
    <FormHeading id="edit-title">{kind === 'memberships' ? 'Editar acceso' : 'Revocar invitación'}</FormHeading>
    <p className="record-id">Objetivo: {target}</p>
    <p>Revisión {base.revision} · {states[base.state]} · {roleNames(base.roles)}</p>
    {comparison && <p role="status">{comparison}</p>}
    {unavailable && <p role="status">Este registro ya no admite cambios. La revocación es definitiva; el reingreso requiere una invitación nueva.</p>}
    <fieldset disabled={command.busy || reloading || unavailable}>
      {kind === 'memberships' && <><RoleFields value={selected} onChange={setSelected} />
        <label>Estado del acceso<select value={state} onChange={e => setState(e.target.value as Membership['state'])}>
          <option value="active">Activo</option><option value="suspended">Suspendido</option>
          {identity.context?.capabilities.includes('members:revoke') && <option value="revoked">Revocado</option>}
        </select></label></>}
      <ReasonField value={reason} onChange={setReason} />
    </fieldset>
    {command.error && <p role="alert" className="banner banner-err">{command.error}</p>}
    {blocked && <p id="last-admin-help" className="muted">Este cambio dejaría la organización sin administrador activo. Modifica los roles, el estado o la razón, o asigna antes otro administrador.</p>}
    <div className="actions">
      {!unavailable && !conflict && <button className={destructive ? 'danger' : 'primary'} disabled={command.busy || reloading || blocked} aria-describedby={blocked ? 'last-admin-help' : undefined}>Revisar cambio</button>}
      {conflict && <button type="button" onClick={() => void reload()} disabled={reloading}>{reloading ? 'Cargando…' : 'Cargar versión actual'}</button>}
      <button type="button" onClick={onCancel} disabled={command.busy}>Volver al listado</button>
    </div>
    {confirm && <Confirm busy={command.busy} onCancel={() => setConfirm(false)} onConfirm={() => void save()} destructive={destructive}>
      <p className="record-id">Objetivo: {target}</p><p>Razón: {reasons[reason]}.</p>
      <p>{kind === 'invitations' ? 'La invitación dejará de permitir el acceso.' : `Estado propuesto: ${states[state]}. Roles: ${roleNames(selected)}.`}</p>
      {kind === 'memberships' && rolesChanged && base.issuerIds.length > 0 && <>
        <p>Este cambio retirará los alcances de emisores existentes. La persona perderá el acceso de operación a estos emisores:</p>
        <ul>{base.issuerIds.map(id => <li className="record-id" key={id}>{id}</li>)}</ul>
      </>}
      {state === 'revoked' && <p>La revocación es definitiva. Para volver a acceder necesitará una invitación nueva.</p>}
    </Confirm>}
  </form>;
}

export function Acceptance({ identity, initialToken, onDone }: { identity: Identity; initialToken: string; onDone: () => void }) {
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => { if (input.current) input.current.value = initialToken; }, [initialToken]);
  const [success, setSuccess] = useState(false);
  const [codeError, setCodeError] = useState('');
  const command = useCommand();
  function validateCode(): boolean {
    const valid = isInvitationCode(input.current?.value ?? '');
    setCodeError(valid ? '' : 'Introduce el código completo de la invitación.');
    return valid;
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    command.setError('');
    if (!validateCode()) { input.current?.focus(); return; }
    const token = input.current?.value ?? '';
    try {
      if (await command.send('/console/api/invitation-acceptances', identity, { token }, 'POST')) {
        if (input.current) input.current.value = '';
        setSuccess(true); onDone();
      }
    } catch { /* No token or recipient is reflected in error messages. */ }
  }
  return <section className="acceptance" aria-labelledby="accept-title"><h2 id="accept-title">Aceptar una invitación</h2>
    <p>Usa la cuenta cuyo correo recibió la invitación. Si necesitas iniciar sesión o verificar tu identidad, vuelve a abrirla después.</p>
    {success ? <p role="status">Invitación aceptada. Elige la organización para continuar.</p> : <form onSubmit={e => void submit(e)} noValidate>
      <label htmlFor="invitation-code">Código de invitación</label><input ref={input} id="invitation-code" type="password" autoComplete="off" maxLength={43}
        spellCheck={false} required aria-invalid={!!codeError} aria-describedby={codeError ? 'accept-help accept-error' : 'accept-help'}
        onBlur={() => { if (input.current?.value) validateCode(); }}
        onChange={() => { if (codeError) validateCode(); }} />
      <p id="accept-help" className="muted">El código permanece sólo mientras esta página esté abierta.</p>
      {codeError && <p id="accept-error" role="alert" className="field-error">{codeError}</p>}
      {command.error && <p role="alert" className="field-error">{command.error}</p>}
      <button disabled={command.busy}>{command.busy ? 'Aceptando…' : 'Aceptar invitación'}</button>
    </form>}
  </section>;
}
