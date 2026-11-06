import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import type { Identity } from '../authentication/client';
import { date, errorMessage, itemId, list, roleNames, roles, states } from './client';
import type { Kind, Page, RecordItem, Role } from './client';
import { EditForm, InviteForm } from './forms';

export function MemberManagement({ identity, onChanged }: { identity: Identity; onChanged: () => void }) {
  const [kind, setKind] = useState<Kind>('memberships');
  const [page, setPage] = useState<Page | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [filters, setFilters] = useState({ state: '', role: '', query: '', deliveryState: '' });
  const [applied, setApplied] = useState(new URLSearchParams({ limit: '25' }));
  const [cursor, setCursor] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [editing, setEditing] = useState<RecordItem | null>(null);
  const [inviting, setInviting] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const caps = identity.context?.capabilities ?? [];
  const canRead = caps.includes(kind === 'memberships' ? 'members:read' : 'invitations:read');

  useEffect(() => {
    setPage(null); setError('');
    if (!canRead) return;
    const controller = new AbortController();
    setBusy(true);
    const params = new URLSearchParams(applied);
    if (cursor) params.set('cursor', cursor);
    void list(identity, kind, params, AbortSignal.any([controller.signal, AbortSignal.timeout(12000)]))
      .then(result => { if (!controller.signal.aborted) setPage(result); })
      .catch(cause => { if (!controller.signal.aborted) setError(errorMessage(cause)); })
      .finally(() => { if (!controller.signal.aborted) setBusy(false); });
    return () => controller.abort();
  }, [kind, applied, cursor, refresh, canRead, identity]);

  function changeKind(value: Kind) {
    setKind(value); setCursor(''); setPage(null); setError(''); setNotice('');
    setEditing(null); setInviting(false); setFilters({ state: '', role: '', query: '', deliveryState: '' });
    setApplied(new URLSearchParams({ limit: '25' }));
  }
  function filter(event: FormEvent) {
    event.preventDefault();
    const params = new URLSearchParams({ limit: '25' });
    for (const [key, value] of Object.entries(filters)) if (value) params.set(key, value);
    setCursor(''); setApplied(params);
  }
  function close() { setEditing(null); setInviting(false); heading.current?.focus(); }
  function done() {
    close(); setNotice('Cambio confirmado. El listado se actualizará con los datos actuales.');
    setCursor(''); setRefresh(value => value + 1); onChanged();
  }
  const edit = editing || inviting;
  return <section className="management" aria-labelledby="members-title">
    <div className="section-heading"><div><span className="eyebrow">Control de acceso</span>
      <h2 id="members-title" tabIndex={-1} ref={heading}>Miembros e invitaciones</h2>
      <p>Gestiona el acceso a esta organización. Los cambios se comprueban al guardar.</p></div>
      {!edit && kind === 'invitations' && caps.includes('members:invite') && <button className="primary" onClick={() => setInviting(true)}>Invitar persona</button>}
    </div>
    {notice && <p role="status">{notice}</p>}
    {!edit && <><div className="actions" role="group" aria-label="Directorio de acceso">
      <button aria-pressed={kind === 'memberships'} onClick={() => changeKind('memberships')}>Miembros</button>
      <button aria-pressed={kind === 'invitations'} onClick={() => changeKind('invitations')}>Invitaciones</button>
    </div>
    {!canRead ? <p role="status" className="data-feedback">No tienes permiso para consultar {kind === 'memberships' ? 'miembros' : 'invitaciones'}. Contacta con el administrador si necesitas acceso.</p> : <>
      <form className="filters" onSubmit={filter}>
        <label>Filtrar por estado<select value={filters.state} onChange={e => setFilters({ ...filters, state: e.target.value })}>
          <option value="">Todos los estados</option>{(kind === 'memberships' ? ['active', 'suspended', 'revoked'] : ['pending', 'accepted', 'revoked', 'expired']).map(s => <option key={s} value={s}>{states[s]}</option>)}
        </select></label>
        <label>Filtrar por rol<select value={filters.role} onChange={e => setFilters({ ...filters, role: e.target.value })}>
          <option value="">Todos los roles</option>{(Object.keys(roles) as Role[]).map(r => <option key={r} value={r}>{roles[r]}</option>)}
        </select></label>
        {kind === 'memberships' ? <label>Buscar por identificador<input value={filters.query} minLength={8} maxLength={36}
          pattern="[0-9a-f]{8}(-[0-9a-f]{0,4}|-[0-9a-f]{4}-[0-9a-f]{0,4}|-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{0,4}|-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{0,12})?"
          aria-describedby="query-help" onChange={e => setFilters({ ...filters, query: e.target.value })} /><span id="query-help" className="muted">Prefijo del ID, mínimo 8 caracteres.</span></label> :
          <label>Filtrar por entrega<select value={filters.deliveryState} onChange={e => setFilters({ ...filters, deliveryState: e.target.value })}>
            <option value="">Todas las entregas</option>{['queued', 'sent', 'failed'].map(s => <option key={s} value={s}>{states[s]}</option>)}
          </select></label>}
        <button>Aplicar filtros</button>
      </form>
      <div className="actions"><button onClick={() => { setCursor(''); setRefresh(v => v + 1); }}>Actualizar listado</button>
        <button onClick={() => changeKind(kind)}>Limpiar filtros</button></div>
      <div className="directory" aria-busy={busy}>
        {busy && <p role="status" className="data-feedback">Cargando {kind === 'memberships' ? 'miembros' : 'invitaciones'}…</p>}
        {error && <p role="alert" className="field-error data-feedback">{error}</p>}
        {page && <><p role="status">{page.items.length} registros en esta página. {page.nextCursor ? 'Hay más resultados.' : 'Fin de los resultados.'}</p>
          {!page.items.length ? <p className="data-feedback">No hay {kind === 'memberships' ? 'miembros' : 'invitaciones'} con estos filtros. Limpia los filtros para ver todos los registros.</p> :
            <ul className="record-list">{page.items.map(item => <li key={itemId(item)}>
              <div className="record-summary"><span className="record-id">{itemId(item)}</span>
                <span className="badge">{states[item.state]}</span>
                {'deliveryState' in item && <span className="badge">{states[item.deliveryState]}</span>}</div>
              <p>{roleNames(item.roles)}</p>
              {'operatorIdentityId' in item ? <p className="muted record-id">Identidad: {item.operatorIdentityId}</p> : <>
                <p className="muted">Destinatario protegido · Vence: {date(item.expiresAt)}</p>
                <p className="muted">Una entrega enviada no acredita aceptación. Si falló o expiró, crea una invitación nueva con el correo autorizado.</p></>}
              {item.issuerIds.length > 0 && <p className="muted record-id">Emisores asignados: {item.issuerIds.join(', ')}</p>}
              <div className="record-footer"><span className="muted">Revisión {item.revision}</span>
                {kind === 'memberships' && item.state !== 'revoked' && caps.includes('members:update') && <button aria-label={`Editar acceso ${itemId(item)}`} onClick={() => setEditing(item)}>Editar acceso</button>}
                {kind === 'invitations' && item.state === 'pending' && caps.includes('invitations:revoke') && <button className="danger" aria-label={`Revocar invitación ${itemId(item)}`} onClick={() => setEditing(item)}>Revocar invitación</button>}
              </div></li>)}</ul>}
          <div className="actions">{cursor && <button onClick={() => setCursor('')}>Volver al inicio</button>}
            {page.nextCursor && <button onClick={() => { setCursor(page.nextCursor!); heading.current?.focus(); }}>Siguiente página</button>}</div>
        </>}
        {error && <button onClick={() => { setCursor(''); setRefresh(v => v + 1); }}>Reintentar desde el inicio</button>}
      </div>
    </>}
    </>}
    {inviting && <InviteForm identity={identity} onDone={done} onCancel={close} />}
    {editing && <EditForm identity={identity} item={editing} kind={kind} onDone={done} onCancel={close} />}
  </section>;
}
