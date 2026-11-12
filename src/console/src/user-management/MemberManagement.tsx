import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import type { Identity } from '../authentication/client';
import { date, errorMessage, itemId, list, roleNames, roles, states } from './client';
import type { Kind, Page, RecordItem, Role } from './client';
import { EditForm, FormDialog, InviteForm, SidePanel } from './forms';

export function MemberManagement({ identity, kind, onChanged }: { identity: Identity; kind: Kind; onChanged: () => void }) {
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
  // The shell owns the single h1 of the view; focus returns there.
  const heading = { current: { focus: () => document.getElementById('page-title')?.focus() } };
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

  function resetFilters() {
    setCursor(''); setPage(null); setError(''); setNotice('');
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
  return <section className="management" aria-label={kind === 'memberships' ? 'Miembros' : 'Invitaciones'}>
    {!inviting && kind === 'invitations' && caps.includes('members:invite') && <div className="section-heading"><div />
      <button className="primary" onClick={() => setInviting(true)}>Invitar persona</button></div>}
    {notice && <p role="status" className="banner banner-ok">{notice}</p>}
    {<>
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
        <button onClick={() => resetFilters()}>Limpiar filtros</button></div>
      <div className="directory" aria-busy={busy}>
        {busy && <p role="status" className="data-feedback">Cargando {kind === 'memberships' ? 'miembros' : 'invitaciones'}…</p>}
        {error && <p role="alert" className="banner banner-err">{error}</p>}
        {page && <><p role="status">{page.items.length} registros en esta página. {page.nextCursor ? 'Hay más resultados.' : 'Fin de los resultados.'}</p>
          {!page.items.length ? <p className="data-feedback">No hay {kind === 'memberships' ? 'miembros' : 'invitaciones'} con estos filtros. Limpia los filtros para ver todos los registros.</p> :
            <>{kind === 'invitations' && <p className="muted">Una entrega enviada no acredita aceptación. Si falló o expiró, crea una invitación nueva con el correo autorizado.</p>}
            <div className="table-wrap"><table className="data-table"><caption className="sr-only">{kind === 'memberships' ? 'Miembros de la organización' : 'Invitaciones de la organización'}</caption>
              <thead><tr><th scope="col">{kind === 'memberships' ? 'Miembro' : 'Invitación'}</th><th scope="col">Roles</th><th scope="col">Estado</th>
                {kind === 'invitations' && <th scope="col">Vence</th>}<th scope="col">Revisión</th><th scope="col"><span className="sr-only">Acciones</span></th></tr></thead>
              <tbody>{page.items.map(item => <tr key={itemId(item)}>
                <td><span className="record-id">{itemId(item)}</span>
                  {'operatorIdentityId' in item ? <span className="muted record-id cell-note">Identidad: {item.operatorIdentityId}</span> : <span className="muted cell-note">Destinatario protegido</span>}
                  {item.issuerIds.length > 0 && <span className="muted record-id cell-note">Emisores asignados: {item.issuerIds.join(', ')}</span>}</td>
                <td>{roleNames(item.roles)}</td>
                <td><span className="badge">{states[item.state]}</span>{'deliveryState' in item && <span className="badge">{states[item.deliveryState]}</span>}</td>
                {'expiresAt' in item && <td>{date(item.expiresAt)}</td>}
                <td className="muted">{item.revision}</td>
                <td className="row-actions">
                  {kind === 'memberships' && item.state !== 'revoked' && caps.includes('members:update') && <button aria-label={`Editar acceso ${itemId(item)}`} onClick={() => setEditing(item)}>Editar acceso</button>}
                  {kind === 'invitations' && item.state === 'pending' && caps.includes('invitations:revoke') && <button className="danger" aria-label={`Revocar invitación ${itemId(item)}`} onClick={() => setEditing(item)}>Revocar invitación</button>}
                </td></tr>)}</tbody></table></div></>}
          <div className="actions">{cursor && <button onClick={() => setCursor('')}>Volver al inicio</button>}
            {page.nextCursor && <button onClick={() => { setCursor(page.nextCursor!); heading.current?.focus(); }}>Siguiente página</button>}</div>
        </>}
        {error && <button onClick={() => { setCursor(''); setRefresh(v => v + 1); }}>Reintentar desde el inicio</button>}
      </div>
    </>}
    </>}
    {inviting && <FormDialog label="Invitar persona" onClose={close}><InviteForm identity={identity} onDone={done} onCancel={close} /></FormDialog>}
    {editing && <SidePanel label={kind === 'memberships' ? 'Editar acceso' : 'Revocar invitación'} onClose={close}>
      <EditForm identity={identity} item={editing} kind={kind} onDone={done} onCancel={close} /></SidePanel>}
  </section>;
}
