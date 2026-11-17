import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import type { Identity } from '../authentication/client';
import { date as formatDate } from '../user-management/client';
import type { Client, Definition, DefinitionInput, FieldSpec, Issuer, OperatorCredential, OperatorRequest } from './client';
import { compromiseIssuerKey, createDefinition, createIssuer, errorMessage, getDefinition,
  listClients, listDefinitions, listIssuers, publishDefinition, registerClient, replaceDefinition,
  revokeClient, rotateClientSecret, rotateIssuerKey, retireDefinition, listOperatorRequests, listOperatorCredentials } from './client';
import './styles.css';

type Kind = 'emisores' | 'definiciones' | 'clientes' | 'solicitudes' | 'credenciales';
type Action = { issuerId: string; operation: 'rotate' | 'compromise' } | null;
type EditDraft = { item: Definition; etag: string } | null;
const splitList = (value: string) => value.split(',').map(part => part.trim()).filter(Boolean);
const blankDefinition: DefinitionInput = { id: '', version: '1.0.0', configurationId: '', displayName: '', locale: 'es-PE',
  contexts: [], types: [], fields: {}, defaultValiditySeconds: 31536000, statusPurposes: ['revocation', 'suspension'], publishSchema: true };

export function IssuanceManagement({ identity, kind }: { identity: Identity; kind: Kind }) {
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [definitions, setDefinitions] = useState<Definition[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [requests, setRequests] = useState<OperatorRequest[]>([]);
  const [credentials, setCredentials] = useState<OperatorCredential[]>([]);
  const [selectedIssuer, setSelectedIssuer] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [offset, setOffset] = useState(0);
  const [creating, setCreating] = useState(false);
  const [action, setAction] = useState<Action>(null);
  const [keyID, setKeyID] = useState('');
  const [editing, setEditing] = useState<EditDraft>(null);
  const [definitionForm, setDefinitionForm] = useState<DefinitionInput>(blankDefinition);
  const [issuerName, setIssuerName] = useState('');
  const [issuerSlug, setIssuerSlug] = useState('');
  const [clientName, setClientName] = useState('');
  const [allowedIssuers, setAllowedIssuers] = useState<string[]>([]);
  const [scopes, setScopes] = useState<string[]>(['issuance:create', 'issuance:read']);
  const [secret, setSecret] = useState('');
  const secretDialog = useRef<HTMLDialogElement>(null);

  const capabilities = identity.context?.capabilities ?? [];
  const roles = identity.context?.roles ?? [];
  const canRead = kind === 'solicitudes' || kind === 'credenciales' ? capabilities.includes('issuance:read') :
    kind === 'clientes' ? capabilities.includes('clients:manage') :
    capabilities.includes(kind === 'emisores' ? 'issuers:manage' : 'definitions:manage') || roles.includes('issuer_operator');
  const canManage = kind === 'emisores' ? capabilities.includes('issuers:manage') :
    kind === 'definiciones' ? capabilities.includes('definitions:manage') :
    kind === 'clientes' && capabilities.includes('clients:manage');

  useEffect(() => {
    const dialog = secretDialog.current;
    if (!dialog) return;
    if (secret && !dialog.open) dialog.showModal();
  }, [secret]);

  useEffect(() => {
    const controller = new AbortController();
    const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(12000)]);
    setBusy(true); setError('');
    const load = async () => {
      try {
        const availableIssuers = await listIssuers(identity, signal);
        if (controller.signal.aborted) return;
        setIssuers(availableIssuers);
        if (!selectedIssuer && availableIssuers.length) setSelectedIssuer(availableIssuers[0]!.issuerId);
        if (kind === 'clientes') setClients(await listClients(identity, signal));
        if (kind === 'definiciones' && selectedIssuer) setDefinitions(await listDefinitions(identity, selectedIssuer, signal));
        const issuerFilter = roles.includes('issuer_operator') ? (selectedIssuer || identity.context?.issuerIds[0]) : undefined;
        if (kind === 'solicitudes') setRequests(await listOperatorRequests(identity, issuerFilter, signal, offset));
        if (kind === 'credenciales') setCredentials(await listOperatorCredentials(identity, issuerFilter, signal, offset));
      } catch (cause) {
        if (!controller.signal.aborted) setError(errorMessage(cause));
      } finally {
        if (!controller.signal.aborted) setBusy(false);
      }
    };
    if (canRead) void load(); else { setIssuers([]); setDefinitions([]); setClients([]); setBusy(false); }
    return () => controller.abort();
  }, [identity.activeTenantId, kind, selectedIssuer, refresh, canRead, offset]);

  function changed(message: string) {
    setNotice(message); setError(''); setCreating(false); setAction(null); setEditing(null); setSecret('');
    setRefresh(value => value + 1);
  }

  async function submitIssuer(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const response = await createIssuer(identity, { issuerId: crypto.randomUUID(), slug: issuerSlug.trim(),
        displayName: issuerName.trim(), initialKid: `key-${crypto.randomUUID()}` }, AbortSignal.timeout(12000));
      const result = await response.json();
      setIssuerName(''); setIssuerSlug('');
      changed(`Emisor creado. URI: ${result.issuer.issuerUri}. KID inicial: ${result.activeKey?.kid ?? 'no disponible'}.`);
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setBusy(false); }
  }

  async function submitKeyAction(event: FormEvent) {
    event.preventDefault();
    if (!action || !keyID.trim()) return;
    setBusy(true); setError('');
    try {
      const response = action.operation === 'rotate'
        ? await rotateIssuerKey(identity, action.issuerId, keyID.trim(), AbortSignal.timeout(12000))
        : await compromiseIssuerKey(identity, action.issuerId, keyID.trim(), AbortSignal.timeout(12000));
      const result = await response.json().catch(() => null);
      const resultKid = result?.activeKey?.kid ?? keyID.trim();
      changed(action.operation === 'rotate' ? `Clave rotada. KID nuevo: ${resultKid}` : `Se registró el compromiso de la clave ${resultKid}.`);
      setKeyID('');
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setBusy(false); }
  }

  async function submitDefinition(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const form = event.currentTarget as HTMLFormElement;
      const fieldsText = new FormData(form).get('fields')?.toString() ?? '{}';
      const fields = JSON.parse(fieldsText) as Record<string, FieldSpec>;
      if (!fields || Array.isArray(fields) || typeof fields !== 'object') throw new Error('fields');
      const body: DefinitionInput = { ...definitionForm, fields };
      if (editing) await replaceDefinition(identity, selectedIssuer, editing.item, editing.etag, body, AbortSignal.timeout(12000));
      else await createDefinition(identity, selectedIssuer, body, AbortSignal.timeout(12000));
      setDefinitionForm(blankDefinition);
      changed(editing ? 'Borrador actualizado.' : 'Borrador creado. Revisa sus campos antes de publicarlo.');
    } catch (cause) {
      setError(cause instanceof SyntaxError || (cause instanceof Error && cause.message === 'fields')
        ? 'Los campos deben ser un objeto JSON válido.' : errorMessage(cause));
    } finally { setBusy(false); }
  }

  async function editDefinition(item: Definition) {
    setBusy(true); setError('');
    try {
      const { value, etag } = await getDefinition(identity, selectedIssuer, item, AbortSignal.timeout(12000));
      setEditing({ item, etag });
      setDefinitionForm({ id: value.id, version: value.version, configurationId: value.configurationId,
        displayName: value.displayName, locale: value.locale, contexts: value.contexts ?? [], types: value.types ?? [],
        fields: value.fields ?? {}, defaultValiditySeconds: value.defaultValiditySeconds,
        statusPurposes: value.statusPurposes ?? [], publishSchema: !!value.publishSchema });
      setCreating(true);
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setBusy(false); }
  }

  async function definitionAction(item: Definition, operation: 'publish' | 'retire') {
    const prompt = operation === 'publish'
      ? `Publicar ${item.id}@${item.version}? La versión publicada quedará inmutable.`
      : `Retirar ${item.id}@${item.version}? No podrá recibir nuevas emisiones.`;
    if (!window.confirm(prompt)) return;
    setBusy(true); setError('');
    try {
      if (operation === 'publish') await publishDefinition(identity, selectedIssuer, item, AbortSignal.timeout(12000));
      else await retireDefinition(identity, selectedIssuer, item, AbortSignal.timeout(12000));
      changed(operation === 'publish' ? 'Versión publicada e inmutable.' : 'Versión retirada.');
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setBusy(false); }
  }

  async function submitClient(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const response = await registerClient(identity, { clientName: clientName.trim(), allowedIssuers, scopes }, AbortSignal.timeout(12000));
      const result = await response.json();
      setSecret(result.clientSecret ?? ''); setClientName(''); setAllowedIssuers([]);
      changed('Cliente registrado. Copia ahora el secreto: solo se muestra en esta sesión.');
      setSecret(result.clientSecret ?? '');
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setBusy(false); }
  }

  async function clientAction(clientId: string, operation: 'rotate' | 'revoke') {
    if (operation === 'revoke' && !window.confirm(`Revocar el cliente ${clientId}? Sus solicitudes futuras serán rechazadas.`)) return;
    setBusy(true); setError('');
    try {
      if (operation === 'rotate') {
        const response = await rotateClientSecret(identity, clientId, AbortSignal.timeout(12000));
        const result = await response.json();
        setSecret(result.clientSecret ?? '');
        setNotice('Se rotó el secreto. Cópialo ahora; no se volverá a mostrar.');
        setRefresh(value => value + 1);
      } else {
        await revokeClient(identity, clientId, AbortSignal.timeout(12000));
        changed('Cliente revocado.');
      }
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setBusy(false); }
  }

  function beginEdit(item: Definition) { void editDefinition(item); }
  function closeSecret() { setSecret(''); }

  if (!canRead) return <section className="issuance"><p role="status" className="issuance-feedback">No tienes permiso para consultar esta sección. Contacta con el administrador si necesitas acceso.</p></section>;

  return <section className="issuance" aria-label={kind} aria-busy={busy}>
    {notice && <p role="status" className="issuance-banner success">{notice}</p>}
    {error && <p role="alert" className="issuance-banner error">{error}</p>}
    <div className="issuance-toolbar">
      {(kind === 'definiciones' || ((kind === 'solicitudes' || kind === 'credenciales') && roles.includes('issuer_operator'))) && <label>Emisor<select value={selectedIssuer} onChange={event => { setSelectedIssuer(event.target.value); setCreating(false); setEditing(null); }}>
        {!issuers.length && <option value="">No hay emisores disponibles</option>}
        {issuers.map(item => <option key={item.issuerId} value={item.issuerId}>{item.displayName} · {item.slug}</option>)}
      </select></label>}
      {canManage && <button className="issuance-primary" disabled={busy || (kind === 'definiciones' && !selectedIssuer)}
        onClick={() => { setCreating(value => !value); setEditing(null); setDefinitionForm(blankDefinition); }}>
        {creating ? 'Cerrar formulario' : kind === 'emisores' ? 'Crear emisor' : kind === 'definiciones' ? 'Crear borrador' : 'Registrar cliente'}
      </button>}
      <button disabled={busy} onClick={() => { setError(''); setRefresh(value => value + 1); }}>Actualizar listado</button>
    </div>

    {kind === 'emisores' && <>
      {creating && <form className="issuance-form" onSubmit={submitIssuer}>
        <h2>Nuevo emisor</h2>
        <label>Nombre visible<input required maxLength={120} value={issuerName} onChange={event => setIssuerName(event.target.value)} /></label>
        <label>Slug de la URL<input required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={48} value={issuerSlug} onChange={event => setIssuerSlug(event.target.value)} />
          <span className="issuance-hint">Se publicará como https://issuer.hukid.pe/{issuerSlug || 'slug'}.</span></label>
        <button className="issuance-primary" disabled={busy}>Crear emisor y clave inicial</button>
      </form>}
      {busy && <p className="issuance-feedback" role="status">Cargando emisores…</p>}
      {!busy && !issuers.length && <p className="issuance-feedback">Todavía no hay emisores registrados en esta organización.</p>}
      {!!issuers.length && <div className="issuance-table-wrap"><table className="issuance-table"><caption className="sr-only">Emisores de la organización</caption>
        <thead><tr><th>Emisor</th><th>URI</th><th>Estado</th><th>Creado</th><th>Acciones</th></tr></thead>
        <tbody>{issuers.map(item => <tr key={item.issuerId}><td><b>{item.displayName}</b><span className="issuance-sub">{item.issuerId}</span></td>
          <td><a href={item.issuerUri} target="_blank" rel="noreferrer">{item.issuerUri}</a></td><td><span className="issuance-state">{item.state}</span></td>
          <td>{formatDate(item.createdAt)}</td><td className="issuance-actions">{canManage && <>
            <button disabled={busy} onClick={() => { setAction({ issuerId: item.issuerId, operation: 'rotate' }); setKeyID(`key-${crypto.randomUUID()}`); }}>Rotar clave</button>
            <button className="issuance-danger" disabled={busy} onClick={() => { setAction({ issuerId: item.issuerId, operation: 'compromise' }); setKeyID(''); }}>Reportar compromiso</button>
          </>}</td></tr>)}</tbody></table></div>}
      {action && <form className="issuance-form compact" onSubmit={submitKeyAction}>
        <h2>{action.operation === 'rotate' ? 'Rotar clave del emisor' : 'Reportar clave comprometida'}</h2>
        <p>{action.operation === 'rotate' ? 'La clave nueva quedará activa y la clave anterior seguirá disponible para verificar credenciales existentes.' : 'Se dejará de usar esta clave para nuevas firmas. Indica el KID afectado.'}</p>
        <label>KID<input required maxLength={128} value={keyID} onChange={event => setKeyID(event.target.value)} /></label>
        <button className={action.operation === 'compromise' ? 'issuance-danger' : 'issuance-primary'} disabled={busy}>
          {action.operation === 'rotate' ? 'Confirmar rotación' : 'Confirmar compromiso'}</button>
        <button type="button" disabled={busy} onClick={() => setAction(null)}>Cancelar</button>
      </form>}
    </>}

    {kind === 'definiciones' && <>
      {creating && <form className="issuance-form" onSubmit={submitDefinition}>
        <h2>{editing ? 'Editar borrador' : 'Nuevo borrador de credencial'}</h2>
        <div className="issuance-grid">
          <label>ID de definición<input required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={64} disabled={!!editing} value={definitionForm.id}
            onChange={event => setDefinitionForm({ ...definitionForm, id: event.target.value })} /></label>
          <label>Versión<input required pattern="[0-9]+\.[0-9]+\.[0-9]+" disabled={!!editing} value={definitionForm.version}
            onChange={event => setDefinitionForm({ ...definitionForm, version: event.target.value })} /></label>
          <label>Configuration ID<input required maxLength={128} value={definitionForm.configurationId}
            onChange={event => setDefinitionForm({ ...definitionForm, configurationId: event.target.value })} /></label>
          <label>Nombre visible<input required maxLength={120} value={definitionForm.displayName}
            onChange={event => setDefinitionForm({ ...definitionForm, displayName: event.target.value })} /></label>
          <label>Locale<input required maxLength={32} value={definitionForm.locale}
            onChange={event => setDefinitionForm({ ...definitionForm, locale: event.target.value })} /></label>
          <label>Validez (segundos)<input required type="number" min="0" max="315360000" value={definitionForm.defaultValiditySeconds}
            onChange={event => setDefinitionForm({ ...definitionForm, defaultValiditySeconds: Number(event.target.value) })} /></label>
          <label>Contextos (separados por coma)<input required value={definitionForm.contexts.join(', ')}
            onChange={event => setDefinitionForm({ ...definitionForm, contexts: splitList(event.target.value) })} /></label>
          <label>Tipos VC (separados por coma)<input required value={definitionForm.types.join(', ')}
            onChange={event => setDefinitionForm({ ...definitionForm, types: splitList(event.target.value) })} /></label>
        </div>
        <label>Especificación de campos en JSON<textarea name="fields" required rows={7} defaultValue={JSON.stringify(definitionForm.fields, null, 2)} /></label>
        <label className="issuance-check"><input type="checkbox" checked={definitionForm.publishSchema} onChange={event => setDefinitionForm({ ...definitionForm, publishSchema: event.target.checked })} />Publicar JSON Schema para esta versión</label>
        <div className="issuance-checks">{['revocation', 'suspension'].map(purpose => <label className="issuance-check" key={purpose}>
          <input type="checkbox" checked={definitionForm.statusPurposes.includes(purpose)} onChange={event => setDefinitionForm({ ...definitionForm,
            statusPurposes: event.target.checked ? [...definitionForm.statusPurposes, purpose] : definitionForm.statusPurposes.filter(value => value !== purpose) })} />
          Habilitar {purpose === 'revocation' ? 'revocación' : 'suspensión'}</label>)}</div>
        <div className="issuance-actions"><button className="issuance-primary" disabled={busy}>{editing ? 'Guardar cambios' : 'Crear borrador'}</button>
          <button type="button" disabled={busy} onClick={() => { setCreating(false); setEditing(null); }}>Cancelar</button></div>
      </form>}
      {busy && <p className="issuance-feedback" role="status">Cargando definiciones…</p>}
      {!busy && selectedIssuer && !definitions.length && <p className="issuance-feedback">No hay definiciones para este emisor.</p>}
      {!!definitions.length && <div className="issuance-table-wrap"><table className="issuance-table"><caption className="sr-only">Definiciones del emisor</caption>
        <thead><tr><th>Definición</th><th>Configuration ID</th><th>Estado</th><th>Hash publicado</th><th>Acciones</th></tr></thead>
        <tbody>{definitions.map(item => <tr key={`${item.id}@${item.version}`}><td><b>{item.displayName}</b><span className="issuance-sub">{item.id}@{item.version}</span></td>
          <td>{item.configurationId}</td><td><span className="issuance-state">{item.state}</span></td><td className="issuance-hash">{item.hash ?? '—'}</td>
          <td className="issuance-actions">{canManage && <>
            {item.state === 'draft' && <><button disabled={busy} onClick={() => beginEdit(item)}>Editar</button>
              <button className="issuance-primary" disabled={busy} onClick={() => void definitionAction(item, 'publish')}>Publicar</button></>}
            {item.state === 'published' && <button className="issuance-danger" disabled={busy} onClick={() => void definitionAction(item, 'retire')}>Retirar</button>}
          </>}</td></tr>)}</tbody></table></div>}
    </>}

    {kind === 'clientes' && <>
      {creating && <form className="issuance-form" onSubmit={submitClient}>
        <h2>Registrar cliente de integración</h2>
        <label>Nombre del sistema<input required maxLength={120} value={clientName} onChange={event => setClientName(event.target.value)} /></label>
        <fieldset><legend>Emisores permitidos</legend>{issuers.map(item => <label className="issuance-check" key={item.issuerId}>
          <input type="checkbox" checked={allowedIssuers.includes(item.issuerId)} onChange={event => setAllowedIssuers(event.target.checked
            ? [...allowedIssuers, item.issuerId] : allowedIssuers.filter(id => id !== item.issuerId))} />{item.displayName} · {item.slug}</label>)}
          {!issuers.length && <p>No hay emisores disponibles para asignar.</p>}</fieldset>
        <fieldset><legend>Permisos de integración</legend>{([
          ['issuance:create', 'Crear solicitudes de emisión'], ['issuance:read', 'Consultar solicitudes propias'], ['status:write', 'Cambiar el estado de credenciales'],
        ] as const).map(([scope, label]) => <label className="issuance-check" key={scope}><input type="checkbox" checked={scopes.includes(scope)} onChange={event => setScopes(event.target.checked
          ? [...scopes, scope] : scopes.filter(value => value !== scope))} />{label}</label>)}</fieldset>
        <button className="issuance-primary" disabled={busy || !allowedIssuers.length}>Registrar cliente</button>
      </form>}
      {busy && <p className="issuance-feedback" role="status">Cargando clientes…</p>}
      {!busy && !clients.length && <p className="issuance-feedback">No hay clientes de integración registrados.</p>}
      {!!clients.length && <div className="issuance-table-wrap"><table className="issuance-table"><caption className="sr-only">Clientes de integración</caption>
        <thead><tr><th>Cliente</th><th>Emisores</th><th>Permisos</th><th>Estado</th><th>Acciones</th></tr></thead>
        <tbody>{clients.map(item => <tr key={item.clientId}><td><b>{item.clientName}</b><span className="issuance-sub">{item.clientId}</span></td>
          <td>{item.allowedIssuers.map(id => issuers.find(issuer => issuer.issuerId === id)?.displayName ?? id).join(', ')}</td>
          <td>{item.scopes.join(', ')}</td><td><span className="issuance-state">{item.state}</span></td>
          <td className="issuance-actions">{item.state !== 'revoked' && <><button disabled={busy} onClick={() => void clientAction(item.clientId, 'rotate')}>Rotar secreto</button>
            <button className="issuance-danger" disabled={busy} onClick={() => void clientAction(item.clientId, 'revoke')}>Revocar</button></>}</td></tr>)}</tbody></table></div>}
    </>}

    {kind === 'solicitudes' && <>
      {busy && <p className="issuance-feedback" role="status">Cargando solicitudes…</p>}
      {!busy && !requests.length && <p className="issuance-feedback">No hay solicitudes de emisión.</p>}
      {!!requests.length && <div className="issuance-table-wrap"><table className="issuance-table"><caption className="sr-only">Solicitudes de emisión</caption>
        <thead><tr><th>Solicitud</th><th>Definición</th><th>Oferta</th><th>Emisión</th><th>Creada</th><th>Vence</th></tr></thead>
        <tbody>{requests.map(item => <tr key={item.id}><td><b>{item.id}</b><span className="issuance-sub">{item.issuerId}</span></td>
          <td>{item.credentialDefinition}<span className="issuance-sub">{item.configurationId}</span></td><td>{item.offerState}</td><td>{item.issuanceState}</td>
          <td>{formatDate(item.createdAt)}</td><td>{formatDate(item.expiresAt)}</td></tr>)}</tbody></table></div>}
      <div className="issuance-toolbar"><button disabled={busy || offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Anterior</button>
        <span>Resultados {offset + (requests.length ? 1 : 0)}–{offset + requests.length}</span>
        <button disabled={busy || requests.length < 50} onClick={() => setOffset(offset + 50)}>Siguiente</button></div>
      <p className="issuance-sub">Solo se muestran referencias y estados operativos; claims y códigos de oferta no se exponen.</p>
    </>}

    {kind === 'credenciales' && <>
      {busy && <p className="issuance-feedback" role="status">Cargando credenciales…</p>}
      {!busy && !credentials.length && <p className="issuance-feedback">No hay credenciales emitidas.</p>}
      {!!credentials.length && <div className="issuance-table-wrap"><table className="issuance-table"><caption className="sr-only">Credenciales emitidas</caption>
        <thead><tr><th>Credencial</th><th>Solicitud</th><th>Estado administrativo</th><th>Publicado</th><th>Versión de status</th><th>Emitida</th></tr></thead>
        <tbody>{credentials.map(item => <tr key={item.credentialId}><td><b>{item.credentialId}</b><span className="issuance-sub">{item.issuerId}</span></td>
          <td>{item.requestId}</td><td>{item.desiredStatus}</td><td>{item.publishedStatus}</td><td>{item.statusVersion}</td><td>{formatDate(item.issuedAt)}</td></tr>)}</tbody></table></div>}
      <div className="issuance-toolbar"><button disabled={busy || offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Anterior</button>
        <span>Resultados {offset + (credentials.length ? 1 : 0)}–{offset + credentials.length}</span>
        <button disabled={busy || credentials.length < 50} onClick={() => setOffset(offset + 50)}>Siguiente</button></div>
      <p className="issuance-sub">Las acciones administrativas de status siguen pendientes de política de autorización del owner.</p>
    </>}

    {!!secret && <dialog ref={secretDialog} className="issuance-secret" aria-labelledby="issuance-secret-title"
      onCancel={event => { event.preventDefault(); closeSecret(); }}>
      <div className="issuance-secret-card"><h2 id="issuance-secret-title">Secreto de integración</h2>
        <p>Este secreto se muestra una sola vez. Guárdalo en el gestor seguro de credenciales de tu sistema fuente.</p>
        <textarea readOnly rows={3} value={secret} aria-label="Secreto de cliente" onFocus={event => event.currentTarget.select()} />
        <button className="issuance-primary" onClick={closeSecret}>Ya lo guardé</button>
      </div>
    </dialog>}
  </section>;
}
