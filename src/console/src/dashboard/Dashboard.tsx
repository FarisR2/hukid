import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { AuthError } from '../authentication/client';
import type { Identity } from '../authentication/client';
import { date } from '../user-management/client';
import { actionNames, initialFilters, message, metrics, readDashboard } from './client';
import type { Activity, DataState, Filters, Overview } from './client';

const states: Record<DataState, string> = { available: 'Disponible', stale: 'Dato antiguo', unavailable: 'Fuente no disponible', error: 'Error de la fuente', notAuthorized: 'Sin permiso' };

export function Dashboard({ identity, onAccessError }: { identity: Identity; onAccessError: (status: number) => void }) {
  const [draft, setDraft] = useState(initialFilters);
  const [filters, setFilters] = useState<Filters>(draft);
  const [validation, setValidation] = useState('');
  const [overview, setOverview] = useState<Overview | null>(null);
  const [activity, setActivity] = useState<Activity | null>(null);
  const [errors, setErrors] = useState({ overview: '', activity: '' });
  const [loading, setLoading] = useState({ overview: true, activity: true });
  const [reload, setReload] = useState(0);
  const [activityReload, setActivityReload] = useState(0);
  const [cursor, setCursor] = useState('');
  const fromInput = useRef<HTMLInputElement>(null);
  const accessError = useRef(onAccessError); accessError.current = onAccessError;
  const caps = identity.context!.capabilities;
  const canAudit = caps.includes('audit:read');
  const canRead = caps.includes('dashboard:read');
  // The parent keys by actor/tenant/revision. Each effect also discards late
  // results after filter changes, including when fetch ignores cancellation.
  useEffect(() => {
    setOverview(null); setErrors(e => ({ ...e, overview: '' }));
    if (!canRead) { setLoading(l => ({ ...l, overview: false })); return; }
    const controller = new AbortController();
    setLoading(l => ({ ...l, overview: true }));
    void readDashboard(identity, 'overview', filters, AbortSignal.any([controller.signal, AbortSignal.timeout(12000)]))
      .then(result => { if (!controller.signal.aborted) setOverview(result); })
      .catch(cause => { if (!controller.signal.aborted) {
        setErrors(e => ({ ...e, overview: message(cause) }));
        if (cause instanceof AuthError && [401, 403, 404].includes(cause.status)) accessError.current(cause.status);
      } })
      .finally(() => { if (!controller.signal.aborted) setLoading(l => ({ ...l, overview: false })); });
    return () => controller.abort();
  }, [filters, reload, canRead]);

  useEffect(() => {
    setActivity(null); setErrors(e => ({ ...e, activity: '' }));
    if (!canRead || !canAudit) { setLoading(l => ({ ...l, activity: false })); return; }
    const controller = new AbortController();
    setLoading(l => ({ ...l, activity: true }));
    void readDashboard(identity, 'activity', filters, AbortSignal.any([controller.signal, AbortSignal.timeout(12000)]), cursor)
      .then(result => { if (!controller.signal.aborted) setActivity(result); })
      .catch(cause => { if (!controller.signal.aborted) {
        setErrors(e => ({ ...e, activity: message(cause) }));
        if (cause instanceof AuthError && [401, 403, 404].includes(cause.status)) accessError.current(cause.status);
      } })
      .finally(() => { if (!controller.signal.aborted) setLoading(l => ({ ...l, activity: false })); });
    return () => controller.abort();
  }, [filters, cursor, reload, activityReload, canRead, canAudit]);

  function apply(event: FormEvent) {
    event.preventDefault();
    const duration = Date.parse(`${draft.to}Z`) - Date.parse(`${draft.from}Z`);
    if (!Number.isFinite(duration) || duration <= 0 || duration > 31 * 86400000) {
      setValidation('El fin debe ser posterior al inicio y el rango no puede superar 31 días.'); fromInput.current?.focus(); return;
    }
    setValidation(''); setOverview(null); setActivity(null); setCursor(''); setFilters({ ...draft });
  }

  return <section id="overview" className="dashboard" aria-labelledby="dashboard-title" tabIndex={-1}>
    <div className="section-heading"><div><span className="eyebrow">Estado de la organización</span><h2 id="dashboard-title">Resumen operativo</h2>
      <p>Consulta los datos disponibles y su fecha de actualización.</p></div>
      {canRead && <button onClick={() => { setCursor(''); setReload(n => n + 1); }}>Actualizar resumen</button>}</div>
    {!canRead ? <p role="status">No tienes permiso para consultar el resumen. Solicita acceso a tu administrador.</p> : <>
      <form className="dashboard-filters" onSubmit={apply}>
        <label>Desde (UTC)<input ref={fromInput} type="datetime-local" step="1" required value={draft.from} aria-invalid={!!validation} aria-describedby="range-help range-error" onChange={e => setDraft({ ...draft, from: e.target.value })} /></label>
        <label>Hasta (UTC)<input type="datetime-local" step="1" required value={draft.to} aria-invalid={!!validation} aria-describedby="range-help range-error" onChange={e => setDraft({ ...draft, to: e.target.value })} /></label>
        {!!identity.context!.issuerIds.length && <label>Emisor autorizado<select value={draft.issuerId} onChange={e => setDraft({ ...draft, issuerId: e.target.value })}>
          <option value="">Todo mi alcance autorizado</option>{identity.context!.issuerIds.map(id => <option key={id} value={id}>{id}</option>)}</select></label>}
        <button className="primary">Aplicar periodo</button>
      </form>
      <p id="range-help" className="muted">Intervalo UTC: incluye el inicio y excluye el fin. Máximo 31 días. Los conteos de estado actual no se filtran por periodo.</p>
      <p id="range-error" className="field-error" role={validation ? 'alert' : undefined}>{validation}</p>
      <div aria-busy={loading.overview}>
        {loading.overview && <p role="status">Cargando resumen…</p>}
        {errors.overview && <p role="alert">{errors.overview} Usa Actualizar resumen para reintentar.</p>}
        {overview && <><p className="muted">Generado: {date(overview.generatedAt)} · Periodo: {date(overview.window.from)} — {date(overview.window.to)}</p>
          <dl className="metric-grid">{(Object.keys(metrics) as (keyof typeof metrics)[]).map(key => {
            const section = overview.sections[key]; const meta = metrics[key];
            return <div className="metric" key={key}><dt>{meta.label}</dt><dd>
              <span className="metric-value">{section.value === null ? '—' : new Intl.NumberFormat('es').format(section.value)}</span>
              <span className="badge">{states[section.state]}</span><span className="muted metric-detail">{meta.scope}</span>
              {section.asOf && <span className="muted metric-detail">Datos al {date(section.asOf)}</span>}
              {section.state === 'stale' && <span className="metric-detail">Puede haber cambios posteriores a esta fecha.</span>}
            </dd></div>;
          })}</dl></>}
      </div>
      <section className="dashboard-activity" aria-labelledby="activity-title" aria-busy={loading.activity}>
        <h3 id="activity-title">Actividad reciente</h3>
        {!canAudit ? <p role="status">No tienes permiso para consultar la actividad.</p> : <>
          {loading.activity && <p role="status">Cargando actividad…</p>}
          {errors.activity && <p role="alert">{errors.activity}</p>}
          {activity && <><p className="muted">Datos al {date(activity.asOf)} · Generado: {date(activity.generatedAt)}</p>
            {!activity.items.length ? <p role="status">No hay actividad en este periodo. Prueba otro rango.</p> : <ol className="activity-list">{activity.items.map(item => <li key={item.eventId}>
              <div><strong>{actionNames[item.action] ?? 'Actividad registrada'}</strong> <span className="badge">{item.outcome === 'success' ? 'Correcto' : item.outcome === 'denied' ? 'Denegado' : item.outcome === 'failure' ? 'Fallido' : 'Registrado'}</span></div>
              <time dateTime={item.occurredAt}>{date(item.occurredAt)}</time><span className="muted metric-detail">Referencia: {item.targetId}</span>
            </li>)}</ol>}</>}
          <div className="actions"><button disabled={loading.activity} onClick={() => { setCursor(''); setActivityReload(n => n + 1); }}>Reiniciar actividad</button>
            {activity?.nextCursor && <button disabled={loading.activity} onClick={() => { setActivity(null); setCursor(activity.nextCursor!); }}>Siguiente página de actividad</button>}</div>
        </>}
      </section>
    </>}
  </section>;
}
