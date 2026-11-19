import { useEffect, useRef, useState } from 'react';
import { AuthError } from '../authentication/client';
import type { Identity } from '../authentication/client';
import { Button } from '@/components/ui/button';
import { roles as roleNames } from '../user-management/client';
import type { Role } from '../user-management/client';
import { formatDurationSeconds, readSettings, settingsErrorMessage } from './client';
import type { ConsoleSettings } from './client';
import './styles.css';

export interface SettingsViewProps {
  identity: Identity;
  onStepUp: () => void;
  onAccessError: (status: number) => void;
}

export function SettingsView({ identity, onStepUp, onAccessError }: SettingsViewProps) {
  const [settings, setSettings] = useState<ConsoleSettings | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');
  const [reload, setReload] = useState(0);
  const accessError = useRef(onAccessError);
  accessError.current = onAccessError;

  const context = identity.context;
  const activeTenant = identity.tenants.find(t => t.tenantId === identity.activeTenantId);
  const activeRoles = context?.roles ?? [];
  const isTenantAdmin = activeRoles.includes('tenant_admin');

  useEffect(() => {
    setSettings(null);
    setError('');
    if (!isTenantAdmin || !identity.activeTenantId) {
      setBusy(false);
      return;
    }
    const controller = new AbortController();
    setBusy(true);
    void readSettings(identity, AbortSignal.any([controller.signal, AbortSignal.timeout(12000)]))
      .then(result => {
        if (!controller.signal.aborted) setSettings(result);
      })
      .catch(cause => {
        if (controller.signal.aborted) return;
        setError(settingsErrorMessage(cause));
        if (cause instanceof AuthError && [401, 403, 404].includes(cause.status)) {
          accessError.current(cause.status);
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false);
      });
    return () => controller.abort();
  }, [identity, isTenantAdmin, reload]);

  if (!isTenantAdmin) {
    return (
      <section className="settings" aria-label="Ajustes de organización">
        <p role="status">Tu rol no permite consultar los ajustes administrativos de esta organización.</p>
      </section>
    );
  }

  return (
    <section className="settings" aria-label="Ajustes de organización" aria-busy={busy}>
      <div className="settings-bar">
        <p className="settings-note">
          Configuración visible en solo lectura. El ciclo de vida de organizaciones, dominios e integración OIDC se gestiona en Platform Foundation.
        </p>
        <Button type="button" variant="outline" disabled={busy} onClick={() => setReload(value => value + 1)}>
          Actualizar configuración
        </Button>
      </div>

      {busy && <p role="status">Cargando configuración vigente…</p>}
      {error && <p role="alert" className="settings-error">{error}</p>}

      <div className="settings-grid">
        <section className="card settings-card" aria-labelledby="settings-org-title">
          <div className="settings-head">
            <h2 id="settings-org-title">Organización activa</h2>
            <span className="sb-pill">Solo lectura</span>
          </div>
          <dl className="settings-dl">
            <div>
              <dt>Nombre visible</dt>
              <dd>{settings?.displayName ?? activeTenant?.displayName ?? '—'}</dd>
            </div>
            <div>
              <dt>Identificador de tenant</dt>
              <dd className="settings-code">{settings?.tenantId ?? identity.activeTenantId ?? '—'}</dd>
            </div>
            <div>
              <dt>Entorno de consola</dt>
              <dd>{settings ? settings.environment : '—'}</dd>
            </div>
            <div>
              <dt>Módulo de emisión (OID4VCI / KMS)</dt>
              <dd>
                {settings ? (
                  <span className="sb-pill">{settings.issuanceRuntimeEnabled ? 'Activo en este entorno' : 'No configurado'}</span>
                ) : '—'}
              </dd>
            </div>
          </dl>
        </section>

        <section className="card settings-card" aria-labelledby="settings-security-title">
          <div className="settings-head">
            <h2 id="settings-security-title">Política de sesión y MFA</h2>
            <span className="sb-pill">Vigente</span>
          </div>
          {settings ? (
            <>
              <dl className="settings-dl">
                <div>
                  <dt>Caducidad por inactividad</dt>
                  <dd>{formatDurationSeconds(settings.sessionPolicy.sessionIdleSeconds)}</dd>
                </div>
                <div>
                  <dt>Duración máxima de sesión</dt>
                  <dd>{formatDurationSeconds(settings.sessionPolicy.sessionAbsoluteSeconds)}</dd>
                </div>
                <div>
                  <dt>Ventana de verificación reciente (step-up)</dt>
                  <dd>{formatDurationSeconds(settings.sessionPolicy.stepUpSeconds)}</dd>
                </div>
                <div>
                  <dt>Vigencia del token de operador</dt>
                  <dd>{formatDurationSeconds(settings.sessionPolicy.accessTokenSeconds)}</dd>
                </div>
                <div>
                  <dt>Métodos MFA requeridos (AMR)</dt>
                  <dd>
                    {settings.sessionPolicy.requiredAmr.length ? (
                      <div className="sb-wrap">
                        {settings.sessionPolicy.requiredAmr.map(amr => <span className="sb-pill settings-code" key={amr}>{amr}</span>)}
                      </div>
                    ) : 'Ninguno configurado'}
                  </dd>
                </div>
                <div>
                  <dt>Niveles de aseguramiento (ACR)</dt>
                  <dd>
                    {settings.sessionPolicy.acceptedAcr.length ? (
                      <div className="sb-wrap">
                        {settings.sessionPolicy.acceptedAcr.map(acr => <span className="sb-pill settings-code" key={acr}>{acr}</span>)}
                      </div>
                    ) : 'Ninguno configurado'}
                  </dd>
                </div>
              </dl>
              <div className="settings-actions">
                <Button type="button" variant="outline" onClick={onStepUp}>
                  Verificar identidad ahora
                </Button>
              </div>
            </>
          ) : (
            <p className="settings-muted">
              {error ? 'No fue posible leer la política vigente del servidor.' : 'Consultando política de sesión…'}
            </p>
          )}
        </section>

        <section className="card settings-card settings-wide" aria-labelledby="settings-scope-title">
          <div className="settings-head">
            <h2 id="settings-scope-title">Alcance administrativo del operador</h2>
            <span className="sb-pill">Revisión {context?.authorizationRevision ?? 0}</span>
          </div>
          <dl className="settings-dl">
            <div>
              <dt>Identificador del operador</dt>
              <dd className="settings-code">{identity.actorId}</dd>
            </div>
            <div>
              <dt>Roles en esta organización</dt>
              <dd>
                {activeRoles.length ? (
                  <div className="sb-wrap">
                    {activeRoles.map(role => (
                      <span className="sb-pill" key={role}>
                        {Object.hasOwn(roleNames, role) ? roleNames[role as Role] : role}
                      </span>
                    ))}
                  </div>
                ) : 'Sin roles activos'}
              </dd>
            </div>
            <div>
              <dt>Capacidades autorizadas</dt>
              <dd>
                {context?.capabilities.length ? (
                  <ul className="settings-caps">
                    {context.capabilities.map(cap => <li className="settings-code" key={cap}>{cap}</li>)}
                  </ul>
                ) : 'Sin capacidades registradas'}
              </dd>
            </div>
            <div>
              <dt>Emisores asignados al contexto</dt>
              <dd>
                {context?.issuerIds.length ? (
                  <ul className="settings-caps">
                    {context.issuerIds.map(id => <li className="settings-code" key={id}>{id}</li>)}
                  </ul>
                ) : 'Alcance general de organización (consulta Emisores para ver la lista completa)'}
              </dd>
            </div>
          </dl>
          <div className="settings-links">
            <a className="link" href="#emisores">Ir a Emisores</a>
            <a className="link" href="#resumen">Ir al Resumen</a>
          </div>
        </section>
      </div>
    </section>
  );
}
