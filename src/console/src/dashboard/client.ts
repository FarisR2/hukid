import { AuthError, request } from '../authentication/client';
import type { Identity } from '../authentication/client';

export const metrics = {
  activeMembers: { label: 'Miembros activos', scope: 'Estado actual · Miembros' },
  activeIssuers: { label: 'Emisores activos', scope: 'Estado actual · Emisores' },
  publishedDefinitionVersions: { label: 'Versiones publicadas', scope: 'Estado actual · Definiciones' },
  createdRequests: { label: 'Solicitudes creadas', scope: 'Periodo seleccionado · Solicitudes' },
  issuedCredentials: { label: 'Credenciales emitidas', scope: 'Periodo seleccionado · Emisión' },
  pendingStatusChanges: { label: 'Cambios de estado pendientes', scope: 'Estado actual · Publicación de estado' },
};
export type Metric = keyof typeof metrics;
export type DataState = 'available' | 'unavailable' | 'stale' | 'error' | 'notAuthorized';
export interface Section { state: DataState; value: number | null; asOf: string | null; reasonCode: string | null }
interface Envelope {
  tenantId: string; issuerId: string | null; generatedAt: string;
  window: { from: string; to: string; timeZone: 'UTC'; bounds: '[from,to)' };
}
export interface Overview extends Envelope { sections: Record<Metric, Section> }
export interface Activity extends Envelope {
  asOf: string; nextCursor: string | null;
  items: { eventId: string; action: string; outcome: string; occurredAt: string; actorId: string | null; targetId: string }[];
}
export interface Filters { from: string; to: string; issuerId: string }
export const actionNames: Record<string, string> = {
  'auth.step_up.completed': 'Identidad verificada', 'auth.context.changed': 'Organización seleccionada',
  'auth.refresh.completed': 'Sesión renovada', 'auth.logout.completed': 'Sesión cerrada', 'auth.family.revoked': 'Acceso de sesión retirado',
  'members.invitation.created': 'Invitación creada', 'members.invitation.revoked': 'Invitación revocada',
  'members.invitation.accepted': 'Invitación aceptada', 'members.invitation.expired': 'Invitación caducada',
  'members.delivery.sent': 'Invitación enviada', 'members.delivery.failed': 'Envío de invitación fallido',
  'members.membership.changed': 'Acceso de miembro actualizado', 'members.membership.revoked': 'Acceso de miembro revocado',
  'members.membership.reentered': 'Acceso de miembro restablecido', 'members.retention.purged': 'Retención de invitaciones aplicada',
};
export function initialFilters(): Filters {
  const to = new Date(); to.setMilliseconds(0);
  return { from: new Date(to.getTime() - 86400000).toISOString().slice(0, 19), to: to.toISOString().slice(0, 19), issuerId: '' };
}
const timestamp = (v: unknown): v is string => typeof v === 'string' && v.endsWith('Z') && Number.isFinite(Date.parse(v));
const nullableText = (v: unknown) => v === null || typeof v === 'string';

export async function readDashboard<K extends 'overview' | 'activity'>(identity: Identity, kind: K, filters: Filters,
  signal: AbortSignal, cursor = ''): Promise<K extends 'overview' ? Overview : Activity> {
  const params = new URLSearchParams({ from: new Date(`${filters.from}Z`).toISOString(), to: new Date(`${filters.to}Z`).toISOString() });
  if (filters.issuerId) params.set('issuerId', filters.issuerId);
  if (kind === 'activity') params.set('limit', '25');
  if (cursor) params.set('cursor', cursor);
  const value = await (await request(`/console/api/tenants/${encodeURIComponent(identity.activeTenantId!)}/${kind}?${params}`, signal)).json();
  const invalid = () => { throw new AuthError(503, 'invalid_response'); };
  if (!value || value.tenantId !== identity.activeTenantId || value.issuerId !== (filters.issuerId || null) ||
    !timestamp(value.generatedAt) || value.window?.timeZone !== 'UTC' || value.window?.bounds !== '[from,to)' ||
    !timestamp(value.window.from) || !timestamp(value.window.to) ||
    Date.parse(value.window.from) !== Date.parse(`${filters.from}Z`) || Date.parse(value.window.to) !== Date.parse(`${filters.to}Z`)) invalid();
  if (kind === 'overview') {
    if (!value.sections || !Object.keys(metrics).every(key => {
      const s = value.sections[key];
      return s && ['available', 'unavailable', 'stale', 'error', 'notAuthorized'].includes(s.state) && nullableText(s.reasonCode) &&
        (['available', 'stale'].includes(s.state) ? Number.isSafeInteger(s.value) && s.value >= 0 && timestamp(s.asOf) : s.value === null && s.asOf === null);
    })) invalid();
  } else if (!timestamp(value.asOf) || !nullableText(value.nextCursor) || !Array.isArray(value.items) || value.items.length > 25 ||
    !value.items.every((e: Activity['items'][number]) => e && typeof e.eventId === 'string' && typeof e.action === 'string' &&
      typeof e.outcome === 'string' && timestamp(e.occurredAt) && nullableText(e.actorId) && typeof e.targetId === 'string')) invalid();
  return value;
}

export function message(cause: unknown): string {
  if (cause instanceof AuthError) {
    if (cause.status === 403 || cause.status === 404) return 'Tu acceso cambió. Se ha comprobado el contexto; revisa la organización y tus permisos antes de reintentar.';
    if (cause.code === 'invalid_cursor') return 'La página ha caducado o tu acceso cambió. Reinicia la actividad para consultar los datos actuales.';
    if (cause.status === 422 || cause.status === 400) return 'No se pudo aplicar el rango o el emisor. Revisa los filtros y vuelve a aplicar.';
  }
  return 'No pudimos cargar estos datos. Comprueba tu conexión y reintenta.';
}
