import { AuthError, request } from '../authentication/client';
import type { Identity } from '../authentication/client';
import { isSectionHash } from '../navigation';

export const roles = { tenant_admin: 'Administración de organización', security_admin: 'Administración de seguridad',
  support_readonly: 'Soporte de consulta', issuer_operator: 'Operación de emisores' };
export type Role = keyof typeof roles;
export const reasons = { access_change: 'Cambio de acceso', security_response: 'Respuesta de seguridad',
  operator_request: 'Solicitud del operador', invitation_cancelled: 'Cancelación de invitación' };
export type Reason = keyof typeof reasons;
export const states: Record<string, string> = { active: 'Activo', suspended: 'Suspendido', revoked: 'Revocado',
  pending: 'Pendiente', accepted: 'Aceptada', expired: 'Expirada', queued: 'En cola', sent: 'Enviada', failed: 'Entrega fallida' };
export interface Membership {
  tenantId: string; membershipId: string; operatorIdentityId: string; roles: Role[]; issuerIds: string[];
  state: 'active' | 'suspended' | 'revoked'; revision: number; lifecycle: number; createdAt: string; updatedAt: string;
}
export interface Invitation {
  tenantId: string; invitationId: string; recipientHint: string; roles: Role[]; issuerIds: string[];
  state: 'pending' | 'accepted' | 'revoked' | 'expired'; deliveryState: 'queued' | 'sent' | 'failed';
  revision: number; createdAt: string; expiresAt: string;
}
export type Kind = 'memberships' | 'invitations';
export type RecordItem = Membership | Invitation;
export interface Page { items: RecordItem[]; nextCursor: string | null }
export const itemId = (item: RecordItem) => 'membershipId' in item ? item.membershipId : item.invitationId;
export const roleNames = (value: Role[]) => value.map(r => roles[r]).join(', ');
export const date = (value: string) => new Intl.DateTimeFormat('es', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(new Date(value)) + ' UTC';
export const directoryPath = (identity: Identity, kind: Kind) => `/console/api/tenants/${encodeURIComponent(identity.activeTenantId!)}/${kind}`;

export async function list(identity: Identity, kind: Kind, filters: URLSearchParams, signal: AbortSignal): Promise<Page> {
  const value: Page = await (await request(`${directoryPath(identity, kind)}?${filters}`, signal)).json();
  if (!value || !Array.isArray(value.items) || !(value.nextCursor === null || typeof value.nextCursor === 'string') ||
    !value.items.every(item => item && item.tenantId === identity.activeTenantId && typeof itemId(item) === 'string' &&
      Number.isSafeInteger(item.revision) && item.revision > 0 && Array.isArray(item.roles) && item.roles.every(r => Object.hasOwn(roles, r)) &&
      Array.isArray(item.issuerIds) && item.issuerIds.every(id => typeof id === 'string') &&
      (kind === 'memberships' ? 'operatorIdentityId' in item && typeof item.operatorIdentityId === 'string' && ['active', 'suspended', 'revoked'].includes(item.state) :
        'deliveryState' in item && ['queued', 'sent', 'failed'].includes(item.deliveryState) && Number.isFinite(Date.parse(item.expiresAt)) && ['pending', 'accepted', 'revoked', 'expired'].includes(item.state)))) throw new AuthError(503, 'invalid_response');
  return value;
}

export function errorMessage(error: unknown): string {
  if (!(error instanceof AuthError)) return 'No se confirmó el resultado. Comprueba tu conexión y reintenta la misma solicitud.';
  const messages: Record<string, string> = {
    revision_mismatch: 'El registro cambió. Tu edición se conserva. Carga la versión actual y compárala antes de confirmar de nuevo.',
    last_admin_required: 'Debe quedar al menos un administrador activo. Asigna otro administrador antes de retirar este acceso.',
    mfa_required: 'Verifica tu identidad antes de continuar. Al salir para verificarla tendrás que volver a introducir los cambios.',
    recipient_unverified: 'Verifica tu identidad para confirmar el correo. Después vuelve a abrir la invitación.',
    invitation_invalid: 'La invitación no está disponible. Puede haber vencido o sido utilizada o revocada. Solicita una nueva al administrador.',
    membership_exists: 'Ya tienes acceso o una membresía suspendida. Contacta con el administrador.',
    membership_revoked: 'Este acceso fue revocado. Solicita una invitación nueva.',
    invitation_not_pending: 'La invitación ya no está pendiente. Recarga el listado.',
    operation_in_progress: 'La solicitud sigue en curso. Espera y reintenta la misma solicitud.',
    invalid_cursor: 'La página venció o cambió. Vuelve al inicio del listado.',
  };
  if (messages[error.code]) return messages[error.code]!;
  if (error.status === 401) return 'Tu sesión venció. Vuelve a comprobar el acceso e inicia sesión.';
  if (error.status === 403) return 'No tienes permiso para esta operación. Comprueba tu acceso o contacta con el administrador.';
  if (error.status === 404) return 'El registro o la organización ya no están disponibles. Comprueba tu acceso.';
  if (error.status === 422) return 'Revisa los campos y los permisos solicitados antes de reintentar.';
  if (error.status === 429) return 'Demasiados intentos. Espera un momento antes de reintentar.';
  return 'No se confirmó el resultado. El servicio puede no estar disponible. Reintenta la misma solicitud.';
}

// Called before React renders or any navigation. Only an in-memory, one-use
// handoff survives; never retain an invitation in URL/history or web storage.
let incomingToken = '';
export const isInvitationCode = (value: string) => /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value);
export function captureInvitation() {
  if (!window.location.hash || isSectionHash(window.location.hash)) return;
  const token = new URLSearchParams(window.location.hash.slice(1)).get('invitation') ?? '';
  window.history.replaceState(null, '', window.location.pathname + window.location.search);
  if (isInvitationCode(token)) incomingToken = token;
}
export function takeInvitation() { const token = incomingToken; incomingToken = ''; return token; }
export function discardInvitation() { incomingToken = ''; }
