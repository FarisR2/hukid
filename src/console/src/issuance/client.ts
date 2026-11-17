import { AuthError, request } from '../authentication/client';
import type { Identity } from '../authentication/client';

export interface Issuer {
  issuerId: string; tenantId: string; slug: string; issuerUri: string; displayName: string;
  state: string; createdAt: string;
}
export interface FieldSpec { type: string; required?: boolean; maxLength?: number; enum?: string[] }
export interface Definition {
  tenantId: string; issuerId: string; id: string; version: string; configurationId: string;
  displayName: string; locale: string; contexts: string[]; types: string[]; fields: Record<string, FieldSpec>;
  defaultValiditySeconds: number; statusPurposes?: string[]; publishSchema?: boolean; state: string;
  hash?: string; etag: string; createdAt: string; publishedAt?: string; retiredAt?: string;
}
export interface Client {
  clientId: string; tenantId: string; clientName: string; allowedIssuers: string[]; scopes: string[];
  state: string; createdAt: string; expiresAt?: string; revokedAt?: string;
}
export interface OperatorRequest {
  id: string; issuerId: string; clientId: string; credentialDefinition: string; configurationId: string;
  offerState: string; issuanceState: string; credentialId?: string; createdAt: string; expiresAt: string;
}
export interface OperatorCredential {
  credentialId: string; issuerId: string; requestId: string; clientId: string; desiredStatus: string;
  publishedStatus: string; statusVersion: number; issuedAt: string;
}
export interface DefinitionInput {
  id: string; version: string; configurationId: string; displayName: string; locale: string;
  contexts: string[]; types: string[]; fields: Record<string, FieldSpec>; defaultValiditySeconds: number;
  statusPurposes: string[]; publishSchema: boolean;
}
export interface ClientInput { clientName: string; allowedIssuers: string[]; scopes: string[]; expiresAt?: string }

const root = (identity: Identity) => `/console/api/tenants/${encodeURIComponent(identity.activeTenantId!)}`;
const itemArray = (value: any): value is { items: unknown[] } => !!value && Array.isArray(value.items);
const text = (value: unknown): value is string => typeof value === 'string';
const record = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const invalid = (): never => { throw new AuthError(503, 'invalid_response'); };

export const idempotencyKey = () => crypto.randomUUID();
export const issuePath = (identity: Identity, suffix: string) => `${root(identity)}/${suffix}`;

export async function listIssuers(identity: Identity, signal: AbortSignal): Promise<Issuer[]> {
  const value = await (await request(issuePath(identity, 'issuers'), signal)).json();
  if (!itemArray(value) || !value.items.every(item => record(item) && text(item.issuerId) && item.tenantId === identity.activeTenantId &&
    text(item.slug) && text(item.issuerUri) && text(item.displayName) && text(item.state) && text(item.createdAt) && Number.isFinite(Date.parse(item.createdAt)))) invalid();
  return value.items as Issuer[];
}

export async function listDefinitions(identity: Identity, issuerId: string, signal: AbortSignal): Promise<Definition[]> {
  const value = await (await request(issuePath(identity, `issuers/${encodeURIComponent(issuerId)}/credential-definitions`), signal)).json();
  if (!itemArray(value) || !value.items.every(item => record(item) && item.tenantId === identity.activeTenantId &&
    item.issuerId === issuerId && text(item.id) && text(item.version) && text(item.configurationId) &&
    text(item.displayName) && text(item.state) && text(item.etag) && text(item.createdAt) && Number.isFinite(Date.parse(item.createdAt)))) invalid();
  return value.items as Definition[];
}

export async function listClients(identity: Identity, signal: AbortSignal): Promise<Client[]> {
  const value = await (await request(issuePath(identity, 'clients'), signal)).json();
  if (!itemArray(value) || !value.items.every(item => record(item) && item.tenantId === identity.activeTenantId &&
    text(item.clientId) && text(item.clientName) && Array.isArray(item.allowedIssuers) && item.allowedIssuers.every(text) &&
    Array.isArray(item.scopes) && item.scopes.every(text) && text(item.state) && text(item.createdAt) && Number.isFinite(Date.parse(item.createdAt)))) invalid();
  return value.items as Client[];
}

async function listOperatorItems<T>(identity: Identity, path: string, issuerId: string | undefined,
  signal: AbortSignal, valid: (item: any) => boolean, offset = 0): Promise<T[]> {
  const params = new URLSearchParams({ limit: '50', offset: String(offset) });
  if (issuerId) params.set('issuerId', issuerId);
  const value = await (await request(`${issuePath(identity, path)}?${params}`, signal)).json();
  if (!itemArray(value) || !value.items.every(valid)) invalid();
  return value.items as T[];
}

export function listOperatorRequests(identity: Identity, issuerId: string | undefined, signal: AbortSignal, offset = 0) {
  return listOperatorItems<OperatorRequest>(identity, 'issuance-requests', issuerId, signal, item => record(item) &&
    text(item.id) && text(item.issuerId) && text(item.clientId) && text(item.credentialDefinition) &&
    text(item.configurationId) && text(item.offerState) && text(item.issuanceState) && text(item.createdAt) && text(item.expiresAt), offset);
}

export function listOperatorCredentials(identity: Identity, issuerId: string | undefined, signal: AbortSignal, offset = 0) {
  return listOperatorItems<OperatorCredential>(identity, 'credentials', issuerId, signal, item => record(item) &&
    text(item.credentialId) && text(item.issuerId) && text(item.requestId) && text(item.clientId) &&
    text(item.desiredStatus) && text(item.publishedStatus) && Number.isInteger(item.statusVersion) && text(item.issuedAt), offset);
}

export async function createIssuer(identity: Identity, body: object, signal: AbortSignal) {
  return request(issuePath(identity, 'issuers'), signal, identity.csrfToken, body, { method: 'POST', key: idempotencyKey() });
}

export async function createDefinition(identity: Identity, issuerId: string, body: DefinitionInput, signal: AbortSignal) {
  return request(issuePath(identity, `issuers/${encodeURIComponent(issuerId)}/credential-definitions`),
    signal, identity.csrfToken, body, { method: 'POST', key: idempotencyKey() });
}

export async function getDefinition(identity: Identity, issuerId: string, item: Definition, signal: AbortSignal) {
  const path = issuePath(identity, `issuers/${encodeURIComponent(issuerId)}/credential-definitions/${encodeURIComponent(item.id)}/versions/${encodeURIComponent(item.version)}`);
  const response = await request(path, signal);
  const value: Definition = await response.json();
  if (!value || value.tenantId !== identity.activeTenantId || value.issuerId !== issuerId || !text(value.etag)) invalid();
  return { value, etag: response.headers.get('ETag') ?? value.etag };
}

export async function replaceDefinition(identity: Identity, issuerId: string, item: Definition, etag: string, body: DefinitionInput, signal: AbortSignal) {
  const path = issuePath(identity, `issuers/${encodeURIComponent(issuerId)}/credential-definitions/${encodeURIComponent(item.id)}/versions/${encodeURIComponent(item.version)}`);
  return request(path, signal, identity.csrfToken, body, { method: 'PUT', etag });
}

export async function publishDefinition(identity: Identity, issuerId: string, item: Definition, signal: AbortSignal) {
  const suffix = `issuers/${encodeURIComponent(issuerId)}/credential-definitions/${encodeURIComponent(item.id)}/versions/${encodeURIComponent(item.version)}/publish`;
  return request(issuePath(identity, suffix), signal, identity.csrfToken, undefined, { method: 'POST', key: idempotencyKey() });
}

export async function retireDefinition(identity: Identity, issuerId: string, item: Definition, signal: AbortSignal) {
  const suffix = `issuers/${encodeURIComponent(issuerId)}/credential-definitions/${encodeURIComponent(item.id)}/versions/${encodeURIComponent(item.version)}/retire`;
  return request(issuePath(identity, suffix), signal, identity.csrfToken, undefined, { method: 'POST', key: idempotencyKey() });
}

export async function rotateIssuerKey(identity: Identity, issuerId: string, kid: string, signal: AbortSignal) {
  return request(issuePath(identity, `issuers/${encodeURIComponent(issuerId)}/keys/rotate`), signal, identity.csrfToken,
    { kid }, { method: 'POST', key: idempotencyKey() });
}

export async function compromiseIssuerKey(identity: Identity, issuerId: string, kid: string, signal: AbortSignal) {
  return request(issuePath(identity, `issuers/${encodeURIComponent(issuerId)}/keys/${encodeURIComponent(kid)}/compromise`),
    signal, identity.csrfToken, undefined, { method: 'POST', key: idempotencyKey() });
}

export async function registerClient(identity: Identity, body: ClientInput, signal: AbortSignal) {
  return request(issuePath(identity, 'clients'), signal, identity.csrfToken, body, { method: 'POST', key: idempotencyKey() });
}

export async function rotateClientSecret(identity: Identity, clientId: string, signal: AbortSignal) {
  return request(issuePath(identity, `clients/${encodeURIComponent(clientId)}/rotate-secret`), signal,
    identity.csrfToken, undefined, { method: 'POST', key: idempotencyKey() });
}

export async function revokeClient(identity: Identity, clientId: string, signal: AbortSignal) {
  return request(issuePath(identity, `clients/${encodeURIComponent(clientId)}/revoke`), signal,
    identity.csrfToken, undefined, { method: 'POST', key: idempotencyKey() });
}

export function errorMessage(error: unknown): string {
  if (!(error instanceof AuthError)) return 'No se confirmó el resultado. Comprueba tu conexión y vuelve a cargar la sección.';
  if (error.code === 'step_up_required' || error.code === 'mfa_required') return 'Verifica tu identidad antes de continuar.';
  if (error.status === 401) return 'Tu sesión venció. Vuelve a comprobar el acceso e inicia sesión.';
  if (error.status === 403) return 'Tu rol no permite esta operación o la verificación reciente venció.';
  if (error.status === 404) return 'El recurso no está disponible dentro de tu organización.';
  if (error.status === 409 || error.status === 412) return 'El recurso cambió o la operación ya no es válida. Actualiza el listado y revisa el estado.';
  if (error.status === 422) return 'Revisa los datos ingresados y vuelve a intentarlo.';
  if (error.status === 429) return 'Hay demasiados intentos. Espera un momento y vuelve a intentarlo.';
  return 'No se confirmó el resultado. Comprueba tu conexión y vuelve a cargar la sección.';
}
