import { AuthError, request } from '../authentication/client';
import type { Identity } from '../authentication/client';

export interface SessionPolicySettings {
  accessTokenSeconds: number;
  sessionIdleSeconds: number;
  sessionAbsoluteSeconds: number;
  stepUpSeconds: number;
  requiredAmr: string[];
  acceptedAcr: string[];
}

export interface ConsoleSettings {
  tenantId: string;
  displayName: string;
  environment: string;
  issuanceRuntimeEnabled: boolean;
  sessionPolicy: SessionPolicySettings;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value);

const isNonNegativeInt = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every(item => typeof item === 'string');

export async function readSettings(identity: Identity, signal: AbortSignal): Promise<ConsoleSettings> {
  const value = await (await request('/console/api/settings', signal)).json();
  if (!isRecord(value) || value.tenantId !== identity.activeTenantId ||
      typeof value.displayName !== 'string' || typeof value.environment !== 'string' || !value.environment ||
      typeof value.issuanceRuntimeEnabled !== 'boolean' || !isRecord(value.sessionPolicy)) {
    throw new AuthError(503, 'invalid_response');
  }
  const policy = value.sessionPolicy;
  if (!isNonNegativeInt(policy.accessTokenSeconds) || !isNonNegativeInt(policy.sessionIdleSeconds) ||
      !isNonNegativeInt(policy.sessionAbsoluteSeconds) || !isNonNegativeInt(policy.stepUpSeconds) ||
      !isStringArray(policy.requiredAmr) || !isStringArray(policy.acceptedAcr)) {
    throw new AuthError(503, 'invalid_response');
  }
  return value as unknown as ConsoleSettings;
}

export function formatDurationSeconds(seconds: number): string {
  const secLabel = `${new Intl.NumberFormat('es').format(seconds)} s`;
  if (seconds > 0 && seconds % 3600 === 0) return `${seconds / 3600} h (${secLabel})`;
  if (seconds > 0 && seconds % 60 === 0) return `${seconds / 60} min (${secLabel})`;
  return secLabel;
}

export function settingsErrorMessage(error: unknown): string {
  if (!(error instanceof AuthError)) {
    return 'No pudimos cargar los ajustes. Comprueba tu conexión e inténtalo de nuevo.';
  }
  if (error.status === 401) return 'Tu sesión venció. Vuelve a comprobar el acceso e inicia sesión.';
  if (error.status === 403) return 'Solo la administración de la organización puede consultar estos ajustes.';
  if (error.status === 404) return 'La organización activa ya no está disponible. Comprueba tu acceso.';
  return 'No pudimos obtener la configuración desde el servidor. Reintenta en unos instantes.';
}
