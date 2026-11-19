// Spec: docs/03-design/console-dashboard-interface.md#layout-de-sidebar--adr-0027
// One public hash per view. Invitation fragments and unknown hashes never survive startup.
export type ViewId = 'resumen' | 'actividad' | 'miembros' | 'invitaciones' |
  'emisores' | 'definiciones' | 'clientes' | 'solicitudes' | 'credenciales' | 'ajustes';

export interface ViewItem {
  id: ViewId;
  label: string;
  group: string;
  icon: 'grid' | 'activity' | 'users' | 'mail' | 'building' | 'file' | 'inbox' | 'shield' | 'sliders';
  /** Capability that shows the item. Absent for exploration or role-gated sections. */
  capabilities?: string[];
  /** Explicit roles that grant access when the view is gated by role. */
  roles?: string[];
  soon?: true;
}

export const navigation: { group: string; items: ViewItem[] }[] = [
  { group: 'General', items: [
    { id: 'resumen', label: 'Resumen', group: 'General', icon: 'grid', capabilities: ['dashboard:read'] },
    { id: 'actividad', label: 'Actividad', group: 'General', icon: 'activity', capabilities: ['audit:read'] }] },
  { group: 'Acceso', items: [
    { id: 'miembros', label: 'Miembros', group: 'Acceso', icon: 'users', capabilities: ['members:read'] },
    { id: 'invitaciones', label: 'Invitaciones', group: 'Acceso', icon: 'mail', capabilities: ['invitations:read'] }] },
  { group: 'Emisión', items: [
    { id: 'emisores', label: 'Emisores', group: 'Emisión', icon: 'building', capabilities: ['issuers:manage'] },
    { id: 'definiciones', label: 'Definiciones', group: 'Emisión', icon: 'file', capabilities: ['definitions:manage'] },
    { id: 'clientes', label: 'Clientes de integración', group: 'Emisión', icon: 'users', capabilities: ['clients:manage'] },
    { id: 'solicitudes', label: 'Solicitudes', group: 'Emisión', icon: 'inbox', capabilities: ['issuance:read'] },
    { id: 'credenciales', label: 'Credenciales', group: 'Emisión', icon: 'shield', capabilities: ['issuance:read'] }] },
  { group: 'Organización', items: [
    { id: 'ajustes', label: 'Ajustes', group: 'Organización', icon: 'sliders', roles: ['tenant_admin'] }] },
];

export const views: ViewItem[] = navigation.flatMap(group => group.items);

export function viewFromHash(hash: string): ViewItem | undefined {
  return views.find(view => `#${view.id}` === hash);
}

export function isSectionHash(hash: string): boolean {
  return viewFromHash(hash) !== undefined;
}

// Exploration and role-gated sections are listed for the authorized roles. Live issuer views
// require their explicit capability and are checked again by the Management API/BFF.
export function isAvailable(view: ViewItem, capabilities: string[], roles: string[] = []): boolean {
  if (view.soon) return roles.includes('tenant_admin');
  if ((view.id === 'emisores' || view.id === 'definiciones') && roles.includes('issuer_operator')) return true;
  if (view.roles?.some(role => roles.includes(role))) return true;
  return (view.capabilities ?? []).some(capability => capabilities.includes(capability));
}

export function visibleNavigation(capabilities: string[], roles: string[] = []) {
  return navigation
    .map(group => ({ group: group.group, items: group.items.filter(item => isAvailable(item, capabilities, roles)) }))
    .filter(group => group.items.length);
}

/** Current view for a hash; unknown or missing hashes mean the summary. */
export function currentView(hash: string): ViewItem {
  return viewFromHash(hash) ?? views[0]!;
}

/** Moves focus to the view heading after the session and tenant resolve. */
export function restoreSection(): boolean {
  const target = document.getElementById('page-title');
  if (!target) return false;
  target.focus({ preventScroll: true });
  return true;
}
