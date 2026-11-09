// Spec: docs/03-design/console-dashboard-interface.md#layout-de-sidebar--adr-0027
// One public hash per view. Invitation fragments and unknown hashes never survive startup.
export type ViewId = 'resumen' | 'actividad' | 'miembros' | 'invitaciones' |
  'emisores' | 'definiciones' | 'solicitudes' | 'credenciales' | 'ajustes';

export interface ViewItem {
  id: ViewId;
  label: string;
  group: string;
  icon: 'grid' | 'activity' | 'users' | 'mail' | 'building' | 'file' | 'inbox' | 'shield' | 'sliders';
  /** Capability that shows the item. Absent for the "Pronto" exploration sections. */
  capabilities?: string[];
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
    { id: 'emisores', label: 'Emisores', group: 'Emisión', icon: 'building', soon: true },
    { id: 'definiciones', label: 'Definiciones', group: 'Emisión', icon: 'file', soon: true },
    { id: 'solicitudes', label: 'Solicitudes', group: 'Emisión', icon: 'inbox', soon: true },
    { id: 'credenciales', label: 'Credenciales', group: 'Emisión', icon: 'shield', soon: true }] },
  { group: 'Organización', items: [
    { id: 'ajustes', label: 'Ajustes', group: 'Organización', icon: 'sliders', soon: true }] },
];

export const views: ViewItem[] = navigation.flatMap(group => group.items);

export function viewFromHash(hash: string): ViewItem | undefined {
  return views.find(view => `#${view.id}` === hash);
}

export function isSectionHash(hash: string): boolean {
  return viewFromHash(hash) !== undefined;
}

// As in the prototype, the exploration sections are listed only for tenant administrators.
// They carry no capability, data or API; the backend never sees them.
export function isAvailable(view: ViewItem, capabilities: string[], roles: string[] = []): boolean {
  if (view.soon) return roles.includes('tenant_admin');
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
