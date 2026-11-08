// Spec: docs/03-design/console-dashboard-interface.md#contexto-y-navegación
// Only public section names may survive startup; invitation fragments never do.
export const sectionHashes = ['#title', '#overview', '#members-title', '#content'] as const;

export function isSectionHash(hash: string): boolean {
  return sectionHashes.some(section => section === hash);
}

export function restoreSection(capabilities: string[]): boolean {
  const hash = window.location.hash;
  if (!isSectionHash(hash)) return false;
  const authorized = (hash !== '#overview' || capabilities.includes('dashboard:read')) &&
    (hash !== '#members-title' || capabilities.some(c => ['members:read', 'invitations:read'].includes(c)));
  const target = authorized ? document.getElementById(hash.slice(1)) : null;
  if (target) {
    target.focus({ preventScroll: true });
    target.scrollIntoView();
    return true;
  }
  // A remembered section may no longer be available with the current access.
  window.history.replaceState(null, '', window.location.pathname + window.location.search + '#title');
  window.dispatchEvent(new HashChangeEvent('hashchange'));
  return false;
}
