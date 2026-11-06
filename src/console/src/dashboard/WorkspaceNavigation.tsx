import { useEffect, useState } from 'react';
import type { Identity } from '../authentication/client';
import { roles } from '../user-management/client';

export function WorkspaceNavigation({ identity }: { identity: Identity }) {
  const [location, setLocation] = useState(window.location.hash);
  useEffect(() => {
    const change = () => setLocation(window.location.hash);
    window.addEventListener('hashchange', change);
    return () => window.removeEventListener('hashchange', change);
  }, []);
  const context = identity.context!;
  const links = [
    ...(context.capabilities.includes('dashboard:read') ? [{ href: '#overview', label: 'Resumen' }] : []),
    ...(context.capabilities.some(c => ['members:read', 'invitations:read'].includes(c)) ? [{ href: '#members-title', label: 'Miembros e invitaciones' }] : []),
    { href: '#title', label: 'Sesión y organización' },
  ];
  const current = links.some(link => link.href === location) ? location : links[0]!.href;
  return <>
    <div className="workspace-context"><p><strong>Tu rol:</strong> {context.roles?.length ? context.roles.map(r => roles[r as keyof typeof roles] ?? 'Rol autorizado').join(', ') : 'Consulta tus capacidades de acceso'}</p>
      <details><summary>Capacidades de tu acceso</summary><ul>{context.capabilities.map(c => <li key={c}>{c}</li>)}</ul></details>
    </div>
    <nav className="workspace-nav" aria-label="Organización activa">{links.map(link => <a key={link.href} href={link.href} aria-current={current === link.href ? 'location' : undefined}>{link.label}</a>)}</nav>
  </>;
}
