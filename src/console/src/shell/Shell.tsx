// Spec: docs/03-design/console-dashboard-interface.md#layout-de-sidebar--adr-0027
import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Activity, ArrowRight, Building2, ChevronsUpDown, FileText, Inbox, LayoutGrid, Lock, LogOut, Mail,
  Menu, ShieldCheck, SlidersHorizontal, Ticket, Users } from 'lucide-react';
import type { Identity } from '../authentication/client';
import { isAvailable, views, viewFromHash, visibleNavigation } from '../navigation';
import type { ViewItem } from '../navigation';
import { roles as roleNames } from '../user-management/client';
import { Button } from '@/components/ui/button';
import './styles.css';

const icons = { grid: LayoutGrid, activity: Activity, users: Users, mail: Mail, building: Building2,
  file: FileText, inbox: Inbox, shield: ShieldCheck, sliders: SlidersHorizontal };

const descriptions: Record<string, string> = {
  resumen: 'Consulta los datos disponibles y su fecha de actualización.',
  actividad: 'Eventos recientes de la organización, con referencias opacas.',
  miembros: 'Gestiona el acceso a esta organización. Los cambios se comprueban al guardar.',
  invitaciones: 'Invita a personas y sigue el estado de cada invitación.',
};

const soon: Record<string, { summary: string; includes: string[]; indicator: string | null }> = {
  emisores: { summary: 'Dependencias autorizadas para emitir credenciales en nombre de la organización.',
    includes: ['Lista de emisores con estado y credenciales emitidas', 'Detalle de cada emisor y sus operadores', 'Alta de un emisor nuevo'], indicator: 'Emisores activos' },
  definiciones: { summary: 'Tipos de credencial y sus versiones.',
    includes: ['Tipos de credencial con versiones Borrador, Publicada y Retirada', 'Editor de campos del esquema', 'Publicar una versión, con confirmación'], indicator: 'Versiones publicadas' },
  solicitudes: { summary: 'Pedidos de emisión pendientes de revisar.',
    includes: ['Bandeja con filtros por estado', 'Detalle de cada solicitud', 'Emitir la credencial desde la solicitud'], indicator: 'Solicitudes creadas' },
  credenciales: { summary: 'Credenciales emitidas y su estado.',
    includes: ['Búsqueda por referencia o por titular', 'Historial de estado de cada credencial', 'Suspender, reactivar o revocar (definitivo)'], indicator: 'Credenciales emitidas' },
  ajustes: { summary: 'Datos institucionales y políticas de acceso.',
    includes: ['Datos institucionales y logotipo', 'Política de sesión y verificación TOTP', 'Zona de peligro'], indicator: null },
};

const initials = (value: string) => value.split(/\s+/).filter(Boolean).slice(0, 2).map(part => part[0]!.toUpperCase()).join('') || '?';

export interface ShellProps {
  identity: Identity;
  busy: boolean;
  /** Content of the available views; the shell renders the page header and the "Pronto" and no-permission views itself. */
  children: (view: ViewItem) => ReactNode;
  onSelectTenant: (tenantId: string) => void;
  onLogout: () => void;
  onRefresh: () => void;
  onStepUp: () => void;
  onAccept: () => void;
}

export function Shell({ identity, busy, children, onSelectTenant, onLogout, onRefresh, onStepUp, onAccept }: ShellProps) {
  const [hash, setHash] = useState(window.location.hash);
  const [menuOpen, setMenuOpen] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const footer = useRef<HTMLDivElement>(null);
  const userButton = useRef<HTMLButtonElement>(null);
  const context = identity.context!;
  const tenant = identity.tenants.find(t => t.tenantId === identity.activeTenantId)!;
  const userRoles = context.roles ?? [];
  // Unknown or missing hashes open the first view this access can see.
  const view = viewFromHash(hash) ?? views.find(item => isAvailable(item, context.capabilities, userRoles)) ?? views[0]!;
  const available = isAvailable(view, context.capabilities, userRoles);

  useEffect(() => {
    const change = () => { setHash(window.location.hash); setNavOpen(false); setMenuOpen(false); window.scrollTo(0, 0); };
    window.addEventListener('hashchange', change);
    return () => window.removeEventListener('hashchange', change);
  }, []);

  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      if (menuOpen) { setMenuOpen(false); userButton.current?.focus(); }
      else if (navOpen) setNavOpen(false);
    };
    const outside = (event: MouseEvent) => {
      if (menuOpen && footer.current && !footer.current.contains(event.target as Node)) setMenuOpen(false);
    };
    document.addEventListener('keydown', key);
    document.addEventListener('mousedown', outside);
    return () => { document.removeEventListener('keydown', key); document.removeEventListener('mousedown', outside); };
  }, [menuOpen, navOpen]);

  // Every view gets its own single h1; focus moves there when the view or organization changes.
  const heading = useRef<HTMLHeadingElement>(null);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    heading.current?.focus({ preventScroll: true });
  }, [view.id]);

  const content = view.soon && available ? <SoonView view={view} /> : !available ? <NoPermission view={view} /> : children(view);

  return <div className={navOpen ? 'shell nav-open' : 'shell'}>
    <a className="skip" href="#page">Ir al contenido</a>
    <aside className="sidebar" id="sidebar" aria-label="Navegación principal">
      <div className="sb-brand"><span className="sb-mark" aria-hidden="true">h.</span><b>HukID</b><small>Consola de operadores</small></div>
      <div className="sb-org">
        <span className="sb-org-av" aria-hidden="true">{initials(tenant.displayName)}</span>
        <span className="sb-org-txt"><span className="sb-org-name">{tenant.displayName}</span><span className="sb-org-ref">{tenant.tenantId.slice(0, 8)}</span></span>
        <ChevronsUpDown aria-hidden="true" />
        <select aria-label="Cambiar de organización" value={tenant.tenantId} disabled={busy || identity.tenants.length < 2}
          onChange={event => { if (event.target.value !== tenant.tenantId) onSelectTenant(event.target.value); }}>
          {identity.tenants.map(t => <option key={t.tenantId} value={t.tenantId}>{t.displayName}</option>)}
        </select>
      </div>
      <nav aria-label="Secciones">
        {visibleNavigation(context.capabilities, userRoles).map(group => <div key={group.group}>
          <div className="sb-group">{group.group}</div>
          {group.items.map(item => {
            const Icon = icons[item.icon];
            return <a key={item.id} className="sb-link" href={`#${item.id}`} aria-current={item.id === view.id ? 'page' : undefined}>
              <Icon aria-hidden="true" /><span>{item.label}</span>{item.soon && <span className="sb-soon">Pronto</span>}</a>;
          })}
        </div>)}
      </nav>
      <div className="sb-foot" ref={footer}>
        {menuOpen && <div className="sb-menu" id="user-menu">
          <div className="sb-menu-sec"><h2>Roles</h2><div className="sb-wrap">{userRoles.length ? userRoles.map(r => <span className="sb-pill" key={r}>{roleNames[r as keyof typeof roleNames] ?? 'Rol autorizado'}</span>) : <span className="sb-faint">Sin roles informados</span>}</div></div>
          <div className="sb-menu-sec"><h2>Capacidades</h2><ul className="sb-caps">{context.capabilities.map(c => <li key={c}>{c}</li>)}</ul></div>
          <button type="button" className="sb-item" onClick={() => { setMenuOpen(false); onAccept(); }}><Ticket aria-hidden="true" />Aceptar una invitación</button>
          <button type="button" className="sb-item" disabled={busy} onClick={() => { setMenuOpen(false); onStepUp(); }}><ShieldCheck aria-hidden="true" />Verificar identidad</button>
          <button type="button" className="sb-item" disabled={busy} onClick={() => { setMenuOpen(false); onRefresh(); }}><ArrowRight aria-hidden="true" />Renovar sesión</button>
          <button type="button" className="sb-item" disabled={busy} onClick={() => { setMenuOpen(false); onLogout(); }}><LogOut aria-hidden="true" />Cerrar sesión</button>
        </div>}
        <button type="button" ref={userButton} className="sb-user" aria-expanded={menuOpen} aria-controls="user-menu" onClick={() => setMenuOpen(open => !open)}>
          <span className="sb-av" aria-hidden="true">{initials('Mi sesión')}</span>
          <span className="sb-user-txt"><span>Mi sesión</span><span>{userRoles[0] ?? 'sin rol'}</span></span>
          <ChevronsUpDown aria-hidden="true" />
        </button>
      </div>
    </aside>
    <div className="scrim" onClick={() => setNavOpen(false)} />
    <div className="shell-main">
      <header className="topbar">
        <Button type="button" variant="ghost" className="menu-btn" aria-label="Abrir menú" aria-expanded={navOpen} aria-controls="sidebar" onClick={() => setNavOpen(open => !open)}><Menu aria-hidden="true" /></Button>
        <nav className="crumbs" aria-label="Ubicación"><span className="crumb-org">{tenant.displayName}</span><span className="crumb-org" aria-hidden="true">/</span><span>{view.group}</span><span aria-hidden="true">/</span><span className="crumb-cur" aria-current="page">{view.label}</span></nav>
        <span className="tb-session">Sesión activa</span>
      </header>
      <main id="page" className="page" aria-busy={busy} tabIndex={-1}>
        <div className="page-head"><div>
          <h1 id="page-title" ref={heading} tabIndex={-1}>{view.label}{view.soon && available && <span className="sb-pill">En exploración</span>}</h1>
          {available && (view.soon ? soon[view.id]!.summary : descriptions[view.id]) && <p>{view.soon ? soon[view.id]!.summary : descriptions[view.id]}</p>}
        </div></div>
        {content}
      </main>
    </div>
  </div>;
}

function SoonView({ view }: { view: ViewItem }) {
  const info = soon[view.id]!;
  return <div className="explore">
    <section className="card"><h2>Qué incluirá</h2><ul>{info.includes.map(item => <li key={item}>{item}</li>)}</ul></section>
    <section className="card"><h2>Estado actual</h2>
      <p>Esta sección todavía no está conectada al backend.{info.indicator ? ` Su indicador en el resumen, «${info.indicator}», muestra «Fuente no disponible».` : ''}</p>
      {info.indicator && <a className="link" href="#resumen">Ver el resumen <ArrowRight aria-hidden="true" /></a>}</section>
  </div>;
}

function NoPermission({ view }: { view: ViewItem }) {
  return <section className="card empty" role="status"><Lock aria-hidden="true" />
    <h2>Tu rol no permite ver {view.label.toLowerCase()}</h2>
    <p>Solicita acceso a tu administrador si lo necesitas.</p>
    {view.id !== 'resumen' && <a className="link" href="#resumen">Ir al resumen <ArrowRight aria-hidden="true" /></a>}</section>;
}
