"""Targeted UI-only regressions for F-002–F-005. No fixtures reach real services."""
import json
from urllib.parse import urlsplit
from playwright.sync_api import expect


def capture(page, artifacts, state):
    for width in [390, 1280]:
        page.set_viewport_size({'width': width, 'height': 1000})
        for scheme in ['light', 'dark']:
            page.emulate_media(color_scheme=scheme)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(artifacts / f'audit-{state}-{width}-{scheme}.png'), full_page=True)
    page.emulate_media(color_scheme='light')


def check_palette(page, artifacts):
    pairs = [('text', 'bg', 4.5), ('text', 'surface', 4.5), ('muted-foreground', 'bg', 4.5),
             ('muted-foreground', 'surface', 4.5), ('primary', 'surface', 4.5), ('on-primary', 'primary', 4.5),
             ('on-primary', 'hover', 4.5), ('badge-text', 'badge-bg', 4.5), ('danger', 'surface', 4.5),
             ('control-border', 'surface', 3), ('focus', 'bg', 3), ('focus', 'surface', 3)]
    results = {}
    for scheme in ['light', 'dark']:
        page.emulate_media(color_scheme=scheme)
        colors = page.evaluate('''() => {
          const style = getComputedStyle(document.documentElement);
          return Object.fromEntries(['text', 'bg', 'surface', 'muted-foreground', 'primary', 'on-primary', 'hover',
            'badge-text', 'badge-bg', 'danger', 'control-border', 'focus'].map(name =>
            [name, style.getPropertyValue('--' + name).trim()]));
        }''')

        def luminance(color):
            value = color.lstrip('#')
            if len(value) == 3:
                value = ''.join(c * 2 for c in value)
            channels = [int(value[i:i+2], 16) / 255 for i in (0, 2, 4)]
            linear = [c / 12.92 if c <= .04045 else ((c + .055) / 1.055) ** 2.4 for c in channels]
            return sum(c * weight for c, weight in zip(linear, [.2126, .7152, .0722]))

        results[scheme] = {}
        for foreground, background, threshold in pairs:
            light, dark = sorted([luminance(colors[foreground]), luminance(colors[background])], reverse=True)
            ratio = (light + .05) / (dark + .05)
            assert ratio >= threshold, (scheme, foreground, background, ratio)
            results[scheme][foreground + '/' + background] = round(ratio, 3)
    page.emulate_media(color_scheme='light')
    (artifacts / 'audit-contrast.json').write_text(json.dumps(results, indent=2), encoding='utf-8')


def run_frontend_audit(browser, origin, artifacts):
    context = browser.new_context(viewport={'width': 1280, 'height': 1000}, reduced_motion='reduce')
    tenant = '10000000-0000-4000-8000-000000000001'
    issuer = '20000000-0000-4000-8000-000000000001'
    member = '30000000-0000-4000-8000-000000000001'
    identity = {
        'actorId': 'audit-synthetic-actor', 'tenants': [{'tenantId': tenant, 'displayName': 'Organización de auditoría'}],
        'activeTenantId': tenant, 'csrfToken': 'a' * 43,
        'context': {'tenantId': tenant, 'roles': ['tenant_admin'], 'issuerIds': [], 'authorizationRevision': 1,
                    'capabilities': ['dashboard:read', 'members:read', 'members:update', 'members:revoke']},
    }
    session = {'authenticated': False, 'loading': True, 'pending': [], 'accept': 'network'}
    commands = []

    def route_console(route):
        path = urlsplit(route.request.url).path
        if path == '/console/api/me':
            if session['loading']:
                session['pending'].append(route)
            elif session['authenticated']:
                route.fulfill(json=identity)
            else:
                route.fulfill(status=401, json={'code': 'invalid_session'})
        elif path == '/console/auth/login':
            # No access page: an unauthenticated visit starts the provider login at once.
            # Keep the provider unreachable so the recovery state is what stays on screen.
            route.fulfill(status=503, json={'code': 'unavailable'})
        elif path.endswith('/memberships'):
            route.fulfill(json={'items': [{
                'tenantId': tenant, 'membershipId': member, 'operatorIdentityId': 'audit-target',
                'roles': ['support_readonly', 'issuer_operator'], 'issuerIds': [issuer],
                'state': 'active', 'revision': 1,
            }], 'nextCursor': None})
        elif path.endswith('/' + member):
            commands.append(route.request.post_data_json)
            # Exercise the request without changing scopes in the real database.
            route.fulfill(status=503, json={'code': 'unavailable'})
        elif path == '/console/api/invitation-acceptances':
            if session['accept'] == 'network':
                route.abort()
            else:
                route.fulfill(status=201, json={})
        elif path.endswith('/overview'):
            route.fulfill(status=503, json={'code': 'unavailable'})
        else:
            raise AssertionError('Unexpected UI fixture request path: ' + path)

    context.route(origin + '/console/**', route_console)
    page = context.new_page()
    page.goto(origin, wait_until='domcontentloaded')
    expect(page.get_by_role('heading', name='Comprobando tu sesión', exact=True)).to_be_visible()
    capture(page, artifacts, 'loading')
    session['loading'] = False
    for pending in session['pending']:
        pending.fulfill(status=401, json={'code': 'invalid_session'})
    expect(page.get_by_role('heading', name='No pudimos conectar', exact=True)).to_be_focused()
    expect(page.get_by_role('complementary', name='Así accedes a tu espacio').get_by_role('listitem')).to_have_count(3)
    expect(page.locator('input[type=password]')).to_have_count(0)
    login = page.get_by_role('button', name='Comprobar acceso', exact=True)
    expect(login).to_have_attribute('data-slot', 'button')
    page.keyboard.press('Tab')
    expect(login).to_be_focused()
    focus = login.evaluate('(el) => ({style: getComputedStyle(el).outlineStyle, width: getComputedStyle(el).outlineWidth})')
    assert focus == {'style': 'solid', 'width': '3px'}, focus
    assert login.bounding_box()['height'] >= 48
    capture(page, artifacts, 'recovery')
    check_palette(page, artifacts)
    panel = page.locator('.access-panel').bounding_box()
    paragraph = page.locator('.access-panel > p').bounding_box()
    button = login.bounding_box()
    assert panel['height'] < 450
    assert abs(button['x'] - paragraph['x']) < 1
    assert button['y'] >= paragraph['y'] + paragraph['height']

    # Each public link survives startup/reload and restores its actual target.
    session['authenticated'] = True
    for fragment in ['#members-title', '#overview', '#title', '#content']:
        page.goto(origin + '/' + fragment)
        page.reload()
        expect(page.locator(fragment)).to_be_focused()
        assert page.url.endswith(fragment)
    identity['context']['capabilities'] = ['dashboard:read']
    page.goto(origin + '/#members-title')
    expect(page.locator('#title')).to_be_focused()
    assert page.url.endswith('#title')
    expect(page.get_by_role('link', name='Sesión y organización')).to_have_attribute('aria-current', 'location')
    expect(page.get_by_role('region', name='Miembros e invitaciones')).to_have_count(0)
    identity['context']['capabilities'] = ['dashboard:read', 'members:read', 'members:update', 'members:revoke']

    # Unknown/sensitive fragments are still removed before React renders.
    for fragment in ['#unknown', '#invitation=invalid']:
        page.goto(origin + '/' + fragment)
        page.reload()
        expect(page.locator('#title')).to_be_focused()
        expect(page).to_have_url(origin + '/')
    capture(page, artifacts, 'workspace')

    code = page.get_by_label('Código de invitación')
    code.fill('incompleto')
    page.get_by_role('button', name='Aceptar invitación', exact=True).press('Enter')
    expect(code).to_be_focused()
    expect(code).to_have_attribute('aria-invalid', 'true')
    expect(code).to_have_attribute('aria-describedby', 'accept-help accept-error')
    expect(page.locator('#accept-error')).to_have_text('Introduce el código completo de la invitación.')
    expect(code).to_have_value('incompleto')
    capture(page, artifacts, 'code-error')
    code.fill('A' * 43)
    expect(code).to_have_attribute('aria-invalid', 'false')
    page.get_by_role('button', name='Aceptar invitación', exact=True).press('Enter')
    expect(page.get_by_role('region', name='Aceptar una invitación').get_by_role('alert')).to_contain_text('No se confirmó el resultado')
    expect(code).to_have_attribute('aria-invalid', 'false')
    expect(code).to_have_value('A' * 43)
    capture(page, artifacts, 'network-error')

    page.get_by_role('button', name='Editar acceso', exact=False).press('Enter')
    page.get_by_label('Operación de emisores', exact=True).uncheck()
    page.get_by_role('button', name='Revisar cambio', exact=True).press('Enter')
    dialog = page.get_by_role('dialog')
    expect(dialog).to_contain_text('perderá el acceso de operación')
    expect(dialog.get_by_role('listitem')).to_have_text(issuer)
    expect(dialog).to_contain_text(member)
    capture(page, artifacts, 'issuer-confirm')
    dialog.get_by_role('button', name='Volver a editar').press('Escape')
    expect(dialog).to_have_count(0)
    expect(page.get_by_role('button', name='Revisar cambio', exact=True)).to_be_focused()
    assert not commands
    page.get_by_role('button', name='Revisar cambio', exact=True).press('Enter')
    dialog.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(dialog).to_have_count(0)
    assert len(commands) == 1 and commands[0]['issuerIds'] == []
    assert commands[0]['roles'] == ['support_readonly']
    page.get_by_role('button', name='Volver al listado', exact=True).press('Enter')
    session['accept'] = 'success'
    page.get_by_role('button', name='Aceptar invitación', exact=True).press('Enter')
    expect(page.get_by_text('Invitación aceptada. Elige la organización para continuar.', exact=True)).to_be_visible()
    capture(page, artifacts, 'accept-success')
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
    context.close()
