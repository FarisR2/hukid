"""AUTH-T08: real Chromium -> Vite -> Go BFF -> synthetic OIDC -> disposable DB.

Only the test harness can complete synthetic IdP interactions. Runtime secrets
arrive through stdin and are never printed, saved in traces or screenshots.
"""
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit, urljoin

from playwright.sync_api import sync_playwright, expect

config = json.loads(sys.stdin.readline())
origin = config['origin']
artifacts = Path('.cache/browser-auth')
artifacts.mkdir(parents=True, exist_ok=True)


def database(action):
    print(action, flush=True)
    assert json.loads(sys.stdin.readline())['ok']


def heading(page, name):
    try:
        expect(page.get_by_role('heading', name=name, exact=True)).to_be_visible()
    except AssertionError:
        print('Observed headings: ' + repr(page.locator('h1').all_text_contents()), file=sys.stderr)
        raise


def login(page):
    with page.expect_navigation(wait_until='networkidle'):
        page.get_by_role('button', name='Iniciar sesión', exact=True).click()
    try:
        page.wait_for_url(origin + '/', timeout=5000)
    except Exception:
        print('Navigation did not return to console; headings: ' + repr(page.locator('h1').all_text_contents()), file=sys.stderr)
        raise
    page.wait_for_load_state('networkidle')


def private_storage(page, context):
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
    assert 'hukid_test_session' not in page.evaluate('document.cookie')
    session = next(c for c in context.cookies() if c['name'] == 'hukid_test_session')
    assert session['httpOnly'] and session['sameSite'] == 'Lax'
    assert session['value'] not in page.content()
    assert not any(key in page.content() for key in ['access_token', 'refresh_token', 'id_token', 'csrfToken'])
    assert page.url == origin + '/'


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
    context.add_init_script("""(() => {
      window.authMetrics = {lcpMs: 0, cls: 0, maxInteractionMs: 0};
      new PerformanceObserver(list => { for (const e of list.getEntries()) window.authMetrics.lcpMs = e.startTime; }).observe({type: 'largest-contentful-paint', buffered: true});
      new PerformanceObserver(list => { for (const e of list.getEntries()) if (!e.hadRecentInput) window.authMetrics.cls += e.value; }).observe({type: 'layout-shift', buffered: true});
      new PerformanceObserver(list => { for (const e of list.getEntries()) if (e.interactionId) window.authMetrics.maxInteractionMs = Math.max(window.authMetrics.maxInteractionMs, e.duration); }).observe({type: 'event', durationThreshold: 16, buffered: true});
    })();""")

    # Synthetic MFA is completed by the harness; the browser still navigates
    # to the real IdP and the real callback. No cookie/token is fabricated.
    # Playwright routing only handles the first request in a redirect chain.
    def authorize(route):
        response = route.fetch(max_redirects=0)
        for _ in range(12):
            assert response.status in (302, 303)
            target = urljoin(response.url, response.headers['location'])
            if not target.startswith(config['issuer'] + '/'):
                assert target.startswith(origin + '/console/auth/callback?')
                route.fulfill(response=response)
                return
            headers = {'X-Hukid-Test-Interaction': config['interactionKey']} if urlsplit(target).path.startswith('/interaction/') else {}
            response = context.request.get(target, headers=headers, max_redirects=0)
        raise AssertionError('Synthetic authorization exceeded redirect bound')
    context.route(config['issuer'] + '/auth?*', authorize)
    page = context.new_page()
    context.new_cdp_session(page).send('Emulation.setCPUThrottlingRate', {'rate': 4})
    errors = []
    page.on('pageerror', lambda _: errors.append('uncaught browser error'))
    page.goto(origin)
    page.wait_for_load_state('networkidle')
    heading(page, 'Accede a HukID')
    expect(page.locator('h1')).to_be_focused()
    page.screenshot(path=str(artifacts / 'login-desktop.png'), full_page=True)
    login(page)
    heading(page, 'Acceso pendiente')
    expect(page.get_by_label('Organización', exact=True)).to_have_count(0)
    private_storage(page, context)
    page.get_by_role('button', name='Cerrar sesión', exact=True).click()
    heading(page, 'Sesión cerrada')
    database('seed')
    login(page)
    heading(page, 'Elige una organización')
    expect(page.locator('h1')).to_be_focused()
    page.get_by_role('button', name='Continuar', exact=True).click()
    expect(page.get_by_role('alert')).to_have_text('Elige una organización para continuar.')
    expect(page.get_by_label('Organización', exact=True)).to_be_focused()
    select = page.get_by_label('Organización', exact=True)
    select.press('ArrowDown')
    select.press('Tab')
    page.get_by_role('button', name='Continuar', exact=True).press('Enter')
    heading(page, 'Organización de prueba A')
    private_storage(page, context)
    before = next(c['value'] for c in context.cookies() if c['name'] == 'hukid_test_session')
    page.get_by_role('button', name='Renovar sesión', exact=True).click()
    heading(page, 'Organización de prueba A')
    after = next(c['value'] for c in context.cookies() if c['name'] == 'hukid_test_session')
    assert after != before
    with page.expect_navigation(wait_until='networkidle'):
        page.get_by_role('button', name='Verificar identidad', exact=True).click()
    page.wait_for_url(origin + '/')
    page.wait_for_load_state('networkidle')
    heading(page, 'Organización de prueba A')
    select.select_option(label='Organización de prueba B')
    page.get_by_role('button', name='Cambiar organización', exact=True).click()
    heading(page, 'Organización de prueba B')
    expect(page.get_by_role('heading', name='Organización de prueba A', exact=True)).to_have_count(0)
    private_storage(page, context)

    metrics = page.evaluate('window.authMetrics')
    (artifacts / 'performance.json').write_text(json.dumps(metrics, indent=2), encoding='utf-8')
    assert 0 < metrics['lcpMs'] <= 2500 and metrics['cls'] <= .1 and metrics['maxInteractionMs'] <= 200, metrics
    for width in [320, 360, 768, 1024, 1440]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        for control in page.locator('button, select, header a').all():
            box = control.bounding_box()
            assert box and box['height'] >= 44 and box['width'] >= 44
        page.screenshot(path=str(artifacts / f'session-{width}.png'), full_page=True)
    page.emulate_media(color_scheme='dark', reduced_motion='reduce')
    page.screenshot(path=str(artifacts / 'session-dark.png'), full_page=True)
    page.emulate_media(color_scheme='light')
    # 200% browser-equivalent content reflow, independently from the 320px case.
    page.evaluate("document.documentElement.style.fontSize = '32px'")
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    page.evaluate("document.documentElement.style.fontSize = ''")

    # Cross-tab invalidation: no storage is used for auth or notifications.
    other = context.new_page()
    other.goto(origin)
    other.wait_for_load_state('networkidle')
    heading(other, 'Organización de prueba B')
    page.bring_to_front()
    page.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
    page.get_by_role('button', name='Cambiar organización', exact=True).click()
    heading(page, 'Organización de prueba A')
    other.bring_to_front()
    heading(other, 'Organización de prueba A')
    other.close()
    page.bring_to_front()
    heading(page, 'Organización de prueba A')

    database('suspend')
    page.reload()
    heading(page, 'Acceso pendiente')
    expect(page.get_by_role('heading', name='Organización de prueba A', exact=True)).to_have_count(0)
    database('resume')
    page.get_by_role('button', name='Comprobar acceso', exact=True).click()
    heading(page, 'Elige una organización')
    page.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
    page.get_by_role('button', name='Continuar', exact=True).click()
    heading(page, 'Organización de prueba A')

    # Dependency errors remain inside the console with an explicit retry.
    def unavailable(route):
        route.fulfill(status=503, content_type='application/problem+json', body=json.dumps({'code': 'dependency_unavailable'}))
    page.route('**/console/auth/refresh', unavailable)
    page.get_by_role('button', name='Renovar sesión', exact=True).click()
    heading(page, 'No pudimos conectar')
    page.unroute('**/console/auth/refresh', unavailable)
    page.get_by_role('button', name='Comprobar acceso', exact=True).click()
    heading(page, 'Organización de prueba A')

    database('expire')
    page.get_by_role('button', name='Renovar sesión', exact=True).click()
    heading(page, 'Vuelve a iniciar sesión')
    expect(page.get_by_role('heading', name='Organización de prueba A', exact=True)).to_have_count(0)
    assert page.url == origin + '/'
    login(page)
    heading(page, 'Elige una organización')
    page.get_by_role('button', name='Cerrar sesión', exact=True).click()
    heading(page, 'Sesión cerrada')
    # Browser history cannot restore an authorized view without a new /me.
    page.goto(origin + '/?history-test=1')
    page.go_back()
    heading(page, 'Accede a HukID')
    assert not any(c['name'] == 'hukid_test_session' for c in context.cookies())

    # Failures before redirect are presented in the SPA; no retry loop.
    page.route('**/console/auth/login**', unavailable)
    page.get_by_role('button', name='Iniciar sesión', exact=True).click()
    heading(page, 'No pudimos conectar')
    page.unroute('**/console/auth/login**', unavailable)
    page.goto(origin + '/console/auth/callback?state=private-state&code=private-code&iss=invalid')
    heading(page, 'No se pudo completar el acceso')
    assert 'private-state' not in page.content() and 'private-code' not in page.content()
    page.get_by_role('link', name='Volver a HukID').click()
    heading(page, 'Accede a HukID')

    def forbidden(route):
        route.fulfill(status=403, content_type='application/problem+json', body=json.dumps({'code': 'mfa_required'}))
    page.route('**/console/api/me', forbidden)
    page.reload()
    heading(page, 'No se pudo autorizar el acceso')
    assert page.url == origin + '/'
    page.unroute('**/console/api/me', forbidden)
    page.route('**/console/api/me', lambda route: route.abort())
    page.get_by_role('button', name='Comprobar acceso', exact=True).click()
    heading(page, 'No pudimos conectar')
    page.unroute('**/console/api/me')
    page.get_by_role('button', name='Comprobar acceso', exact=True).click()
    heading(page, 'Accede a HukID')
    assert not errors

    # A response belonging to an aborted page generation must never restore
    # the previous tenant after a newer /me has completed.
    late = []
    calls = [0]
    def delayed_identity(route):
        calls[0] += 1
        if calls[0] == 1:
            late.append(route)
            return
        route.fulfill(status=200, content_type='application/json', body=json.dumps({
            'actorId': 'synthetic-actor', 'tenants': [{'tenantId': 'tenant-b', 'displayName': 'Contexto nuevo'}],
            'activeTenantId': 'tenant-b', 'context': {'tenantId': 'tenant-b', 'capabilities': [], 'issuerIds': [], 'authorizationRevision': 1},
            'csrfToken': 'a' * 43}))
    page.route('**/console/api/me', delayed_identity)
    page.reload(wait_until='domcontentloaded')
    expect(page.get_by_role('heading', name='Comprobando tu sesión', exact=True)).to_be_visible()
    page.wait_for_request('**/console/api/me') if not late else None
    page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow'))")
    heading(page, 'Contexto nuevo')
    late[0].fulfill(status=401, content_type='application/problem+json', body='{"code":"invalid_session"}')
    heading(page, 'Contexto nuevo')
    page.unroute('**/console/api/me', delayed_identity)
    def one_tenant(route):
        route.fulfill(status=200, content_type='application/json', body=json.dumps({
            'actorId': 'synthetic-actor', 'tenants': [{'tenantId': 'only-tenant', 'displayName': 'Única organización'}],
            'activeTenantId': None, 'context': None, 'csrfToken': 'a' * 43}))
    page.route('**/console/api/me', one_tenant)
    page.reload()
    heading(page, 'Elige una organización')
    expect(page.get_by_label('Organización', exact=True)).to_have_value('only-tenant')
    context.close()
    browser.close()
    print('Browser: login/pending/tenant/me/refresh/step-up/logout, live suspension, expiry, failures, keyboard, history, cross-tab, storage and responsive screenshots passed.', flush=True)
