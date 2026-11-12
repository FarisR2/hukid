"""AUTH-T08: real Chromium -> Vite -> Go BFF -> synthetic OIDC -> disposable DB.

Only the test harness can complete synthetic IdP interactions. Runtime secrets
arrive through stdin and are never printed, saved in traces or screenshots.
"""
import json
from pathlib import Path
import os
import re
import sys
import traceback
from urllib.parse import urlsplit, urljoin

from playwright.sync_api import sync_playwright, expect
from shell_ui import USER_BUTTON, in_tenant, menu_action, switch_tenant
from members import run_members
from dashboard import run_dashboard
from frontend_audit import capture, run_frontend_audit

config = json.loads(sys.stdin.readline())
origin = config['origin']
artifacts = Path('.cache/browser-auth')
artifacts.mkdir(parents=True, exist_ok=True)


def database(action):
    print(action, flush=True)
    result = json.loads(sys.stdin.readline())
    assert result['ok']
    return result


def heading(page, name):
    try:
        expect(page.get_by_role('heading', name=name, exact=True)).to_be_visible()
    except AssertionError:
        print('Observed headings: ' + repr(page.locator('h1').all_text_contents()), file=sys.stderr)
        raise


def redact(text):
    return re.sub(r'[A-Za-z0-9_\-+/=]{32,}', '<redacted>', text)


def dump_failure(exc_info):
    """On failure print what each open page shows, so a CI log alone is enough to diagnose it.
    Only the URL path is printed (the query carries state/code) and long token-like strings are redacted.
    On GitHub Actions the same text is also emitted as an error annotation, which the public
    check-runs API serves without authentication (job logs need a login)."""
    parts = [redact(''.join(traceback.format_exception_only(exc_info[0], exc_info[1])).strip())]
    try:
        for index, candidate in enumerate(context.pages):
            snapshot = redact(candidate.locator('body').aria_snapshot(timeout=3000))
            # Controls first: long tables can push them past the size cap.
            controls = candidate.evaluate("() => [...document.querySelectorAll('button, [role=button]')].map(e => (e.getAttribute('aria-label') || e.textContent).trim()).filter(Boolean)")
            parts.append(f'--- page {index} {urlsplit(candidate.url).path or "/"}\nbuttons: {redact(repr(controls))[:900]}\n{snapshot[:3500]}')
    except Exception as error:
        parts.append('failure dump unavailable: ' + type(error).__name__)
    report = '\n'.join(parts)
    print(report, file=sys.stderr, flush=True)
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        # Workflow-command escaping: % first, then CR and LF. Stay far below the annotation size cap.
        escaped = report[:20000].replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        print(f'::error title=Browser journey failed::{escaped}', file=sys.stderr, flush=True)


def session_cookie(context):
    return next((c['value'] for c in context.cookies() if c['name'] == 'hukid_test_session'), None)


def wait_new_session(page, before):
    """The console has no access page: without a valid session it goes straight to the
    provider and must come back with a different session cookie."""
    for _ in range(150):
        page.wait_for_timeout(100)
        now = session_cookie(page.context)
        if now and now != before:
            break
    else:
        print('No new session; headings: ' + repr(page.locator('h1').all_text_contents()), file=sys.stderr)
        raise AssertionError('Expected an automatic provider login')
    page.wait_for_url(origin + '/', timeout=5000)
    page.wait_for_load_state('networkidle')


def login(page):
    """Opening the console signs in at the synthetic provider; no button is involved.
    With a session already present the page simply settles on the console."""
    if session_cookie(page.context):
        page.wait_for_url(origin + '/', timeout=5000)
        page.wait_for_load_state('networkidle')
    else:
        wait_new_session(page, None)


def sign_out(page):
    """Logout is local; the console immediately starts a new provider login."""
    before = session_cookie(page.context)
    if page.get_by_role('button', name=USER_BUTTON).count():
        menu_action(page, 'Cerrar sesión')
    else:
        page.get_by_role('button', name='Cerrar sesión', exact=True).click()
    wait_new_session(page, before)


def private_storage(page, context):
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
    assert 'hukid_test_session' not in page.evaluate('document.cookie')
    session = next(c for c in context.cookies() if c['name'] == 'hukid_test_session')
    assert session['httpOnly'] and session['sameSite'] == 'Lax'
    assert session['value'] not in page.content()
    assert not any(key in page.content() for key in ['access_token', 'refresh_token', 'id_token', 'csrfToken'])
    assert page.url == origin + '/'


with sync_playwright() as playwright:
    try:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
        context.add_init_script("""(() => {
          window.authMetrics = {lcpMs: 0, cls: 0, maxInteractionMs: 0};
          window.authLayoutShifts = [];
          new PerformanceObserver(list => { for (const e of list.getEntries()) window.authMetrics.lcpMs = e.startTime; }).observe({type: 'largest-contentful-paint', buffered: true});
          new PerformanceObserver(list => { for (const e of list.getEntries()) if (!e.hadRecentInput) {
            window.authMetrics.cls += e.value;
            window.authLayoutShifts.push({value: e.value, sources: e.sources.map(s => ({
              tag: s.node?.tagName, className: typeof s.node?.className === 'string' ? s.node.className : '',
              previous: s.previousRect.toJSON(), current: s.currentRect.toJSON()
            }))});
          } }).observe({type: 'layout-shift', buffered: true});
          new PerformanceObserver(list => { for (const e of list.getEntries()) if (e.interactionId) window.authMetrics.maxInteractionMs = Math.max(window.authMetrics.maxInteractionMs, e.duration); }).observe({type: 'event', durationThreshold: 16, buffered: true});
        })();""")

        # Synthetic MFA is completed by the harness; the browser still navigates
        # to the real IdP and the real callback. No cookie/token is fabricated.
        # Playwright routing only handles the first request in a redirect chain.
        def authorize(route, current_context=context, account='operator-test-a'):
            response = route.fetch(max_redirects=0)
            for _ in range(12):
                assert response.status in (302, 303)
                target = urljoin(response.url, response.headers['location'])
                if not target.startswith(config['issuer'] + '/'):
                    assert target.startswith(origin + '/console/auth/callback?')
                    route.fulfill(response=response)
                    return
                headers = {'X-Hukid-Test-Interaction': config['interactionKey'], 'X-Hukid-Test-Account': account} if urlsplit(target).path.startswith('/interaction/') else {}
                response = current_context.request.get(target, headers=headers, max_redirects=0)
            raise AssertionError('Synthetic authorization exceeded redirect bound')
        context.route(config['issuer'] + '/auth?*', lambda route: authorize(route))
        page = context.new_page()
        context.new_cdp_session(page).send('Emulation.setCPUThrottlingRate', {'rate': 4})
        errors = []
        page.on('pageerror', lambda _: errors.append('uncaught browser error'))
        page.goto(origin)
        login(page)
        heading(page, 'Acceso pendiente')
        capture(page, artifacts, 'access-pending')
        expect(page.get_by_label('Organización', exact=True)).to_have_count(0)
        private_storage(page, context)
        sign_out(page)
        heading(page, 'Acceso pendiente')
        recheck = page.get_by_role('button', name='Comprobar acceso', exact=True)
        recheck.click()
        # Nothing was granted yet: the screen stays put, says so, and keeps focus on the button.
        expect(page.get_by_role('status')).to_have_text('Todavía no tienes una organización asignada.')
        expect(recheck).to_be_focused()
        heading(page, 'Acceso pendiente')
        database('seed')
        recheck.click()
        heading(page, 'Elige una organización')
        expect(page.locator('h1')).to_be_focused()
        page.get_by_role('button', name='Continuar', exact=True).click()
        expect(page.get_by_role('alert')).to_have_text('Elige una organización para continuar.')
        expect(page.get_by_label('Organización', exact=True)).to_be_focused()
        expect(page.get_by_label('Organización', exact=True)).to_have_attribute('data-slot', 'native-select')
        capture(page, artifacts, 'organization-selection')
        # The picker has its own sign-out: someone on the wrong account must not be stuck here.
        sign_out(page)
        heading(page, 'Elige una organización')
        select = page.get_by_label('Organización', exact=True)
        select.press('ArrowDown')
        select.press('Tab')
        page.get_by_role('button', name='Continuar', exact=True).press('Enter')
        in_tenant(page, 'Organización de prueba A')
        private_storage(page, context)
        before = next(c['value'] for c in context.cookies() if c['name'] == 'hukid_test_session')
        menu_action(page, 'Renovar sesión')
        in_tenant(page, 'Organización de prueba A')
        after = next(c['value'] for c in context.cookies() if c['name'] == 'hukid_test_session')
        assert after != before
        with page.expect_navigation(wait_until='networkidle'):
            menu_action(page, 'Verificar identidad')
        page.wait_for_url(origin + '/')
        page.wait_for_load_state('networkidle')
        in_tenant(page, 'Organización de prueba A')
        # The sidebar switcher changes organization as soon as an option is chosen.
        page.get_by_label('Cambiar de organización', exact=True).select_option(label='Organización de prueba B')
        in_tenant(page, 'Organización de prueba B')
        private_storage(page, context)

        metrics = page.evaluate('window.authMetrics')
        (artifacts / 'layout-shifts.json').write_text(json.dumps(page.evaluate('window.authLayoutShifts'), indent=2), encoding='utf-8')
        (artifacts / 'performance.json').write_text(json.dumps(metrics, indent=2), encoding='utf-8')
        def worst_shifts():
            """The budget is for the whole journey, so name the biggest contributors and what moved."""
            rect = lambda r: [round(r[k]) for k in ('x', 'y', 'width', 'height')]
            shifts = sorted(page.evaluate('window.authLayoutShifts'), key=lambda s: -s['value'])[:6]
            return [{'value': round(s['value'], 4), 'moved': [(x['tag'], x['className'][:50], rect(x['previous']), rect(x['current'])) for x in s['sources'][:3]]} for s in shifts]
        assert 0 < metrics['lcpMs'] <= 2500 and metrics['cls'] <= .1 and metrics['maxInteractionMs'] <= 200, (metrics, worst_shifts())
        for width in [320, 360, 768, 1024, 1440]:
            page.set_viewport_size({'width': width, 'height': 1000})
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
            # Only rendered controls count: the mobile menu button is display:none on desktop.
            # Offenders are collected so one run reports every undersized control.
            small = []
            for control in page.locator('button, select, header a, nav a').all():
                if not control.is_visible():
                    continue
                box = control.bounding_box()
                if not (box and box['height'] >= 44 and box['width'] >= 44):
                    small.append(control.evaluate("e => `${e.tagName.toLowerCase()}.${e.className} ${e.getAttribute('aria-label') || e.textContent.trim().slice(0, 30)}`") + f' {box and (round(box["width"]), round(box["height"]))}')
            assert not small, f'{width}px controls under 44px: {small}'
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
        in_tenant(other, 'Organización de prueba B')
        page.bring_to_front()
        page.get_by_label('Cambiar de organización', exact=True).select_option(label='Organización de prueba A')
        in_tenant(page, 'Organización de prueba A')
        other.bring_to_front()
        in_tenant(other, 'Organización de prueba A')
        other.close()
        page.bring_to_front()
        in_tenant(page, 'Organización de prueba A')

        database('suspend')
        page.reload()
        heading(page, 'Acceso pendiente')
        expect(page.locator('.sb-org-name')).to_have_count(0)
        database('resume')
        page.reload()
        heading(page, 'Elige una organización')
        page.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
        page.get_by_role('button', name='Continuar', exact=True).click()
        in_tenant(page, 'Organización de prueba A')

        # Dependency errors remain inside the console with an explicit retry.
        def unavailable(route):
            route.fulfill(status=503, content_type='application/problem+json', body=json.dumps({'code': 'dependency_unavailable'}))
        page.route('**/console/auth/refresh', unavailable)
        menu_action(page, 'Renovar sesión')
        heading(page, 'No pudimos conectar')
        page.unroute('**/console/auth/refresh', unavailable)
        page.get_by_role('button', name='Comprobar acceso', exact=True).click()
        in_tenant(page, 'Organización de prueba A')

        # Settle dashboard/context reads before expiring the session out of band;
        # otherwise an earlier 401 can remove the user menu before the click.
        page.wait_for_load_state('networkidle')
        database('expire')
        expired = session_cookie(context)
        menu_action(page, 'Renovar sesión')
        # An expired session sends the browser straight back to the provider: no stale view remains.
        wait_new_session(page, expired)
        heading(page, 'Elige una organización')
        expect(page.locator('.sb-org-name')).to_have_count(0)
        assert page.url == origin + '/'
        # The selection screen has no sign-out of its own: enter an organization, then leave from the menu.
        page.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
        page.get_by_role('button', name='Continuar', exact=True).click()
        in_tenant(page, 'Organización de prueba A')
        sign_out(page)
        heading(page, 'Elige una organización')
        # Browser history cannot restore an authorized view without a new /me.
        page.goto(origin + '/?history-test=1')
        page.go_back()
        heading(page, 'Elige una organización')

        # Failures before the redirect are presented in the SPA; no retry loop.
        context.clear_cookies()
        page.route('**/console/auth/login**', unavailable)
        page.reload()
        heading(page, 'No pudimos conectar')
        page.unroute('**/console/auth/login**', unavailable)
        page.goto(origin + '/console/auth/callback?state=private-state&code=private-code&iss=invalid')
        heading(page, 'No se pudo completar el acceso')
        assert 'private-state' not in page.content() and 'private-code' not in page.content()
        page.get_by_role('link', name='Volver a HukID').click()
        # A second automatic attempt right after a failure is refused: recovery view, no loop.
        heading(page, 'Acceso no completado')
        assert session_cookie(context) is None

        def forbidden(route):
            route.fulfill(status=403, content_type='application/problem+json', body=json.dumps({'code': 'mfa_required'}))
        page.route('**/console/api/me', forbidden)
        page.reload()
        heading(page, 'No se pudo autorizar el acceso')
        assert page.url == origin + '/'
        # Without a session this view only offers a new login, not a re-check.
        expect(page.get_by_role('button', name='Iniciar sesión de nuevo', exact=True)).to_be_visible()
        expect(page.get_by_role('button', name='Comprobar acceso', exact=True)).to_have_count(0)
        page.unroute('**/console/api/me', forbidden)
        page.route('**/console/api/me', lambda route: route.abort())
        # A dropped connection is the case that does offer "Comprobar acceso".
        page.reload()
        heading(page, 'No pudimos conectar')
        page.unroute('**/console/api/me')
        # Pin the one-attempt window so this check does not depend on elapsed time.
        page.evaluate("sessionStorage.setItem('hukid-auto-login', String(Date.now()))")
        page.get_by_role('button', name='Comprobar acceso', exact=True).click()
        heading(page, 'Acceso no completado')
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
        # Wait until the first /me has reached the route and is held in `late`. Page has no
        # wait_for_request, and a request that already arrived cannot be awaited as an event.
        for _ in range(200):
            if late: break
            page.wait_for_timeout(50)
        assert late, 'the first /me request never reached the route'
        page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow'))")
        in_tenant(page, 'Contexto nuevo')
        late[0].fulfill(status=401, content_type='application/problem+json', body='{"code":"invalid_session"}')
        in_tenant(page, 'Contexto nuevo')
        page.unroute('**/console/api/me', delayed_identity)
        def one_tenant(route):
            route.fulfill(status=200, content_type='application/json', body=json.dumps({
                'actorId': 'synthetic-actor', 'tenants': [{'tenantId': 'only-tenant', 'displayName': 'Única organización'}],
                'activeTenantId': None, 'context': None, 'csrfToken': 'a' * 43}))
        page.route('**/console/api/me', one_tenant)
        page.reload()
        heading(page, 'Elige una organización')
        expect(page.get_by_label('Organización', exact=True)).to_have_value('only-tenant')
        page.unroute('**/console/api/me', one_tenant)
        run_dashboard(page, context, config, database, heading, login, artifacts)
        run_members(page, context, browser, config, authorize, database, heading, login, artifacts)
        run_frontend_audit(browser, origin, artifacts)
        context.close()
        browser.close()
        print('Browser: login/pending/tenant/me/refresh/step-up/logout, live suspension, expiry, failures, keyboard, history, cross-tab, storage and responsive screenshots passed.', flush=True)
    except BaseException:
        dump_failure(sys.exc_info())
        raise
