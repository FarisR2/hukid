"""DASH-T04/T07: real BFF reads and explicit UI-only fault fixtures.

Two views share one component: Resumen (overview cards plus a five-event preview) and
Actividad (the full feed: 25 per page, cursor pagination, "Reiniciar actividad").
"""
from playwright.sync_api import expect
import json
from time import perf_counter
from urllib.parse import parse_qs, urlsplit, urlunsplit

from shell_ui import in_tenant, shows_role, switch_tenant


def go_to(page, view):
    """Sidebar navigation: one public hash per view."""
    page.get_by_role('navigation', name='Secciones').get_by_role('link', name=view, exact=True).click()
    expect(page.locator('h1')).to_have_text(view)


def run_dashboard(page, context, config, database, heading, login, artifacts):
    database('dashboard-activity')
    page.goto(config['origin'])
    page.wait_for_load_state('networkidle')
    login(page)
    page.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
    with page.expect_response(lambda response: '/activity?' in response.url) as preview_feed:
        page.get_by_role('button', name='Continuar', exact=True).press('Enter')
    assert preview_feed.value.status == 200, f'Initial dashboard feed status: {preview_feed.value.status}'
    in_tenant(page, 'Organización de prueba A')
    dashboard = page.get_by_role('region', name='Resumen operativo')
    metric = dashboard.locator('.metric').filter(has=page.get_by_text('Miembros activos', exact=True))
    expect(metric.locator('.metric-value')).to_have_text('1')
    expect(metric.get_by_text('Disponible', exact=True)).to_be_visible()
    shows_role(page, 'Administración de organización')
    expect(dashboard.get_by_text('Sin permiso', exact=True)).to_have_count(5)
    # The overview only previews the latest five events and links to the full feed.
    assert len(preview_feed.value.json()['items']) == 5
    expect(page.get_by_role('region', name='Actividad reciente').get_by_role('link', name='Ver toda la actividad')).to_be_visible()
    expect(dashboard.get_by_role('button', name='Siguiente página de actividad')).to_have_count(0)

    # Real cursor round-trip: two tenants have 30 seeded events each. Gather
    # only this tenant's pages through the UI and never persist IDs or cursors.
    with page.expect_response(lambda response: '/activity?' in response.url and 'cursor=' not in response.url) as first_feed:
        go_to(page, 'Actividad')
    assert first_feed.value.status == 200
    first = first_feed.value.json()
    assert len(first['items']) == 25 and first['nextCursor']
    activity = page.get_by_role('region', name='Actividad', exact=True)
    feed = page.get_by_role('region', name='Eventos de la organización')
    next_button = activity.get_by_role('button', name='Siguiente página de actividad')
    next_button.focus()
    before_page = perf_counter()
    with page.expect_response(lambda response: '/activity?' in response.url and 'cursor=' in response.url) as next_feed:
        page.keyboard.press('Enter')
    assert next_feed.value.status == 200
    second = next_feed.value.json()
    expect(feed).to_have_attribute('aria-busy', 'false')
    expect(activity.get_by_role('heading', name='Eventos de la organización')).to_be_focused()
    assert second['asOf'] == first['asOf'] and second['nextCursor'] is None
    ids = [item['eventId'] for item in first['items'] + second['items']]
    assert len(ids) == len(set(ids)) and len(ids) >= 30
    assert all(item['targetId'] != '10000000-0000-4000-8000-000000000002'
               for item in first['items'] + second['items'])
    (artifacts / 'dashboard-performance.json').write_text(json.dumps({
        'profile': 'synthetic loopback; Chromium; 4x CPU; 30 events per tenant; no SLA',
        'nextPageToRenderedMs': (perf_counter() - before_page) * 1000,
        'pages': 2, 'uniqueEvents': len(ids), 'pageLimit': 25,
    }, indent=2), encoding='utf-8')
    # With a cursor set the restart control is labelled "Volver al inicio".
    with page.expect_response(lambda response: '/activity?' in response.url and 'cursor=' not in response.url):
        activity.get_by_role('button', name='Volver al inicio').press('Enter')
    expect(activity.get_by_role('button', name='Reiniciar actividad')).to_be_visible()
    expect(next_button).to_be_visible()
    # Send a synthetic PII canary in malformed input to the real BFF. The Go
    # harness checks captured application logs after this request (never prints
    # them). This does not claim to cover external proxies or infrastructure.
    feed_url = urlsplit(first_feed.value.url)
    invalid = context.request.get(urlunsplit(feed_url._replace(query='')), params={
        'from': 'dashboard-pii-canary@example.invalid', 'to': '2026-11-01T00:00:00Z'})
    assert invalid.status == 422
    page.get_by_role('link', name='Resumen', exact=True).press('Enter')
    expect(page.get_by_role('link', name='Resumen', exact=True)).to_have_attribute('aria-current', 'page')
    assert page.locator('h1').count() == 1
    expect(dashboard).to_be_visible()

    for width in [320, 360, 768, 1024, 1440]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path=str(artifacts / f'dashboard-{width}.png'), full_page=True)
    page.emulate_media(color_scheme='dark')
    page.screenshot(path=str(artifacts / 'dashboard-dark.png'), full_page=True)
    page.emulate_media(color_scheme='light')
    page.evaluate("document.documentElement.style.fontSize='32px'")
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.evaluate("document.documentElement.style.fontSize=''")
    # The rest drives desktop controls; the sidebar is off-canvas below 900px.
    page.set_viewport_size({'width': 1440, 'height': 1000})

    # Invalid input is preserved with focused recovery; no malformed read is sent.
    start = dashboard.get_by_label('Desde (UTC)')
    end = dashboard.get_by_label('Hasta (UTC)')
    # Reach controls through the actual tab sequence, not locator.press alone.
    refresh = dashboard.get_by_role('button', name='Actualizar resumen')
    refresh.focus()
    page.keyboard.press('Tab')
    expect(start).to_be_focused()
    # datetime-local has browser-native subfields; traverse until the next
    # named control rather than assuming one Tab per input.
    for target in [end, dashboard.get_by_role('button', name='Aplicar periodo')]:
        for _ in range(20):
            page.keyboard.press('Tab')
            if target.evaluate('(element) => element === document.activeElement'):
                break
        expect(target).to_be_focused()
    for control in [start, end]:
        expect(control).to_have_attribute('aria-describedby', 'range-help range-error')
    original_from, original_to = start.input_value(), end.input_value()
    start.fill(original_to)
    dashboard.get_by_role('button', name='Aplicar periodo').press('Enter')
    expect(dashboard.locator('#range-error')).to_contain_text('fin debe ser posterior')
    expect(start).to_be_focused()
    expect(start).to_have_attribute('aria-invalid', 'true')
    start.fill(original_from)
    dashboard.get_by_role('button', name='Aplicar periodo').press('Enter')
    expect(metric.locator('.metric-value')).to_have_text('1')
    expect(start).to_have_attribute('aria-invalid', 'false')
    expect(dashboard.locator('#range-error')).to_be_empty()

    # Capture real payload and inject only the section state for UI coverage.
    degradation_calls = [0]
    def degraded(route):
        response = route.fetch()
        value = response.json()
        assert response.status == 200
        value['sections']['activeMembers'] = {'state': 'unavailable', 'value': None, 'asOf': None, 'reasonCode': 'source_not_implemented'}
        value['sections']['activeIssuers'] = {'state': 'stale', 'value': 7, 'asOf': value['generatedAt'], 'reasonCode': 'source_stale'}
        degradation_calls[0] += 1
        if degradation_calls[0] > 1:
            value['sections']['activeMembers'] = {'state': 'available', 'value': 0, 'asOf': value['generatedAt'], 'reasonCode': None}
            value['sections']['activeIssuers'] = {'state': 'error', 'value': None, 'asOf': None, 'reasonCode': 'source_error'}
        route.fulfill(response=response, json=value)
    page.route('**/overview?*', degraded)
    dashboard.get_by_role('button', name='Actualizar resumen').press('Enter')
    expect(metric.locator('.metric-value')).to_have_text('—')
    expect(metric).to_contain_text('Fuente no disponible')
    expect(dashboard.get_by_text('Dato antiguo', exact=True)).to_be_visible()
    page.screenshot(path=str(artifacts / 'dashboard-partial.png'), full_page=True)
    dashboard.get_by_role('button', name='Actualizar resumen').press('Enter')
    expect(metric.locator('.metric-value')).to_have_text('0')
    expect(dashboard.get_by_text('Error de la fuente', exact=True)).to_be_visible()
    page.unroute('**/overview?*', degraded)

    # A feed failure leaves the authorized overview usable; refreshing the overview retries it
    # (the overview preview has no feed-only controls).
    def unavailable(route):
        route.fulfill(status=503, json={'code': 'dependency_unavailable'})
    page.route('**/activity?*', unavailable)
    dashboard.get_by_role('button', name='Actualizar resumen').press('Enter')
    expect(metric.locator('.metric-value')).to_have_text('1')
    expect(dashboard.get_by_role('alert')).to_contain_text('No pudimos cargar')
    page.unroute('**/activity?*', unavailable)
    with page.expect_response(lambda response: '/activity?' in response.url):
        dashboard.get_by_role('button', name='Actualizar resumen').press('Enter')
    expect(page.get_by_role('region', name='Actividad reciente')).to_have_attribute('aria-busy', 'false')
    expect(dashboard.get_by_role('alert')).to_have_count(0)

    # UI-only pagination fixture on the Actividad view: the real API's authenticated cursor is
    # tested by DASH-T03. Here pin binding of UTC filters and explicit cursor recovery.
    go_to(page, 'Actividad')
    page.wait_for_load_state('networkidle')
    cursor = 'a' * 32
    page_requests = []
    def paginated(route):
        params = parse_qs(urlsplit(route.request.url).query)
        page_requests.append(params)
        if 'cursor' in params:
            route.fulfill(status=422, json={'code': 'invalid_cursor'})
            return
        response = route.fetch()
        value = response.json()
        value['nextCursor'] = cursor if len(page_requests) == 1 else None
        route.fulfill(response=response, json=value)
    page.route('**/activity?*', paginated)
    activity.get_by_role('button', name='Reiniciar actividad').press('Enter')
    activity.get_by_role('button', name='Siguiente página de actividad').press('Enter')
    expect(activity.get_by_role('alert')).to_contain_text('La página ha caducado')
    expect(activity.get_by_role('heading', name='Eventos de la organización')).to_be_focused()
    page.keyboard.press('Tab')
    # The rejected cursor stays set, so recovery is offered as "Volver al inicio".
    expect(activity.get_by_role('button', name='Volver al inicio')).to_be_focused()
    assert page_requests[1]['cursor'] == [cursor]
    assert page_requests[0]['from'] == page_requests[1]['from'] and page_requests[0]['to'] == page_requests[1]['to']
    with page.expect_response(lambda response: '/activity?' in response.url):
        activity.get_by_role('button', name='Volver al inicio').press('Enter')
    expect(feed).to_have_attribute('aria-busy', 'false')
    expect(activity.get_by_role('alert')).to_have_count(0)
    page.unroute('**/activity?*', paginated)
    go_to(page, 'Resumen')

    # Filter changes abort the previous generation, even if its response arrives.
    late = []
    def delay(route):
        response = route.fetch()
        value = response.json()
        value['sections']['activeMembers']['value'] = 987654
        late.append((route, response, value))
    page.route('**/overview?*', delay, times=1)
    dashboard.get_by_role('button', name='Actualizar resumen').press('Enter')
    expect(dashboard.get_by_text('Cargando resumen…')).to_be_visible()
    # Drive the event loop until the held response is ready.
    page.wait_for_function('true')
    end.fill('2026-11-01T12:00')
    start.fill('2026-10-31T12:00')
    dashboard.get_by_role('button', name='Aplicar periodo').press('Enter')
    expect(metric.locator('.metric-value')).to_have_text('1')
    assert late
    late[0][0].fulfill(response=late[0][1], json=late[0][2])
    expect(metric.locator('.metric-value')).to_have_text('1')
    expect(dashboard.get_by_text('No hay actividad en este periodo.', exact=False)).to_be_visible()

    # Tenant change also aborts the old generation; no A data appears in B.
    late.clear()
    page.route('**/overview?*', delay, times=1)
    dashboard.get_by_role('button', name='Actualizar resumen').press('Enter')
    expect(dashboard.get_by_text('Cargando resumen…')).to_be_visible()
    switch_tenant(page, 'Organización de prueba B')
    expect(metric.locator('.metric-value')).to_have_text('2')
    assert late
    late[0][0].fulfill(response=late[0][1], json=late[0][2])
    expect(metric.locator('.metric-value')).to_have_text('2')
    assert '987.654' not in dashboard.inner_text()

    switch_tenant(page, 'Organización de prueba A')
    expect(metric.locator('.metric-value')).to_have_text('1')
    database('dashboard-readonly')
    # Real 403 on the feed revalidates /me, removes the activity navigation and
    # stops fetching the feed. No browser-authored capabilities are trusted.
    dashboard.get_by_role('button', name='Actualizar resumen').press('Enter')
    shows_role(page, 'Soporte de consulta')
    nav = page.get_by_role('navigation', name='Secciones')
    expect(nav.get_by_role('link', name='Miembros', exact=True)).to_have_count(0)
    expect(nav.get_by_role('link', name='Actividad', exact=True)).to_have_count(0)
    expect(dashboard.get_by_text('No tienes permiso para consultar la actividad.')).to_be_visible()
    expect(metric.locator('.metric-value')).to_have_text('—')
    feed_requests = []
    def record_feed(request):
        if '/activity?' in request.url:
            feed_requests.append(request.url)
    page.on('request', record_feed)
    dashboard.get_by_role('button', name='Actualizar resumen').press('Enter')
    expect(metric.locator('.metric-value')).to_have_text('—')
    assert not feed_requests
    page.remove_listener('request', record_feed)
    database('dashboard-admin')
    # There is no re-check button once signed in; a reload re-reads the access.
    page.reload()
    in_tenant(page, 'Organización de prueba A')
    expect(metric.locator('.metric-value')).to_have_text('1')

    # HTTP 401 returns to login and clears all dashboard data without a loop.
    page.route('**/overview?*', lambda route: route.fulfill(status=401, json={'code': 'invalid_credential'}), times=1)
    before = next(c['value'] for c in context.cookies() if c['name'] == 'hukid_test_session')
    dashboard.get_by_role('button', name='Actualizar resumen').press('Enter')
    # A rejected credential restarts the provider login: a new session without an active tenant.
    heading(page, 'Elige una organización')
    expect(dashboard).to_have_count(0)
    assert next(c['value'] for c in context.cookies() if c['name'] == 'hukid_test_session') != before
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
