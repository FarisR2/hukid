"""DASH-T04: real BFF reads plus explicitly injected UI degradation/late responses."""
from playwright.sync_api import expect


def run_dashboard(page, context, config, database, heading, login, artifacts):
    page.goto(config['origin'])
    page.wait_for_load_state('networkidle')
    login(page)
    page.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
    with page.expect_response(lambda response: '/activity?' in response.url) as first_feed:
        page.get_by_role('button', name='Continuar', exact=True).press('Enter')
    assert first_feed.value.status == 200, f'Initial dashboard feed status: {first_feed.value.status}'
    heading(page, 'Organización de prueba A')
    dashboard = page.get_by_role('region', name='Resumen operativo')
    metric = dashboard.locator('.metric').filter(has=page.get_by_text('Miembros activos', exact=True))
    expect(metric.locator('.metric-value')).to_have_text('1')
    expect(metric.get_by_text('Disponible', exact=True)).to_be_visible()
    expect(page.get_by_text('Tu rol:', exact=True)).to_be_visible()
    expect(page.locator('.workspace-context')).to_contain_text('Administración de organización')
    expect(dashboard.get_by_text('Sin permiso', exact=True)).to_have_count(5)
    page.get_by_role('link', name='Resumen', exact=True).press('Enter')
    expect(page.get_by_role('link', name='Resumen', exact=True)).to_have_attribute('aria-current', 'location')
    assert page.locator('h1').count() == 1

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

    # Invalid input is preserved with focused recovery; no malformed read is sent.
    start = dashboard.get_by_label('Desde (UTC)')
    end = dashboard.get_by_label('Hasta (UTC)')
    original_from, original_to = start.input_value(), end.input_value()
    start.fill(original_to)
    dashboard.get_by_role('button', name='Aplicar periodo').press('Enter')
    expect(dashboard.locator('#range-error')).to_contain_text('fin debe ser posterior')
    expect(start).to_be_focused()
    start.fill(original_from)
    dashboard.get_by_role('button', name='Aplicar periodo').press('Enter')
    expect(metric.locator('.metric-value')).to_have_text('1')

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

    # A feed failure leaves the authorized overview usable and offers retry.
    def unavailable(route):
        route.fulfill(status=503, json={'code': 'dependency_unavailable'})
    page.route('**/activity?*', unavailable)
    dashboard.get_by_role('button', name='Actualizar resumen').press('Enter')
    expect(metric.locator('.metric-value')).to_have_text('1')
    expect(dashboard.get_by_role('alert')).to_contain_text('No pudimos cargar')
    page.unroute('**/activity?*', unavailable)
    with page.expect_response(lambda response: '/activity?' in response.url):
        dashboard.get_by_role('button', name='Reiniciar actividad').press('Enter')
    expect(page.get_by_role('region', name='Actividad reciente')).to_have_attribute('aria-busy', 'false')
    expect(dashboard.get_by_role('alert')).to_have_count(0)

    # UI-only pagination fixture: the real API's authenticated cursor is tested
    # by DASH-T03. Here pin binding of UTC filters and explicit cursor recovery.
    cursor = 'a' * 32
    page_requests = []
    def paginated(route):
        from urllib.parse import parse_qs, urlsplit
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
    dashboard.get_by_role('button', name='Reiniciar actividad').press('Enter')
    dashboard.get_by_role('button', name='Siguiente página de actividad').press('Enter')
    expect(dashboard.get_by_role('alert')).to_contain_text('La página ha caducado')
    assert page_requests[1]['cursor'] == [cursor]
    assert page_requests[0]['from'] == page_requests[1]['from'] and page_requests[0]['to'] == page_requests[1]['to']
    with page.expect_response(lambda response: '/activity?' in response.url):
        dashboard.get_by_role('button', name='Reiniciar actividad').press('Enter')
    expect(page.get_by_role('region', name='Actividad reciente')).to_have_attribute('aria-busy', 'false')
    expect(dashboard.get_by_role('alert')).to_have_count(0)
    page.unroute('**/activity?*', paginated)

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
    page.get_by_label('Organización', exact=True).select_option(label='Organización de prueba B')
    page.get_by_role('button', name='Cambiar organización', exact=True).press('Enter')
    heading(page, 'Organización de prueba B')
    expect(metric.locator('.metric-value')).to_have_text('2')
    assert late
    late[0][0].fulfill(response=late[0][1], json=late[0][2])
    expect(metric.locator('.metric-value')).to_have_text('2')
    assert '987.654' not in dashboard.inner_text()

    page.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
    page.get_by_role('button', name='Cambiar organización', exact=True).press('Enter')
    heading(page, 'Organización de prueba A')
    expect(metric.locator('.metric-value')).to_have_text('1')
    database('dashboard-readonly')
    # Real 403 on the feed revalidates /me, removes directory navigation and
    # stops fetching the feed. No browser-authored capabilities are trusted.
    dashboard.get_by_role('button', name='Reiniciar actividad').press('Enter')
    expect(page.locator('.workspace-context')).to_contain_text('Soporte de consulta')
    expect(page.get_by_role('link', name='Miembros e invitaciones')).to_have_count(0)
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
    page.get_by_role('button', name='Comprobar acceso', exact=True).press('Enter')
    heading(page, 'Organización de prueba A')
    expect(metric.locator('.metric-value')).to_have_text('1')

    # HTTP 401 returns to login and clears all dashboard data without a loop.
    page.route('**/overview?*', lambda route: route.fulfill(status=401, json={'code': 'invalid_credential'}), times=1)
    dashboard.get_by_role('button', name='Actualizar resumen').press('Enter')
    heading(page, 'Accede a HukID')
    expect(dashboard).to_have_count(0)
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
    # The injected failure did not revoke the real session: close it for USR.
    page.reload()
    heading(page, 'Organización de prueba A')
    page.get_by_role('button', name='Cerrar sesión', exact=True).click()
    heading(page, 'Sesión cerrada')
