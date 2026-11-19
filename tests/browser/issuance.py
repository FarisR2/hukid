"""Live Chromium E2E smoke for issuer console management (Emisores, Definiciones, Clientes) and read-only Ajustes."""
import json
from pathlib import Path
import re
import sys
import traceback
from urllib.parse import urljoin, urlsplit

from playwright.sync_api import expect, sync_playwright

from shell_ui import go_to, in_tenant, menu_action, switch_tenant


def run_issuance(page, context, config, database, _heading, _login, artifacts):
    origin = config['origin']
    in_tenant(page, 'Organización de prueba A')

    # Refresh MFA step-up before executing step-up-protected issuer mutations.
    with page.expect_navigation(wait_until='networkidle'):
        menu_action(page, 'Verificar identidad')
    page.wait_for_url(origin + '/')
    page.wait_for_load_state('networkidle')
    in_tenant(page, 'Organización de prueba A')

    # 1. Emisores: create issuer + initial KMS key, then rotate signing key.
    go_to(page, 'Emisores')
    emisores = page.get_by_role('region', name='emisores', exact=True)
    expect(emisores.get_by_text('Todavía no hay emisores registrados en esta organización.')).to_be_visible()
    emisores.get_by_role('button', name='Crear emisor', exact=True).click()
    form = emisores.locator('.issuance-form')
    form.get_by_label('Nombre visible').fill('Universidad Nacional Agraria de la Selva')
    form.get_by_label('Slug de la URL').fill('unas')
    form.get_by_role('button', name='Crear emisor y clave inicial', exact=True).click()
    expect(emisores.locator('.issuance-banner.success')).to_contain_text('Emisor creado. URI: https://issuer.hukid.pe/unas')
    expect(emisores.locator('tbody tr')).to_have_count(1)
    expect(emisores.locator('tbody tr').first).to_contain_text('Universidad Nacional Agraria de la Selva')
    expect(emisores.locator('tbody tr').first).to_contain_text('active')

    emisores.get_by_role('button', name='Rotar clave', exact=True).click()
    emisores.get_by_role('button', name='Confirmar rotación', exact=True).click()
    expect(emisores.locator('.issuance-banner.success')).to_contain_text('Clave rotada. KID nuevo:')
    page.screenshot(path=str(artifacts / 'issuance-emisores.png'), full_page=True)

    # 2. Definiciones: create draft, edit with ETag, and publish immutable version.
    go_to(page, 'Definiciones')
    definiciones = page.get_by_role('region', name='definiciones', exact=True)
    expect(definiciones.get_by_text('No hay definiciones para este emisor.')).to_be_visible()
    definiciones.locator('.issuance-toolbar').get_by_role('button', name='Crear borrador', exact=True).click()
    def_form = definiciones.locator('.issuance-form')
    def_form.get_by_label('ID de definición', exact=True).fill('unas-cert')
    def_form.get_by_label('Versión', exact=True).fill('1.0.0')
    def_form.get_by_label('Configuration ID', exact=True).fill('pe.edu.unas.cert.v1')
    def_form.get_by_label('Nombre visible', exact=True).fill('Certificado de Asistencia UNAS')
    def_form.get_by_label('Contextos (separados por coma)', exact=True).fill('https://issuer.hukid.pe/unas/contexts/unas-cert/1.0.0.jsonld')
    def_form.get_by_label('Tipos VC (separados por coma)', exact=True).fill('UnasCertificate')
    def_form.get_by_role('textbox', name='Especificación de campos en JSON', exact=True).fill('{"participantName":{"type":"string","required":true}}')
    def_form.get_by_role('button', name='Crear borrador', exact=True).click()
    expect(definiciones.locator('.issuance-banner.success')).to_contain_text('Borrador creado.')
    expect(definiciones.locator('tbody tr')).to_have_count(1)
    expect(definiciones.locator('tbody tr').first).to_contain_text('draft')

    definiciones.get_by_role('button', name='Editar', exact=True).click()
    expect(def_form.get_by_role('heading', name='Editar borrador', exact=True)).to_be_visible()
    def_form.get_by_label('Nombre visible').fill('Certificado Oficial UNAS')
    def_form.get_by_role('button', name='Guardar cambios', exact=True).click()
    expect(definiciones.locator('.issuance-banner.success')).to_contain_text('Borrador actualizado.')
    expect(definiciones.locator('tbody tr').first).to_contain_text('Certificado Oficial UNAS')

    page.once('dialog', lambda d: d.accept())
    definiciones.get_by_role('button', name='Publicar', exact=True).click()
    expect(definiciones.locator('.issuance-banner.success')).to_contain_text('Versión publicada e inmutable.')
    expect(definiciones.locator('tbody tr').first).to_contain_text('published')
    page.screenshot(path=str(artifacts / 'issuance-definiciones.png'), full_page=True)

    # 3. Clientes de integración: register, inspect one-time secret, rotate secret, revoke.
    go_to(page, 'Clientes de integración')
    clientes = page.get_by_role('region', name='clientes', exact=True)
    expect(clientes.get_by_text('No hay clientes de integración registrados.')).to_be_visible()
    clientes.locator('.issuance-toolbar').get_by_role('button', name='Registrar cliente', exact=True).click()
    cli_form = clientes.locator('.issuance-form')
    cli_form.get_by_label('Nombre del sistema').fill('Plataforma de Eventos UNAS')
    cli_form.get_by_label('Universidad Nacional Agraria de la Selva · unas').check()
    cli_form.get_by_role('button', name='Registrar cliente', exact=True).click()

    secret_dialog = page.get_by_role('dialog', name='Secreto de integración')
    expect(secret_dialog).to_be_visible()
    secret_one = secret_dialog.get_by_label('Secreto de cliente').input_value()
    assert secret_one.startswith('hks_') and len(secret_one) >= 24
    secret_dialog.get_by_role('button', name='Ya lo guardé', exact=True).click()
    expect(secret_dialog).to_have_count(0)
    expect(clientes.locator('tbody tr').first).to_contain_text('Plataforma de Eventos UNAS')
    expect(clientes.locator('tbody tr').first).to_contain_text('active')
    assert secret_one not in page.content()

    clientes.get_by_role('button', name='Rotar secreto', exact=True).click()
    expect(secret_dialog).to_be_visible()
    secret_two = secret_dialog.get_by_label('Secreto de cliente').input_value()
    assert secret_two.startswith('hks_') and secret_two != secret_one
    secret_dialog.get_by_role('button', name='Ya lo guardé', exact=True).click()
    expect(secret_dialog).to_have_count(0)
    assert secret_two not in page.content()

    page.once('dialog', lambda d: d.accept())
    clientes.get_by_role('button', name='Revocar', exact=True).click()
    expect(clientes.locator('.issuance-banner.success')).to_contain_text('Cliente revocado.')
    expect(clientes.locator('tbody tr').first).to_contain_text('revoked')
    page.screenshot(path=str(artifacts / 'issuance-clientes.png'), full_page=True)

    # 4. Read-only Ajustes view (tenant_admin only) & cross-tenant reload.
    with page.expect_response(lambda r: r.url.endswith('/console/api/settings')) as settings_resp:
        go_to(page, 'Ajustes')
    assert settings_resp.value.status == 200
    settings_json = settings_resp.value.json()
    assert settings_json['displayName'] == 'Organización de prueba A'
    assert settings_json['issuanceRuntimeEnabled'] is True
    assert settings_json['sessionPolicy']['sessionIdleSeconds'] == 1800
    assert settings_json['sessionPolicy']['stepUpSeconds'] == 300
    assert 'clientId' not in settings_json and 'issuer' not in settings_json

    ajustes = page.get_by_role('region', name='Ajustes de organización', exact=True)
    expect(ajustes.get_by_text('Organización de prueba A', exact=True)).to_be_visible()
    expect(ajustes.get_by_text('Activo en este entorno', exact=True)).to_be_visible()
    expect(ajustes.get_by_text('30 min (1800 s)', exact=True)).to_be_visible()
    expect(ajustes.get_by_text('Administración de organización', exact=True)).to_be_visible()
    expect(ajustes.get_by_role('button', name='Verificar identidad ahora', exact=True)).to_be_visible()
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.screenshot(path=str(artifacts / 'issuance-ajustes.png'), full_page=True)

    with page.expect_response(lambda r: r.url.endswith('/console/api/settings')) as refresh_resp:
        ajustes.get_by_role('button', name='Actualizar configuración', exact=True).click()
    assert refresh_resp.value.status == 200

    # 5. Cross-tenant isolation across Emisores and Ajustes.
    with page.expect_response(lambda r: r.url.endswith('/console/api/settings')) as tenant_b_settings:
        switch_tenant(page, 'Organización de prueba B')
    assert tenant_b_settings.value.status == 200
    assert tenant_b_settings.value.json()['displayName'] == 'Organización de prueba B'
    expect(ajustes.get_by_text('Organización de prueba B', exact=True)).to_be_visible()

    go_to(page, 'Emisores')
    expect(page.get_by_role('region', name='emisores', exact=True).get_by_text('Todavía no hay emisores registrados en esta organización.')).to_be_visible()
    switch_tenant(page, 'Organización de prueba A')

    # 6. Live Solicitudes & Credenciales (ADR-0034 issuance:read) + role gating for Ajustes/Solicitudes/Credenciales.
    nav = page.get_by_role('navigation', name='Secciones')
    expect(nav.get_by_role('link', name='Solicitudes', exact=True)).to_be_visible()
    expect(nav.get_by_role('link', name='Credenciales', exact=True)).to_be_visible()

    with page.expect_response(lambda r: '/issuance-requests' in r.url) as reqs_resp:
        go_to(page, 'Solicitudes')
    assert reqs_resp.value.status == 200
    assert reqs_resp.value.json()['items'] == []
    solicitudes = page.get_by_role('region', name='solicitudes', exact=True)
    expect(solicitudes.get_by_text('No hay solicitudes de emisión.')).to_be_visible()
    page.screenshot(path=str(artifacts / 'issuance-solicitudes.png'), full_page=True)

    with page.expect_response(lambda r: '/credentials' in r.url) as creds_resp:
        go_to(page, 'Credenciales')
    assert creds_resp.value.status == 200
    assert creds_resp.value.json()['items'] == []
    credenciales = page.get_by_role('region', name='credenciales', exact=True)
    expect(credenciales.get_by_text('No hay credenciales emitidas.')).to_be_visible()
    page.screenshot(path=str(artifacts / 'issuance-credenciales.png'), full_page=True)

    database('dashboard-readonly')
    denied = context.request.get(origin + '/console/api/settings')
    assert denied.status == 403 and denied.json()['code'] == 'forbidden', (denied.status, denied.text())
    page.goto(origin + '/#solicitudes')
    page.reload()
    expect(nav.get_by_role('link', name='Solicitudes', exact=True)).to_have_count(0)
    expect(nav.get_by_role('link', name='Credenciales', exact=True)).to_have_count(0)
    expect(nav.get_by_role('link', name='Ajustes', exact=True)).to_have_count(0)
    expect(page.locator('h1')).to_have_text('Solicitudes')
    expect(page.get_by_text('Tu rol no permite ver solicitudes')).to_be_visible()

    page.goto(origin + '/#ajustes')
    expect(page.locator('h1')).to_have_text('Ajustes')
    expect(page.get_by_text('Tu rol no permite ver ajustes')).to_be_visible()

    database('dashboard-admin')
    page.reload()
    expect(nav.get_by_role('link', name='Ajustes', exact=True)).to_be_visible()
    expect(nav.get_by_role('link', name='Solicitudes', exact=True)).to_be_visible()
    expect(nav.get_by_role('link', name='Credenciales', exact=True)).to_be_visible()
    expect(ajustes.get_by_text('Organización de prueba A', exact=True)).to_be_visible()

    page.evaluate("location.hash = '#resumen'")
    expect(page.locator('h1')).to_have_text('Resumen')
    print('Browser ISSUANCE+SETTINGS: Emisores/Definiciones/Clientes lifecycle, read-only Ajustes, role gating and cross-tenant isolation passed.', flush=True)


def main():
    config = json.loads(sys.stdin.readline())
    origin = config['origin']
    artifacts = Path('.cache/browser-auth')
    artifacts.mkdir(parents=True, exist_ok=True)

    def database(action):
        print(action, flush=True)
        result = json.loads(sys.stdin.readline())
        assert result['ok']
        return result

    def session_cookie(context):
        return next((c['value'] for c in context.cookies() if c['name'] == 'hukid_test_session'), None)

    def wait_new_session(page, before):
        for _ in range(150):
            page.wait_for_timeout(100)
            now = session_cookie(page.context)
            if now and now != before:
                break
        else:
            raise AssertionError('Expected an automatic provider login')
        page.wait_for_url(origin + '/', timeout=5000)
        page.wait_for_load_state('networkidle')

    def login(page):
        if session_cookie(page.context):
            page.wait_for_url(origin + '/', timeout=5000)
            page.wait_for_load_state('networkidle')
        else:
            wait_new_session(page, None)

    def redact(text):
        return re.sub(r'[A-Za-z0-9_\-+/=]{32,}', '<redacted>', text)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
        try:
            def authorize(route):
                response = route.fetch(max_redirects=0)
                for _ in range(12):
                    assert response.status in (302, 303)
                    target = urljoin(response.url, response.headers['location'])
                    if not target.startswith(config['issuer'] + '/'):
                        assert target.startswith(origin + '/console/auth/callback?')
                        route.fulfill(response=response)
                        return
                    headers = {'X-Hukid-Test-Interaction': config['interactionKey'], 'X-Hukid-Test-Account': 'operator-test-a'} if urlsplit(target).path.startswith('/interaction/') else {}
                    response = context.request.get(target, headers=headers, max_redirects=0)
                raise AssertionError('Synthetic authorization exceeded redirect bound')

            context.route(config['issuer'] + '/auth?*', authorize)
            page = context.new_page()
            errors = []
            page.on('pageerror', lambda e: errors.append(str(e)))
            page.goto(origin)
            login(page)
            expect(page.get_by_role('heading', name='Acceso pendiente', exact=True)).to_be_visible()
            database('seed')
            page.get_by_role('button', name='Comprobar acceso', exact=True).click()
            expect(page.get_by_role('heading', name='Elige una organización', exact=True)).to_be_visible()
            page.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
            page.get_by_role('button', name='Continuar', exact=True).click()
            run_issuance(page, context, config, database, None, login, artifacts)
            assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
            assert not errors, errors
        except BaseException:
            parts = [redact(''.join(traceback.format_exception_only(*sys.exc_info()[:2])).strip())]
            for idx, p in enumerate(context.pages):
                try:
                    parts.append(f'--- page {idx} {urlsplit(p.url).path or "/"}\n{redact(p.locator("body").aria_snapshot(timeout=3000))[:3000]}')
                except Exception:
                    pass
            print('\n'.join(parts), file=sys.stderr, flush=True)
            raise
        finally:
            context.close()
            browser.close()


if __name__ == '__main__':
    main()
