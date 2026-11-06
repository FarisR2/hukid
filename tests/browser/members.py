"""USR-T08: real UI commands and isolated OIDC recipient, with targeted failure injection."""
import json
from playwright.sync_api import expect


def run_members(page, context, browser, config, authorize, database, heading, login, artifacts):
    origin = config['origin']
    page.goto(origin)
    page.wait_for_load_state('networkidle')
    login(page)
    page.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
    page.get_by_role('button', name='Continuar', exact=True).click()
    heading(page, 'Organización de prueba A')
    management = page.get_by_role('region', name='Miembros e invitaciones')
    expect(management.get_by_role('listitem')).to_have_count(1)
    management.get_by_role('button', name='Invitaciones', exact=True).press('Enter')
    expect(management.get_by_text('No hay invitaciones con estos filtros.', exact=False)).to_be_visible()
    management.get_by_role('button', name='Invitar persona').press('Enter')
    expect(page.get_by_role('heading', name='Invitar a una persona')).to_be_focused()
    page.get_by_label('Correo del destinatario').fill('Browser+recipient@example.invalid')
    expect(page.get_by_label('Operación de emisores', exact=True)).to_be_disabled()

    # Lose the response after a real commit. Retry must reuse the key and ID.
    attempts = []
    def lose_response(route):
        attempts.append(route.request.headers['idempotency-key'])
        response = route.fetch()
        if len(attempts) == 1:
            assert response.status == 201
            route.abort()
        else:
            assert response.status == 201
            route.fulfill(response=response)
    page.route('**/invitations', lose_response, times=2)
    page.get_by_role('button', name='Crear invitación', exact=True).press('Enter')
    expect(page.get_by_role('alert')).to_contain_text('No se confirmó el resultado')
    expect(page.get_by_label('Correo del destinatario')).to_have_value('Browser+recipient@example.invalid')
    page.get_by_role('button', name='Crear invitación', exact=True).press('Enter')
    expect(management.get_by_role('listitem')).to_have_count(1)
    assert len(attempts) == 2 and attempts[0] == attempts[1]
    token = database('deliver-invitation')['token']

    guest = browser.new_context(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
    guest.route(config['issuer'] + '/auth?*', lambda route: authorize(route, guest, 'operator-test-b'))
    recipient = guest.new_page()
    recipient.goto(origin + '/#invitation=' + token)
    heading(recipient, 'Accede a HukID')
    assert recipient.url == origin + '/'
    login(recipient)
    heading(recipient, 'Acceso pendiente')
    expect(recipient.get_by_label('Código de invitación')).to_have_value('')
    recipient.goto(origin + '/#invitation=' + token)
    recipient.reload()
    heading(recipient, 'Acceso pendiente')
    assert recipient.get_by_label('Código de invitación').input_value() == token
    assert token not in recipient.content() and recipient.url == origin + '/'
    recipient.get_by_label('Código de invitación').press('Tab')
    expect(recipient.get_by_role('button', name='Aceptar invitación', exact=True)).to_be_focused()
    recipient.keyboard.press('Enter')
    heading(recipient, 'Elige una organización')
    expect(recipient.get_by_text('Invitación aceptada. Elige la organización para continuar.')).to_be_visible()
    recipient.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
    recipient.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
    recipient.get_by_role('button', name='Continuar', exact=True).press('Enter')
    heading(recipient, 'Organización de prueba A')
    expect(recipient.get_by_text('No tienes permiso para consultar miembros.', exact=False)).to_be_visible()
    assert recipient.evaluate('localStorage.length === 0 && sessionStorage.length === 0')

    page.get_by_role('button', name='Miembros', exact=True).press('Enter')
    expect(management.get_by_role('listitem')).to_have_count(2)
    member_rows = management.get_by_role('listitem')
    target_row = member_rows.filter(has_text='Soporte de consulta')
    target_id = target_row.locator('.record-summary .record-id').inner_text()
    target_row.get_by_role('button', name='Editar acceso', exact=False).press('Enter')
    page.get_by_label('Soporte de consulta', exact=True).uncheck()
    page.get_by_label('Administración de seguridad', exact=True).check()
    page.get_by_label('Razón del cambio').select_option('operator_request')
    def mfa_required(route):
        route.fulfill(status=403, content_type='application/problem+json', body=json.dumps({'code': 'mfa_required'}))
    page.route('**/memberships/*', mfa_required)
    page.get_by_role('button', name='Revisar cambio').press('Enter')
    page.get_by_role('dialog').get_by_role('button', name='Volver a editar').press('Enter')
    expect(page.get_by_role('dialog')).to_have_count(0)
    page.get_by_role('button', name='Revisar cambio').press('Enter')
    page.get_by_role('dialog').get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(page.get_by_role('alert')).to_contain_text('Verifica tu identidad')
    expect(page.get_by_label('Administración de seguridad', exact=True)).to_be_checked()
    page.unroute('**/memberships/*', mfa_required)
    database('stale-member')
    page.get_by_role('button', name='Revisar cambio').press('Enter')
    dialog = page.get_by_role('dialog')
    expect(dialog).to_contain_text(target_id)
    expect(dialog).to_contain_text('Solicitud del operador')
    expect(dialog.get_by_role('button', name='Volver a editar')).to_be_focused()
    page.screenshot(path=str(artifacts / 'members-confirm.png'), full_page=True)
    dialog.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(page.get_by_role('alert')).to_contain_text('Tu edición se conserva')
    expect(page.get_by_label('Administración de seguridad', exact=True)).to_be_checked()
    page.get_by_role('button', name='Cargar versión actual').press('Enter')
    expect(page.get_by_text('Versión actual 2:', exact=False)).to_be_visible()
    expect(page.get_by_label('Razón del cambio')).to_have_value('operator_request')
    page.screenshot(path=str(artifacts / 'members-conflict-recovered.png'), full_page=True)
    page.get_by_role('button', name='Revisar cambio').press('Enter')
    dialog.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(management.get_by_role('listitem').filter(has_text=target_id)).to_contain_text('Administración de seguridad')
    recipient.reload()
    expect(recipient.get_by_role('listitem')).to_have_count(2)
    recipient.get_by_role('button', name='Invitaciones', exact=True).press('Enter')
    expect(recipient.get_by_text('No tienes permiso para consultar invitaciones.', exact=False)).to_be_visible()

    # All viewport screenshots contain synthetic IDs only.
    for width in [320, 360, 768, 1024, 1440]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        expect(page.locator('h1')).to_have_count(1)
        for control in management.locator('button, select, input').all():
            box = control.bounding_box()
            assert box and box['height'] >= 44 and box['width'] >= 44
        page.screenshot(path=str(artifacts / f'members-{width}.png'), full_page=True)
    page.emulate_media(color_scheme='dark')
    page.screenshot(path=str(artifacts / 'members-dark.png'), full_page=True)
    page.emulate_media(color_scheme='light')
    page.evaluate("document.documentElement.style.fontSize = '32px'")
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    page.evaluate("document.documentElement.style.fontSize = ''")

    row = management.get_by_role('listitem').filter(has_text=target_id)
    row.get_by_role('button', name='Editar acceso', exact=False).press('Enter')
    page.get_by_label('Estado del acceso').select_option('suspended')
    page.get_by_role('button', name='Revisar cambio').press('Enter')
    dialog.get_by_role('button', name='Volver a editar').press('Escape')
    expect(dialog).to_have_count(0)
    expect(page.get_by_role('button', name='Revisar cambio')).to_be_focused()
    page.get_by_role('button', name='Revisar cambio').press('Enter')
    dialog.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(management.get_by_role('listitem').filter(has_text=target_id)).to_contain_text('Suspendido')
    recipient.reload()
    heading(recipient, 'Acceso pendiente')

    # The server protects the last admin; the draft and reason remain recoverable.
    management.get_by_role('listitem').filter(has_text='Administración de organización').get_by_role('button', name='Editar acceso', exact=False).press('Enter')
    page.get_by_label('Estado del acceso').select_option('suspended')
    page.get_by_role('button', name='Revisar cambio').press('Enter')
    dialog.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(page.get_by_role('alert')).to_contain_text('Debe quedar al menos un administrador activo')
    page.get_by_role('button', name='Volver al listado').press('Enter')

    # Reactivation keeps grants; revocation is terminal in the editor.
    row = management.get_by_role('listitem').filter(has_text=target_id)
    row.get_by_role('button', name='Editar acceso', exact=False).press('Enter')
    page.get_by_label('Estado del acceso').select_option('active')
    page.get_by_role('button', name='Revisar cambio').press('Enter')
    dialog.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(management.get_by_role('listitem').filter(has_text=target_id)).to_contain_text('Activo')
    recipient.reload()
    heading(recipient, 'Elige una organización')
    row.get_by_role('button', name='Editar acceso', exact=False).press('Enter')
    page.get_by_label('Estado del acceso').select_option('revoked')
    page.get_by_role('button', name='Revisar cambio').press('Enter')
    expect(dialog).to_contain_text('La revocación es definitiva')
    # A missing row also has zero buttons. Wait for the committed state and
    # context revalidation/focus before sending the next keyboard action.
    with page.expect_response(lambda response: response.url == origin + '/console/api/me' and response.request.method == 'GET'):
        dialog.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(page.locator('h1')).to_be_focused()
    expect(management.get_by_role('listitem').filter(has_text=target_id)).to_contain_text('Revocado')
    expect(management.get_by_role('listitem').filter(has_text=target_id).get_by_role('button')).to_have_count(0)

    # A new recipient can receive another invitation, then the admin revokes it.
    management.get_by_role('button', name='Invitaciones', exact=True).press('Enter')
    management.get_by_role('button', name='Invitar persona').press('Enter')
    page.get_by_label('Correo del destinatario').fill('Another+recipient@example.invalid')
    page.get_by_role('button', name='Crear invitación', exact=True).press('Enter')
    expect(management.get_by_role('listitem')).to_have_count(2)

    management.get_by_role('button', name='Revocar invitación', exact=False).press('Enter')
    page.get_by_label('Razón del cambio').select_option('invitation_cancelled')
    page.get_by_role('button', name='Revisar cambio').press('Enter')
    expect(dialog).to_contain_text('Cancelación de invitación')
    dialog.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(management.get_by_role('listitem').filter(has_text='Revocado')).to_have_count(1)

    def unavailable(route):
        route.fulfill(status=503, content_type='application/problem+json', body=json.dumps({'code': 'dependency_unavailable'}))
    page.route('**/invitations?*', unavailable)
    management.get_by_role('button', name='Actualizar listado').press('Enter')
    expect(management.get_by_role('alert')).to_contain_text('No se confirmó el resultado')
    page.unroute('**/invitations?*', unavailable)
    management.get_by_role('button', name='Reintentar desde el inicio').press('Enter')
    expect(management.get_by_role('listitem')).to_have_count(2)
    management.get_by_role('button', name='Invitar persona').press('Enter')
    page.get_by_label('Correo del destinatario').fill('Browser+recipient@example.invalid')
    page.get_by_role('button', name='Crear invitación', exact=True).press('Enter')
    expect(management.get_by_role('listitem')).to_have_count(3)
    expired_token = database('deliver-invitation')['token']
    database('expire-invitation')
    management.get_by_role('button', name='Actualizar listado').press('Enter')
    expect(management.get_by_role('listitem').filter(has_text='Expirada')).to_have_count(1)
    recipient.goto(origin + '/#invitation=' + expired_token)
    recipient.reload()
    heading(recipient, 'Acceso pendiente')
    recipient.get_by_role('button', name='Aceptar invitación', exact=True).press('Enter')
    expect(recipient.get_by_role('alert')).to_contain_text('La invitación no está disponible')
    assert expired_token not in recipient.content() and recipient.url == origin + '/'
    assert token not in page.content() and token not in recipient.content()
    guest.close()
    print('Browser USR-T08: real invitation/recipient acceptance/roles/suspension/revocation, lost-response replay, 412 draft recovery, last admin, permissions, keyboard and responsive states passed.', flush=True)
