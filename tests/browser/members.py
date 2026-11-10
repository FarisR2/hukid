"""USR-T08: real UI commands and isolated OIDC recipient, with targeted failure injection.

Members and invitations are separate sidebar views with table listings. The invite form and the
invitation-code form are modal dialogs; the access editor is a side-panel dialog and its change
confirmation is a second dialog nested inside it, so dialogs are always addressed by name.
"""
import json
from playwright.sync_api import expect

from shell_ui import go_to, in_tenant


def undersized(container):
    """Visible controls under the 44px touch target, as readable strings."""
    small = []
    for control in container.locator('button, select, input').all():
        if not control.is_visible():
            continue
        box = control.bounding_box()
        if not (box and box['height'] >= 44 and box['width'] >= 44):
            label = control.evaluate("e => `${e.tagName.toLowerCase()} ${e.getAttribute('aria-label') || e.textContent.trim().slice(0, 30) || e.type}`")
            small.append(f'{label} {box and (round(box["width"]), round(box["height"]))}')
    return small


def run_members(page, context, browser, config, authorize, database, heading, login, artifacts):
    origin = config['origin']
    page.goto(origin)
    page.wait_for_load_state('networkidle')
    login(page)
    page.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
    page.get_by_role('button', name='Continuar', exact=True).click()
    in_tenant(page, 'Organización de prueba A')
    members = page.get_by_role('region', name='Miembros', exact=True)
    invitations = page.get_by_role('region', name='Invitaciones', exact=True)
    invite = page.get_by_role('dialog', name='Invitar persona')
    editor = page.get_by_role('dialog', name='Editar acceso')
    revoker = page.get_by_role('dialog', name='Revocar invitación')
    confirm = page.get_by_role('dialog', name='Confirmar cambio de acceso')
    go_to(page, 'Miembros')
    expect(members.locator('tbody tr')).to_have_count(1)
    go_to(page, 'Invitaciones')
    expect(invitations.get_by_text('No hay invitaciones con estos filtros.', exact=False)).to_be_visible()
    invitations.get_by_role('button', name='Invitar persona').press('Enter')
    expect(invite.get_by_role('heading', name='Invitar a una persona')).to_be_focused()
    invite.get_by_label('Correo del destinatario').fill('Browser+recipient@example.invalid')
    expect(invite.get_by_label('Operación de emisores', exact=True)).to_be_disabled()

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
    invite.get_by_role('button', name='Crear invitación', exact=True).press('Enter')
    expect(invite.get_by_role('alert')).to_contain_text('No se confirmó el resultado')
    expect(invite.get_by_label('Correo del destinatario')).to_have_value('Browser+recipient@example.invalid')
    invite.get_by_role('button', name='Crear invitación', exact=True).press('Enter')
    expect(invite).to_have_count(0)
    expect(invitations.locator('tbody tr')).to_have_count(1)
    assert len(attempts) == 2 and attempts[0] == attempts[1]
    token = database('deliver-invitation')['token']

    guest = browser.new_context(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
    guest.route(config['issuer'] + '/auth?*', lambda route: authorize(route, guest, 'operator-test-b'))
    recipient = guest.new_page()
    accept = recipient.get_by_role('dialog', name='Aceptar una invitación')
    recipient.goto(origin + '/#invitation=' + token)
    login(recipient)
    assert recipient.url == origin + '/'
    heading(recipient, 'Acceso pendiente')
    # The code lives in memory only: the login round trip discards it, so nothing is prefilled.
    expect(accept).to_have_count(0)
    recipient.get_by_role('button', name='Tengo un código de invitación').click()
    expect(accept.get_by_label('Código de invitación')).to_have_value('')
    recipient.keyboard.press('Escape')
    expect(accept).to_have_count(0)
    recipient.goto(origin + '/#invitation=' + token)
    recipient.reload()
    heading(recipient, 'Acceso pendiente')
    # A fragment that survives startup opens the dialog with the code, then leaves the URL.
    assert accept.get_by_label('Código de invitación').input_value() == token
    assert token not in recipient.content() and recipient.url == origin + '/'
    accept.get_by_label('Código de invitación').press('Tab')
    expect(accept.get_by_role('button', name='Aceptar invitación', exact=True)).to_be_focused()
    recipient.keyboard.press('Enter')
    expect(accept.get_by_text('Invitación aceptada. Elige la organización para continuar.')).to_be_visible()
    # The dialog stays open on success; close it to reach the organization chooser behind it.
    recipient.keyboard.press('Escape')
    expect(accept).to_have_count(0)
    heading(recipient, 'Elige una organización')
    recipient.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
    recipient.get_by_role('button', name='Continuar', exact=True).press('Enter')
    in_tenant(recipient, 'Organización de prueba A')
    recipient_nav = recipient.get_by_role('navigation', name='Secciones')
    expect(recipient_nav.get_by_role('link', name='Miembros', exact=True)).to_have_count(0)
    expect(recipient_nav.get_by_role('link', name='Invitaciones', exact=True)).to_have_count(0)
    assert recipient.evaluate('localStorage.length === 0 && sessionStorage.length === 0')

    go_to(page, 'Miembros')
    rows = members.locator('tbody tr')
    expect(rows).to_have_count(2)
    target_row = rows.filter(has_text='Soporte de consulta')
    target_id = target_row.locator('.record-id').first.inner_text()
    target_row.get_by_role('button', name='Editar acceso', exact=False).press('Enter')
    editor.get_by_label('Soporte de consulta', exact=True).uncheck()
    editor.get_by_label('Administración de seguridad', exact=True).check()
    editor.get_by_label('Razón del cambio').select_option('operator_request')
    def mfa_required(route):
        route.fulfill(status=403, content_type='application/problem+json', body=json.dumps({'code': 'mfa_required'}))
    page.route('**/memberships/*', mfa_required)
    editor.get_by_role('button', name='Revisar cambio').press('Enter')
    confirm.get_by_role('button', name='Volver a editar').press('Enter')
    expect(confirm).to_have_count(0)
    editor.get_by_role('button', name='Revisar cambio').press('Enter')
    confirm.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(editor.get_by_role('alert')).to_contain_text('Verifica tu identidad')
    expect(editor.get_by_label('Administración de seguridad', exact=True)).to_be_checked()
    page.unroute('**/memberships/*', mfa_required)
    database('stale-member')
    editor.get_by_role('button', name='Revisar cambio').press('Enter')
    expect(confirm).to_contain_text(target_id)
    expect(confirm).to_contain_text('Solicitud del operador')
    expect(confirm.get_by_role('button', name='Volver a editar')).to_be_focused()
    page.screenshot(path=str(artifacts / 'members-confirm.png'), full_page=True)
    confirm.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(editor.get_by_role('alert')).to_contain_text('Tu edición se conserva')
    expect(editor.get_by_label('Administración de seguridad', exact=True)).to_be_checked()
    editor.get_by_role('button', name='Cargar versión actual').press('Enter')
    expect(editor.get_by_text('Versión actual 2:', exact=False)).to_be_visible()
    expect(editor.get_by_label('Razón del cambio')).to_have_value('operator_request')
    page.screenshot(path=str(artifacts / 'members-conflict-recovered.png'), full_page=True)
    editor.get_by_role('button', name='Revisar cambio').press('Enter')
    confirm.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(rows.filter(has_text=target_id)).to_contain_text('Administración de seguridad')
    recipient.reload()
    recipient_members = recipient.get_by_role('region', name='Miembros', exact=True)
    go_to(recipient, 'Miembros')
    expect(recipient_members.locator('tbody tr')).to_have_count(2)
    # Security administration reads members but not invitations: the section is gated, not hidden by error.
    expect(recipient_nav.get_by_role('link', name='Invitaciones', exact=True)).to_have_count(0)
    recipient.evaluate("location.hash = '#invitaciones'")
    expect(recipient.get_by_text('Tu rol no permite ver invitaciones')).to_be_visible()
    recipient.evaluate("location.hash = '#miembros'")

    # All viewport screenshots contain synthetic IDs only. Offenders are collected so one run
    # reports every undersized control of a width.
    for width in [320, 360, 768, 1024, 1440]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        expect(page.locator('h1')).to_have_count(1)
        small = undersized(members)
        assert not small, f'{width}px members controls under 44px: {small}'
        page.screenshot(path=str(artifacts / f'members-{width}.png'), full_page=True)
    page.emulate_media(color_scheme='dark')
    page.screenshot(path=str(artifacts / 'members-dark.png'), full_page=True)
    page.emulate_media(color_scheme='light')
    page.evaluate("document.documentElement.style.fontSize = '32px'")
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    page.evaluate("document.documentElement.style.fontSize = ''")

    row = rows.filter(has_text=target_id)
    row.get_by_role('button', name='Editar acceso', exact=False).press('Enter')
    editor.get_by_label('Estado del acceso').select_option('suspended')
    editor.get_by_role('button', name='Revisar cambio').press('Enter')
    confirm.get_by_role('button', name='Volver a editar').press('Escape')
    expect(confirm).to_have_count(0)
    expect(editor.get_by_role('button', name='Revisar cambio')).to_be_focused()
    editor.get_by_role('button', name='Revisar cambio').press('Enter')
    confirm.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(rows.filter(has_text=target_id)).to_contain_text('Suspendido')
    recipient.reload()
    heading(recipient, 'Acceso pendiente')

    # The server protects the last admin; the draft and reason remain recoverable.
    rows.filter(has_text='Administración de organización').get_by_role('button', name='Editar acceso', exact=False).press('Enter')
    editor.get_by_label('Estado del acceso').select_option('suspended')
    editor.get_by_role('button', name='Revisar cambio').press('Enter')
    confirm.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(editor.get_by_role('alert')).to_contain_text('Debe quedar al menos un administrador activo')
    editor.get_by_role('button', name='Volver al listado').press('Enter')
    expect(editor).to_have_count(0)

    # Reactivation keeps grants; revocation is terminal in the editor.
    row = rows.filter(has_text=target_id)
    row.get_by_role('button', name='Editar acceso', exact=False).press('Enter')
    editor.get_by_label('Estado del acceso').select_option('active')
    editor.get_by_role('button', name='Revisar cambio').press('Enter')
    confirm.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(rows.filter(has_text=target_id)).to_contain_text('Activo')
    recipient.reload()
    heading(recipient, 'Elige una organización')
    row.get_by_role('button', name='Editar acceso', exact=False).press('Enter')
    editor.get_by_label('Estado del acceso').select_option('revoked')
    editor.get_by_role('button', name='Revisar cambio').press('Enter')
    expect(confirm).to_contain_text('La revocación es definitiva')
    # A missing row also has zero buttons. Wait for the committed state and
    # context revalidation/focus before sending the next keyboard action.
    with page.expect_response(lambda response: response.url == origin + '/console/api/me' and response.request.method == 'GET'):
        confirm.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(page.locator('h1')).to_be_focused()
    expect(rows.filter(has_text=target_id)).to_contain_text('Revocado')
    expect(rows.filter(has_text=target_id).get_by_role('button')).to_have_count(0)

    # A new recipient can receive another invitation, then the admin revokes it.
    go_to(page, 'Invitaciones')
    invitations.get_by_role('button', name='Invitar persona').press('Enter')
    invite.get_by_label('Correo del destinatario').fill('Another+recipient@example.invalid')
    invite.get_by_role('button', name='Crear invitación', exact=True).press('Enter')
    expect(invite).to_have_count(0)
    invitation_rows = invitations.locator('tbody tr')
    expect(invitation_rows).to_have_count(2)

    invitations.get_by_role('button', name='Revocar invitación', exact=False).press('Enter')
    revoker.get_by_label('Razón del cambio').select_option('invitation_cancelled')
    revoker.get_by_role('button', name='Revisar cambio').press('Enter')
    expect(confirm).to_contain_text('Cancelación de invitación')
    confirm.get_by_role('button', name='Confirmar cambio').press('Enter')
    expect(invitation_rows.filter(has_text='Revocado')).to_have_count(1)

    def unavailable(route):
        route.fulfill(status=503, content_type='application/problem+json', body=json.dumps({'code': 'dependency_unavailable'}))
    page.route('**/invitations?*', unavailable)
    invitations.get_by_role('button', name='Actualizar listado').press('Enter')
    expect(invitations.get_by_role('alert')).to_contain_text('No se confirmó el resultado')
    page.unroute('**/invitations?*', unavailable)
    invitations.get_by_role('button', name='Reintentar desde el inicio').press('Enter')
    expect(invitation_rows).to_have_count(2)
    invitations.get_by_role('button', name='Invitar persona').press('Enter')
    invite.get_by_label('Correo del destinatario').fill('Browser+recipient@example.invalid')
    invite.get_by_role('button', name='Crear invitación', exact=True).press('Enter')
    expect(invite).to_have_count(0)
    expect(invitation_rows).to_have_count(3)
    expired_token = database('deliver-invitation')['token']
    database('expire-invitation')
    invitations.get_by_role('button', name='Actualizar listado').press('Enter')
    expect(invitation_rows.filter(has_text='Expirada')).to_have_count(1)
    recipient.goto(origin + '/#invitation=' + expired_token)
    recipient.reload()
    heading(recipient, 'Acceso pendiente')
    accept.get_by_role('button', name='Aceptar invitación', exact=True).press('Enter')
    expect(accept.get_by_role('alert')).to_contain_text('La invitación no está disponible')
    assert expired_token not in recipient.content() and recipient.url == origin + '/'
    assert token not in page.content() and token not in recipient.content()
    guest.close()
    print('Browser USR-T08: real invitation/recipient acceptance/roles/suspension/revocation, lost-response replay, 412 draft recovery, last admin, permissions, keyboard and responsive states passed.', flush=True)
