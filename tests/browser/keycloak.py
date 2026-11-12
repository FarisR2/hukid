"""Real password/TOTP, BFF and SQL checks against resources owned by test-keycloak.mjs.

Secrets arrive on stdin. No traces, screenshots, HTML dumps or token output.
"""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit, parse_qs
from playwright.sync_api import sync_playwright, expect

config = json.loads(sys.stdin.readline())
origin, issuer = config['origin'], config['issuer']
output = Path(config['scratch']) / 'browser.json'
report = {'status': 'running', 'checks': []}
current = 'launch'


def stage(name):
    global current
    current = name


def passed():
    report['checks'].append(current)
    output.write_text(json.dumps(report, indent=2), encoding='utf-8')


def totp(secret):
    digest = hmac.new(base64.b32decode(secret + '=' * (-len(secret) % 8)), struct.pack('>Q', int(time.time()) // 30), hashlib.sha1).digest()
    off = digest[-1] & 15
    return str((struct.unpack('>I', digest[off:off+4])[0] & 0x7fffffff) % 1000000).zfill(6)


def fresh_otp(user):
    counter = int(time.time()) // 30
    if counter == user.get('lastCounter'):
        time.sleep(31 - (time.time() % 30))
    user['lastCounter'] = int(time.time()) // 30
    return totp(user['totp'])


def sql(query):
    # The parent created this private cluster and passes only its administrative password.
    command = [str(Path(config['pgBin']) / ('psql.exe' if os.name == 'nt' else 'psql')), '-X', '-t', '-A', '-v', 'ON_ERROR_STOP=1',
               '-h', '127.0.0.1', '-p', str(config['pgPort']), '-U', 'hukid_e2e_admin', '-d', 'hukid_local']
    result = subprocess.run(command, input=query, text=True, capture_output=True, env={**os.environ, 'PGPASSWORD': config['password']}, timeout=10)
    assert result.returncode == 0, 'owned SQL fixture failed'
    return result.stdout.strip()


def identity(context):
    response = context.request.get(origin + '/console/api/me')
    assert response.status == 200, 'expected authenticated identity'
    assert 'no-store' in response.headers.get('cache-control', '')
    return response.json()


def post(context, path, body=None, headers=None):
    me = identity(context)
    return context.request.post(origin + path, data=body,
        headers={'Origin': origin, 'X-CSRF-Token': me['csrfToken'], **(headers or {})})


def credentials(page, user, wrong=False):
    page.locator('#username').wait_for()
    page.locator('#username').fill(user['username'])
    page.locator('#password').fill('incorrect-password' if wrong else user['password'])
    page.locator('#kc-login').click()
    page.wait_for_load_state('networkidle')


def consent(page):
    if page.locator('#kc-login').count() and not page.locator('#otp').count() and not page.locator('#username').count():
        page.locator('#kc-login').click()
        page.wait_for_load_state('networkidle')


def login(page, user):
    page.goto(origin)
    page.wait_for_load_state('networkidle')
    retry = page.get_by_role('button', name='Iniciar sesión de nuevo', exact=True)
    if retry.count(): retry.click()
    credentials(page, user)
    page.locator('#otp').wait_for()
    page.locator('#otp').fill(fresh_otp(user))
    page.locator('#kc-login').click()
    page.wait_for_load_state('networkidle')
    consent(page)
    page.wait_for_url(origin + '/')
    page.wait_for_load_state('networkidle')
    return identity(page.context)


def enroll(page, user):
    page.goto(origin)
    credentials(page, user)
    link = page.locator('a').filter(has_text='Unable to scan')
    if link.count(): link.click()
    secret = page.locator('#kc-totp-secret-key')
    secret.wait_for()
    user['totp'] = ''.join(secret.inner_text().split())
    page.locator('#totp').fill(fresh_otp(user))
    page.locator('#userLabel').fill('Isolated E2E')
    page.locator('#saveTOTPBtn').click()
    page.wait_for_load_state('networkidle')
    consent(page)
    # Enrollment alone did not execute the configured OTP authenticator. Fail closed.
    response = page.context.request.get(origin + '/console/api/me')
    assert response.status == 401
    assert not any(c['name'] == 'hukid_local_session' for c in page.context.cookies())


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()
    user, other = config['users']
    try:
        stage('password_incorrect_denied')
        page.goto(origin)
        credentials(page, user, wrong=True)
        assert page.locator('#password').is_visible()
        assert not any(c['name'] == 'hukid_local_session' for c in context.cookies())
        passed()
        # A clean tab avoids the anti-loop marker from this deliberately incomplete flow.
        page.close(); page = context.new_page()
        stage('totp_enrollment_does_not_fabricate_mfa')
        enroll(page, user)
        passed()
        stage('password_and_real_otp_create_bff_session')
        me = login(page, user)
        assert len(me['tenants']) == 1 and me['tenants'][0]['tenantId'] == user['tenant']
        cookies = context.cookies()
        cookie = next(c for c in cookies if c['name'] == 'hukid_local_session')
        assert cookie['httpOnly'] and cookie['sameSite'] == 'Lax'
        assert 'hukid_local_session' not in page.evaluate('document.cookie')
        assert page.evaluate('localStorage.length') == 0
        passed()
        stage('tenant_selection_and_real_dashboard')
        response = post(context, '/console/auth/tenant-context', {'tenantId': user['tenant']})
        assert response.status in [200, 204]
        me = identity(context)
        assert me['activeTenantId'] == user['tenant']
        page.goto(origin); page.wait_for_load_state('networkidle')
        expect(page.get_by_role('region', name='Resumen operativo')).to_be_visible()
        expect(page.get_by_role('region', name='Resumen operativo').get_by_text('Miembros activos', exact=True)).to_be_visible()
        passed()
        prefix = '/console/api/tenants/' + user['tenant']
        stage('members_and_tenant_isolation')
        members = context.request.get(origin + prefix + '/memberships')
        assert members.status == 200 and len(members.json()['items']) == 1
        assert context.request.get(origin + '/console/api/tenants/' + other['tenant'] + '/memberships').status in [403, 404]
        assert post(context, '/console/auth/tenant-context', {'tenantId': other['tenant']}).status in [403, 404]
        passed()
        stage('csrf_and_origin_denied')
        assert context.request.post(origin + '/console/auth/refresh', headers={'Origin': origin}).status == 403
        me = identity(context)
        assert context.request.post(origin + '/console/auth/refresh', headers={'Origin': 'http://127.0.0.1:1', 'X-CSRF-Token': me['csrfToken']}).status == 403
        passed()
        stage('real_refresh_rotates_cookie')
        previous = next(c['value'] for c in context.cookies() if c['name'] == 'hukid_local_session')
        response = post(context, '/console/auth/refresh')
        assert response.status in [200, 204]
        assert next(c['value'] for c in context.cookies() if c['name'] == 'hukid_local_session') != previous
        identity(context)
        passed()
        stage('real_step_up')
        response = post(context, '/console/auth/step-up', {'returnTo': '/'}, {'Accept': 'application/json'})
        assert response.status == 200
        page.goto(response.json()['authorizationUrl'])
        credentials(page, user)
        page.locator('#otp').wait_for(); page.locator('#otp').fill(fresh_otp(user)); page.locator('#kc-login').click()
        page.wait_for_load_state('networkidle'); consent(page)
        page.wait_for_url(origin + '/')
        identity(context)
        passed()
        stage('invitation_create_replay_revoke')
        payload = {'email': 'invitee@example.invalid', 'roles': ['support_readonly'], 'issuerIds': []}
        key = secrets.token_urlsafe(24)
        response = post(context, prefix + '/invitations', payload, {'Idempotency-Key': key})
        assert response.status == 201
        invitation = response.json()
        assert post(context, prefix + '/invitations', payload, {'Idempotency-Key': key}).json() == invitation
        revoked = post(context, prefix + '/invitations/' + invitation['invitationId'] + '/revocations', {'reasonCode': 'invitation_cancelled'},
                       {'Idempotency-Key': secrets.token_urlsafe(24), 'If-Match': response.headers['etag']})
        assert revoked.status == 200
        passed()
        stage('last_administrator_protected')
        own_member = context.request.get(origin + prefix + '/memberships').json()['items'][0]
        response = context.request.patch(origin + prefix + '/memberships/' + own_member['membershipId'],
            data={'roles': ['support_readonly'], 'issuerIds': [], 'reasonCode': 'access_change'},
            headers={'Origin': origin, 'X-CSRF-Token': identity(context)['csrfToken'],
                     'Idempotency-Key': secrets.token_urlsafe(24), 'If-Match': '"' + str(own_member['revision']) + '"'})
        assert response.status == 409
        passed()
        stage('live_role_and_suspension_revalidation')
        subject = user['subject']
        member = sql(f"SELECT membership_id FROM tenancy.memberships m JOIN tenancy.operator_identities i USING(operator_identity_id) WHERE i.subject='{subject}';")
        sql(f"UPDATE tenancy.membership_roles SET role='support_readonly' WHERE membership_id='{member}';")
        assert context.request.get(origin + prefix + '/memberships').status == 403
        sql(f"UPDATE tenancy.membership_roles SET role='tenant_admin' WHERE membership_id='{member}'; UPDATE tenancy.memberships SET state='suspended' WHERE membership_id='{member}';")
        assert identity(context)['activeTenantId'] is None
        sql(f"UPDATE tenancy.memberships SET state='active' WHERE membership_id='{member}';")
        passed()
        stage('owned_database_outage_and_recovery')
        ctl = str(Path(config['pgBin']) / ('pg_ctl.exe' if os.name == 'nt' else 'pg_ctl'))
        assert Path(config['pgData']).parent == Path(config['scratch'])
        stopped = subprocess.run([ctl, '-D', config['pgData'], '-m', 'fast', '-w', 'stop'], capture_output=True, timeout=20)
        assert stopped.returncode == 0
        try:
            assert context.request.get(origin + '/console/api/me').status == 503
        finally:
            with open(Path(config['scratch']) / 'recovery.log', 'ab') as log:
                restarted = subprocess.run([ctl, '-D', config['pgData'], '-l', str(Path(config['scratch']) / 'postgres.log'),
                    '-o', f"-h 127.0.0.1 -p {config['pgPort']} -c log_statement=none -c log_min_error_statement=panic", '-w', 'start'],
                    stdout=log, stderr=log, timeout=30)
            assert restarted.returncode == 0
        # Pools may discard a connection killed by pg_ctl on the first retry.
        for _ in range(20):
            recovered = context.request.get(origin + '/console/api/me')
            if recovered.status == 200: break
            assert recovered.status == 503
            time.sleep(.25)
        assert recovered.status == 200
        passed()
        stage('logout_revokes_previous_cookie_and_requires_credentials')
        old = next(c['value'] for c in context.cookies() if c['name'] == 'hukid_local_session')
        assert post(context, '/console/auth/logout').status in [200, 204]
        assert context.request.get(origin + '/console/api/me', headers={'Cookie': 'hukid_local_session=' + old}).status == 401
        page.goto(origin)
        page.locator('#username').wait_for()
        assert page.locator('#password').is_visible()
        passed()
        stage('signed_token_profile_and_replay')
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        captured = {}
        redirect = origin + '/console/auth/callback'
        def intercept(route):
            response = route.fetch(max_redirects=0)
            location = response.headers.get('location', '')
            if location.startswith(redirect + '?'):
                captured.update(parse_qs(urlsplit(location).query))
                route.fulfill(status=200, body='Isolated code capture')
            else: route.fulfill(response=response)
        page.route('**/login-actions/**', intercept)
        page.goto(issuer + '/protocol/openid-connect/auth?' + urlencode({'client_id': 'hukid-console', 'redirect_uri': redirect,
            'response_type': 'code', 'scope': 'openid email offline_access operator:read', 'state': state, 'nonce': nonce,
            'code_challenge': challenge, 'code_challenge_method': 'S256', 'prompt': 'login consent', 'acr_values': '2'}))
        credentials(page, user)
        page.locator('#otp').wait_for()
        bad_otp = str((int(totp(user['totp'])) + 1) % 1000000).zfill(6)
        page.locator('#otp').fill(bad_otp); page.locator('#kc-login').click()
        assert page.locator('#otp').is_visible() and not captured
        page.locator('#otp').fill(fresh_otp(user)); page.locator('#kc-login').click()
        page.wait_for_load_state('networkidle'); consent(page)
        assert captured.get('state') == [state] and captured.get('code')
        form = {'grant_type': 'authorization_code', 'client_id': 'hukid-console', 'client_secret': config['clientSecret'],
                'code': captured['code'][0], 'redirect_uri': redirect, 'code_verifier': verifier}
        response = context.request.post(issuer + '/protocol/openid-connect/token', form=form)
        assert response.status == 200
        tokens = response.json()
        # Verify signatures with the same pinned issuer JWKS via the installed jose library.
        script = """import {createRemoteJWKSet,jwtVerify} from 'jose';let s='';for await(const c of process.stdin)s+=c;const x=JSON.parse(s);const keys=createRemoteJWKSet(new URL(x.issuer+'/protocol/openid-connect/certs'));for(const [name,raw] of Object.entries(x.tokens)){const {payload:p,protectedHeader:h}=await jwtVerify(raw,keys,{issuer:x.issuer,algorithms:['ES256'],audience:name==='id_token'?'hukid-console':'https://api.hukid.pe/operator'});if(p.acr!=='2'||!['pwd','otp'].every(m=>p.amr.includes(m))||p.exp-p.iat>300||!p.auth_time)throw Error('evidence');if(name==='access_token'&&(h.typ!=='at+jwt'||p.hukid_token_class!=='operator'||p.hukid_grant!=='authorization_code'||p.client_id!=='hukid-console'||p.aud!=='https://api.hukid.pe/operator'))throw Error('operator');if(name==='id_token'&&p.nonce!==x.nonce)throw Error('nonce');}console.log('verified');"""
        verified = subprocess.run(['node', '--input-type=module', '-e', script], input=json.dumps({'issuer': issuer, 'nonce': nonce,
            'tokens': {key: tokens[key] for key in ['id_token', 'access_token']}}), text=True, capture_output=True, timeout=15)
        assert verified.returncode == 0
        assert context.request.post(issuer + '/protocol/openid-connect/token', form=form).status == 400
        # Disabled grant paths must not issue operator credentials.
        assert context.request.post(issuer + '/protocol/openid-connect/token', form={'grant_type': 'password', 'client_id': 'hukid-console',
            'client_secret': config['clientSecret'], 'username': user['username'], 'password': user['password']}).status == 400
        denied_grant = context.request.post(issuer + '/protocol/openid-connect/token', form={'grant_type': 'client_credentials', 'client_id': 'hukid-console',
            'client_secret': config['clientSecret']})
        assert denied_grant.status in [400, 401] and denied_grant.json().get('error') == 'unauthorized_client'
        passed()
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', failedCase=current, errorType=type(error).__name__, path=urlsplit(page.url).path,
                      line=[frame.lineno for frame in traceback.extract_tb(error.__traceback__) if frame.filename == __file__])
        # No exception text: Playwright diagnostics may contain authorization URLs.
    finally:
        output.write_text(json.dumps(report, indent=2), encoding='utf-8')
        browser.close()
if report['status'] != 'passed': sys.exit(1)
