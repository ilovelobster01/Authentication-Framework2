import os, re, json, base64, subprocess, shutil, ipaddress
from flask import Flask, request, jsonify

SAFE_UNAME_RE = re.compile(r'^[A-Za-z0-9_.-]+$')

def create_app():
    app = Flask(__name__)

    API_TOKEN = os.environ.get('CA_API_TOKEN')
    if not API_TOKEN:
        print('[WARN] CA_API_TOKEN not set; API will reject all requests')
    CA_SCRIPTS_DIR = os.environ.get('CA_SCRIPTS_DIR', os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts', 'ca')))
    CA_PASS = os.environ.get('CA_PASS')  # keep only in env of this service
    ALLOWED_EMAIL_DOMAIN = os.environ.get('ALLOWED_EMAIL_DOMAIN')
    PERSIST = os.environ.get('CA_API_PERSIST_OUTPUT', '0') == '1'

    # IP allowlist
    ALLOW_ALL = os.environ.get('CA_API_ALLOW_ALL', '0') == '1'
    RAW_ALLOWLIST = os.environ.get('CA_API_IP_ALLOWLIST', '127.0.0.1,::1')
    _allowlist = []
    for part in [p.strip() for p in RAW_ALLOWLIST.split(',') if p.strip()]:
        try:
            if '/' in part:
                _allowlist.append(ipaddress.ip_network(part, strict=False))
            else:
                # single host treated as /32 or /128
                ip_obj = ipaddress.ip_address(part)
                net = ipaddress.ip_network(part + ('/32' if ip_obj.version == 4 else '/128'), strict=False)
                _allowlist.append(net)
        except ValueError:
            print(f"[WARN] Ignoring invalid IP/CIDR in allowlist: {part}")

    def client_ip(req):
        # Prefer first X-Forwarded-For entry if present
        xff = req.headers.get('X-Forwarded-For', '')
        if xff:
            first = xff.split(',')[0].strip()
            return first
        return req.remote_addr or ''

    def ip_allowed(req):
        if ALLOW_ALL:
            return True
        cip = client_ip(req)
        try:
            ip_obj = ipaddress.ip_address(cip)
        except ValueError:
            return False
        for net in _allowlist:
            if ip_obj in net:
                return True
        return False

    def auth_ok(req):
        hdr = req.headers.get('Authorization','')
        if not hdr.startswith('Bearer '):
            return False
        tok = hdr.split(' ',1)[1].strip()
        return API_TOKEN and tok == API_TOKEN

    @app.get('/api/health')
    def health():
        return {'status': 'ok'}, 200

    @app.post('/api/issue')
    def issue():
        if not ip_allowed(request):
            return {'message': 'Forbidden'}, 403
        if not auth_ok(request):
            return {'message': 'Unauthorized'}, 401
        try:
            data = request.get_json(force=True)
        except Exception:
            return {'message': 'Invalid JSON'}, 400
        username = (data.get('username') or '').strip()
        email = (data.get('email') or '').strip()
        p12_password = data.get('p12_password') or ''
        if not SAFE_UNAME_RE.match(username):
            return {'message': 'Invalid username'}, 400
        if ALLOWED_EMAIL_DOMAIN and not email.endswith('@' + ALLOWED_EMAIL_DOMAIN):
            return {'message': 'Email domain not allowed'}, 400
        if len(p12_password) < 6:
            return {'message': 'Weak P12 password'}, 400

        out_dir = os.path.join(CA_SCRIPTS_DIR, 'out', 'clients', username)
        os.makedirs(out_dir, exist_ok=True)

        backend = os.environ.get('CA_BACKEND', 'local').lower()
        if backend == 'ipa':
            # Use FreeIPA CLI. Requires Kerberos keytab & principal.
            IPA_PRINCIPAL = os.environ.get('IPA_PRINCIPAL')
            IPA_KEYTAB = os.environ.get('IPA_KEYTAB')
            IPA_PROFILE = os.environ.get('IPA_PROFILE', 'userCert')
            IPA_BASE_DN = os.environ.get('IPA_BASE_DN')
            if not IPA_PRINCIPAL or not IPA_KEYTAB or not IPA_BASE_DN:
                return {'message': 'IPA not configured (IPA_PRINCIPAL/IPA_KEYTAB/IPA_BASE_DN)'}, 500
            # Generate key and CSR locally
            key_path = os.path.join(out_dir, f'{username}.key')
            csr_path = os.path.join(out_dir, f'{username}.csr')
            crt_path = os.path.join(out_dir, f'{username}.crt')
            try:
                subprocess.check_call(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', key_path, '-out', csr_path, '-subj', f'/CN={username}/emailAddress={email}'])
                # kinit with keytab for this request
                subprocess.check_call(['kinit', '-k', '-t', IPA_KEYTAB, IPA_PRINCIPAL])
                principal_dn = f'uid={username},cn=users,cn=accounts,{IPA_BASE_DN}'
                subprocess.check_call(['ipa', 'cert-request', csr_path, '--principal', principal_dn, '--profile-id', IPA_PROFILE, f'--certificate-out={crt_path}'])
                # Build P12
                p12_path = os.path.join(out_dir, f'{username}.p12')
                subprocess.check_call(['openssl', 'pkcs12', '-export', '-out', p12_path, '-inkey', key_path, '-in', crt_path, '-passout', f'pass:{p12_password}', '-name', f'{username}-client'])
                # Return artifacts as base64
                paths = {'crt': crt_path, 'key': key_path, 'p12': p12_path}
                resp = {}
                for k, p in paths.items():
                    with open(p, 'rb') as f:
                        resp[k] = base64.b64encode(f.read()).decode('ascii')
                if not PERSIST:
                    for p in paths.values():
                        try: os.remove(p)
                        except OSError: pass
                    try:
                        if not os.listdir(out_dir):
                            os.rmdir(out_dir)
                    except OSError:
                        pass
                return resp, 200
            except subprocess.CalledProcessError:
                return {'message': 'IPA issuance failed'}, 500
            except FileNotFoundError:
                return {'message': 'Artifacts missing'}, 500
        else:
            # Local OpenSSL CA scripts backend
            if not CA_PASS:
                return {'message': 'CA not configured'}, 500
            script = os.path.join(CA_SCRIPTS_DIR, 'issue_client.sh')
            try:
                env = os.environ.copy()
                subprocess.check_call([script, username, email, p12_password, CA_PASS], cwd=CA_SCRIPTS_DIR, env=env)
                # Read artifacts
                paths = {
                    'crt': os.path.join(out_dir, f'{username}.crt'),
                    'key': os.path.join(out_dir, f'{username}.key'),
                    'p12': os.path.join(out_dir, f'{username}.p12'),
                }
                resp = {}
                for k, p in paths.items():
                    with open(p, 'rb') as f:
                        resp[k] = base64.b64encode(f.read()).decode('ascii')
                # Optionally clean up artifacts to limit exposure on CA host
                if not PERSIST:
                    for p in paths.values():
                        try: os.remove(p)
                        except OSError: pass
                    try:
                        # Remove empty dir if possible
                        if not os.listdir(out_dir):
                            os.rmdir(out_dir)
                    except OSError:
                        pass
                return resp, 200
            except subprocess.CalledProcessError:
                return {'message': 'Issuance failed'}, 500
            except FileNotFoundError:
                return {'message': 'Artifacts missing'}, 500

    @app.post('/api/revoke')
    def revoke():
        if not ip_allowed(request):
            return {'message': 'Forbidden'}, 403
        if not auth_ok(request):
            return {'message': 'Unauthorized'}, 401
        try:
            data = request.get_json(force=True)
        except Exception:
            return {'message': 'Invalid JSON'}, 400
        username = (data.get('username') or '').strip()
        if not SAFE_UNAME_RE.match(username):
            return {'message': 'Invalid username'}, 400
        script = os.path.join(CA_SCRIPTS_DIR, 'revoke_client.sh')
        try:
            env = os.environ.copy()
            env['CA_PASS'] = CA_PASS or ''
            subprocess.check_call([script, username], cwd=CA_SCRIPTS_DIR, env=env)
            return {'status': 'revoked'}, 200
        except subprocess.CalledProcessError:
            return {'message': 'Revoke failed'}, 500

    return app

app = create_app()
