import json
from urllib.parse import quote
import pyotp
from app.models import db, User, UserCertificate
from app.cert_utils import sha256_fingerprint
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import datetime


def make_self_signed_cert(common_name='userA'):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TestOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    return pem, cert


def test_login_cert_user_must_match(client, app):
    # Create two users
    with app.app_context():
        userA = User(username='userA', email='a@example.com', password_hash='x', is_admin=False)
        userB = User(username='userB', email='b@example.com', password_hash='x', is_admin=False)
        db.session.add_all([userA, userB]); db.session.commit()
        # Set password hash (argon would be slow in tests; bypass verify by setting a known password scheme)
        from app.security import PasswordSecurity
        pwd = PasswordSecurity(); userA.password_hash = pwd.hash('pass'); userB.password_hash = pwd.hash('pass'); db.session.commit()

        # Bind a cert to userA
        pem, cert = make_self_signed_cert('userA')
        fpr = cert.fingerprint(hashes.SHA256()).hex().upper()
        db.session.add(UserCertificate(user_id=userA.id, fingerprint_sha256=fpr, serial_number='1', issuer='I', subject='S'))
        db.session.commit()

        # Prepare headers simulating nginx
        escaped = quote(pem.replace('\n', '\t'))
        headers = {
            'X-Client-Verify': 'SUCCESS',
            'X-Client-Cert': escaped,
        }

    # Login as userB with userA's cert: should 401
    resp = client.post('/login', json={'username':'userB','password':'pass'}, headers=headers)
    assert resp.status_code == 401

    # Login as userA with same cert: should 200
    resp = client.post('/login', json={'username':'userA','password':'pass'}, headers=headers)
    assert resp.status_code == 200


def test_require_mtls_for_login_enforced(client, app, monkeypatch):
    # Force REQUIRE_MTLS_FOR_LOGIN=1
    app.config['REQUIRE_MTLS_FOR_LOGIN'] = True
    with app.app_context():
        from app.security import PasswordSecurity
        u = User(username='alice', email='alice@example.com', password_hash=PasswordSecurity().hash('secret'))
        db.session.add(u); db.session.commit()

    # No cert presented: should 401
    resp = client.post('/login', json={'username':'alice','password':'secret'})
    assert resp.status_code == 401

    # Present a cert that is not bound: should 401
    pem, cert = make_self_signed_cert('alice')
    escaped = quote(pem.replace('\n', '\t'))
    headers = {'X-Client-Verify':'SUCCESS','X-Client-Cert':escaped}
    resp = client.post('/login', json={'username':'alice','password':'secret'}, headers=headers)
    assert resp.status_code == 401

    # Bind it and retry: should 200
    with app.app_context():
        fpr = cert.fingerprint(hashes.SHA256()).hex().upper()
        u = User.query.filter_by(username='alice').first()
        db.session.add(UserCertificate(user_id=u.id, fingerprint_sha256=fpr, serial_number='1', issuer='I', subject='S'))
        db.session.commit()
    resp = client.post('/login', json={'username':'alice','password':'secret'}, headers=headers)
    assert resp.status_code == 200


def test_2fa_setup_and_enable(client, app):
    # Create user and login
    from app.security import PasswordSecurity
    with app.app_context():
        u = User(username='charlie', email='c@example.com', password_hash=PasswordSecurity().hash('pw'))
        db.session.add(u); db.session.commit()
    resp = client.post('/login', json={'username':'charlie','password':'pw'})
    assert resp.status_code == 200

    # Setup 2FA
    r = client.get('/2fa/setup')
    assert r.status_code == 200
    data = r.get_json()
    secret = data['secret']

    # Enable with valid code
    totp = pyotp.TOTP(secret)
    code = totp.now()
    r = client.post('/2fa/enable', json={'secret': secret, 'code': code})
    assert r.status_code == 200

    # Verify user has 2FA enabled
    with app.app_context():
        u = User.query.filter_by(username='charlie').first()
        assert u.totp_enabled is True
