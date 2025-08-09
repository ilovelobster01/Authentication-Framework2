import base64
from datetime import datetime
from typing import Optional

from flask import Flask, jsonify, request, abort
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import CSRFProtect
from flask import render_template, redirect, url_for, flash, session, request
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from . import cert_utils as cu
from urllib.parse import unquote
from werkzeug.exceptions import HTTPException

from .models import db, User, UserCertificate, AuditLog
from .security import PasswordSecurity
import pyotp
import qrcode
import io
import base64


REQUIRED_CERT_HEADER = "X-Client-Verify"
ESCAPED_CERT_HEADER = "X-Client-Cert"
FPR_HEADER = "X-Client-Cert-Fingerprint"  # may be SHA-1 depending on nginx; we recompute SHA-256 from PEM
SERIAL_HEADER = "X-Client-Cert-Serial"
SUBJECT_HEADER = "X-Client-Cert-Subject"
ISSUER_HEADER = "X-Client-Cert-Issuer"


def parse_escaped_pem_cert(escaped: str) -> Optional[x509.Certificate]:  # moved to cert_utils.py
    return cu.parse_escaped_pem_cert(escaped)  # delegate to cert utils
    try:
        # nginx's $ssl_client_escaped_cert URL-encodes the PEM and replaces newlines with "\t".
        # We reverse escaping: URL-decode and convert "\t" back to newlines. Do NOT replace spaces.
        unesc = unquote(escaped)
        pem = unesc.replace("\t", "\n").replace("\r", "")
        if "BEGIN CERTIFICATE" not in pem:
            # In rare cases proxies may pass raw PEM without escaping
            if escaped.startswith("-----BEGIN"):
                pem = escaped
            else:
                return None
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"), default_backend())
        return cert
    except Exception:
        return None


# sha256_fingerprint is provided by cert_utils (cu)


def create_app():
    app = Flask(__name__)

    # Minimal config; in next steps we'll externalize to env vars
    app.config["SECRET_KEY"] = app.config.get("SECRET_KEY") or "dev-insecure-change-me"
    import os
    db_url = os.environ.get("DATABASE_URL") or "sqlite:///dev.db"
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["WTF_CSRF_SSL_STRICT"] = False  # don't require Referer header on HTTPS; rely on CSRF token

    # Dev-friendly: allow password/TOTP login without mTLS unless explicitly required
    import os
    app.config["REQUIRE_MTLS_FOR_LOGIN"] = os.environ.get("REQUIRE_MTLS_FOR_LOGIN", "0") == "1"
    app.config["ADMIN_REQUIRE_MTLS"] = os.environ.get("ADMIN_REQUIRE_MTLS", "1") == "1"

    db.init_app(app)
    Migrate(app, db)

    csrf = CSRFProtect(app)

    login_manager = LoginManager()
    login_manager.login_view = "login_page"
    login_manager.init_app(app)

    pwdsec = PasswordSecurity()

    @login_manager.user_loader
    def load_user(user_id: str):
        return db.session.get(User, int(user_id))

    def get_presented_cert_fpr() -> Optional[str]:
        verified = request.headers.get(REQUIRED_CERT_HEADER)
        if verified != "SUCCESS":
            return None
        cert_pem_escaped = request.headers.get(ESCAPED_CERT_HEADER)
        if not cert_pem_escaped:
            return None
        cert = cu.parse_escaped_pem_cert(cert_pem_escaped)
        if not cert:
            return None
        return cu.sha256_fingerprint(cert)

    def log_event(event_type: str, details: dict | None = None, user: User | None = None, status: str | None = None):
        try:
            entry = AuditLog(
                user_id=(user.id if user else (current_user.id if current_user.is_authenticated else None)),
                event_type=event_type,
                ip=request.headers.get('X-Forwarded-For', request.remote_addr),
                user_agent=request.headers.get('User-Agent'),
                details=(jsonify(details).get_data(as_text=True) if details else None),
            )
            db.session.add(entry)
            db.session.commit()
        except Exception:
            db.session.rollback()

    def require_client_cert():
        if not get_presented_cert_fpr():
            abort(401, description="Client certificate required")

    @app.get("/healthz")
    def healthz():
        return "ok", 200

    @app.before_request
    def enforce_session_and_admin_mtls():
        # Skip static and health
        p = request.path or ""
        if p.startswith('/static/') or p == '/healthz':
            return
        if current_user.is_authenticated:
            fpr = get_presented_cert_fpr()
            if fpr:
                any_binding = UserCertificate.query.filter_by(fingerprint_sha256=fpr, is_revoked=False).first()
                if any_binding and any_binding.user_id != current_user.id:
                    log_event('session_cert_user_mismatch', {'fingerprint': fpr})
                    logout_user()
                    abort(401, description="Certificate does not match logged-in user")
                if any_binding and not any_binding.is_valid_now():
                    log_event('session_cert_invalid', {'fingerprint': fpr})
                    logout_user()
                    abort(401, description="Certificate not valid for this user")
            # Admin-only mTLS enforcement: accessing /admin requires verified, bound, valid cert
            if p.startswith('/admin') and current_user.is_admin and app.config.get("ADMIN_REQUIRE_MTLS", True):
                if not fpr:
                    log_event('admin_access_denied', {'reason': 'mtls_required'})
                    abort(401, description="Admin requires mTLS certificate")
                binding = UserCertificate.query.filter_by(user_id=current_user.id, fingerprint_sha256=fpr, is_revoked=False).first()
                if not binding or not binding.is_valid_now():
                    log_event('admin_access_denied', {'reason': 'binding_missing_or_invalid', 'fingerprint': fpr})
                    abort(401, description="Admin requires valid bound certificate")

    @app.get("/mtls/status")
    def mtls_status():
        return jsonify({
            "ssl_client_verify": request.headers.get(REQUIRED_CERT_HEADER),
            "has_cert_header": bool(request.headers.get(ESCAPED_CERT_HEADER)),
        }), 200

    @csrf.exempt
    @app.post("/dev/create_user")
    def dev_create_user():
        data = request.get_json(force=True) or {}
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        is_admin = bool(data.get("is_admin", False))
        if not username or not email or not password:
            abort(400, description="username, email, password required")
        if User.query.filter((User.username == username) | (User.email == email)).first():
            abort(409, description="username or email already exists")
        u = User(username=username, email=email, password_hash=pwdsec.hash(password), is_admin=is_admin)
        db.session.add(u)
        db.session.commit()
        return {"status": "ok", "id": u.id}, 201

    @csrf.exempt
    @app.post("/login")
    def login():
        data = request.get_json(force=True) or {}
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            abort(400, description="username and password required")
        user = User.query.filter_by(username=username).first()
        if not user or not user.is_active or not user.password_hash or not pwdsec.verify(user.password_hash, password):
            log_event('login_failed', {'username': username, 'reason': 'invalid_credentials'})
            abort(401, description="Invalid credentials")

        # If a verified client cert was presented, it must belong to this user (even when not strictly required)
        presented_fpr = get_presented_cert_fpr()
        if presented_fpr:
            any_binding = UserCertificate.query.filter_by(fingerprint_sha256=presented_fpr, is_revoked=False).first()
            if any_binding:
                if any_binding.user_id != user.id:
                    log_event('login_failed', {'username': username, 'reason': 'cert_user_mismatch', 'fingerprint': presented_fpr}, user=user)
                    abort(401, description="Presented certificate belongs to a different user")
                if not any_binding.is_valid_now():
                    log_event('login_failed', {'username': username, 'reason': 'cert_invalid', 'fingerprint': presented_fpr}, user=user)
                    abort(401, description="Presented certificate is not valid")

        # Require mTLS certificate bound to this user when explicitly enabled
        if app.config.get("REQUIRE_MTLS_FOR_LOGIN", False):
            if not presented_fpr:
                log_event('login_failed', {'username': username, 'reason': 'mtls_required'})
                abort(401, description="mTLS certificate required")
            binding = UserCertificate.query.filter_by(user_id=user.id, fingerprint_sha256=presented_fpr, is_revoked=False).first()
            if not binding or not binding.is_valid_now():
                log_event('login_failed', {'username': username, 'reason': 'mtls_binding_missing_or_invalid', 'fingerprint': presented_fpr}, user=user)
                abort(401, description="Valid bound certificate required")

        # If TOTP is enabled, require it
        if user.totp_enabled:
            from flask import session
            session["pending_2fa_user_id"] = user.id
            log_event('login_pending_2fa', {'username': username})
            return {"status": "2fa_required"}, 200
        login_user(user)
        log_event('login_success', {'username': username})
        return {"status": "ok"}, 200

    @csrf.exempt
    @app.post("/2fa/verify")
    def verify_2fa():
        from flask import session
        code = (request.get_json(force=True) or {}).get("code")
        if not code:
            abort(400, description="code required")
        uid = session.get("pending_2fa_user_id")
        if not uid:
            abort(400, description="no pending 2fa")
        user = db.session.get(User, int(uid))
        if not user or not user.totp_enabled or not user.totp_secret:
            abort(400, description="user not eligible for 2fa")
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(str(code), valid_window=1):
            abort(401, description="invalid code")
        session.pop("pending_2fa_user_id", None)
        login_user(user)
        return {"status": "ok"}, 200

    @app.get("/2fa/setup")
    @login_required
    def setup_2fa():
        # Generate secret if not present
        if current_user.totp_secret and current_user.totp_enabled:
            return {"status": "already_enabled"}, 200
        secret = current_user.totp_secret or pyotp.random_base32()
        issuer = "FlaskAuthDemo"
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email or current_user.username, issuer_name=issuer)
        # Generate QR PNG as data URL
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        return {"secret": secret, "otpauth_uri": uri, "qr_data_url": f"data:image/png;base64,{b64}"}, 200

    @app.post("/2fa/enable")
    @login_required
    def enable_2fa():
        data = request.get_json(force=True) or {}
        secret = data.get("secret")
        code = str(data.get("code")) if data.get("code") is not None else None
        if not secret or not code:
            abort(400, description="secret and code required")
        totp = pyotp.TOTP(secret)
        if not totp.verify(code, valid_window=1):
            abort(401, description="invalid code")
        # Save to user
        u = db.session.get(User, current_user.id)
        u.totp_secret = secret
        u.totp_enabled = True
        db.session.commit()
        return {"status": "ok"}, 200

    @app.route("/logout", methods=["GET", "POST"])
    @login_required
    def logout():
        # Allow GET so the header link works; POST also supported
        log_event('logout', {'user': current_user.username if current_user.is_authenticated else None})
        logout_user()
        flash('Logged out', 'success')
        return redirect(url_for('login_page'))

    @app.get("/me")
    @login_required
    def me():
        return {"id": current_user.id, "username": current_user.username, "email": current_user.email, "is_admin": current_user.is_admin}, 200

    @app.get("/profile")
    @login_required
    def profile_page():
        return render_template('profile.html', user=current_user)

    @app.get("/")
    def root_index():
        return redirect(url_for('login_page'))

    @app.get("/login")
    def login_page():
        return render_template('login.html')

    @app.get("/debug/identity")
    def debug_identity():
        headers = request.headers
        cert_pem_escaped = headers.get(ESCAPED_CERT_HEADER)
        sha256_fpr = None
        parsed = None
        if cert_pem_escaped:
            parsed = cu.parse_escaped_pem_cert(cert_pem_escaped)
            if parsed:
                sha256_fpr = cu.sha256_fingerprint(parsed)
        return jsonify({
            "ssl_client_verify": headers.get(REQUIRED_CERT_HEADER),
            "fingerprint_sha256_from_nginx": headers.get(FPR_HEADER),
            "fingerprint_sha256_from_pem": sha256_fpr,
            "serial": headers.get(SERIAL_HEADER),
            "subject": headers.get(SUBJECT_HEADER),
            "issuer": headers.get(ISSUER_HEADER),
            "client_ip": request.headers.get('X-Forwarded-For', request.remote_addr),
            "user_agent": request.headers.get('User-Agent'),
        }), 200

    @csrf.exempt
    @app.post("/cert/bind/<username>")
    def bind_certificate(username: str):
        # Enforce that TLS client cert is present and verified by nginx
        require_client_cert()
        headers = request.headers
        cert_pem_escaped = headers.get(ESCAPED_CERT_HEADER)
        if not cert_pem_escaped:
            abort(400, description="Missing client cert header")
        cert = cu.parse_escaped_pem_cert(cert_pem_escaped)
        if not cert:
            abort(400, description="Could not parse client cert")
        fpr = cu.sha256_fingerprint(cert)
        user = User.query.filter_by(username=username).first()
        if not user:
            abort(404, description="User not found")
        # Basic metadata
        serial = headers.get(SERIAL_HEADER) or hex(cert.serial_number)[2:].upper()
        subject = headers.get(SUBJECT_HEADER)
        issuer = headers.get(ISSUER_HEADER)
        # Store UTC as naive datetimes for DB compatibility
        not_before = cert.not_valid_before_utc.replace(tzinfo=None)
        not_after = cert.not_valid_after_utc.replace(tzinfo=None)

        # Create binding if not exists
        existing = UserCertificate.query.filter_by(fingerprint_sha256=fpr).first()
        if existing:
            if existing.user_id != user.id:
                abort(409, description="Certificate already bound to another user")
            # Already bound to same user, ensure not revoked
            if existing.is_revoked:
                existing.is_revoked = False
                existing.revoked_at = None
                db.session.commit()
            return jsonify({"status": "ok", "message": "Already bound", "fingerprint": fpr}), 200
        binding = UserCertificate(
            user_id=user.id,
            fingerprint_sha256=fpr,
            serial_number=serial,
            issuer=issuer,
            subject=subject,
            not_before=not_before,
            not_after=not_after,
            is_revoked=False,
        )
        db.session.add(binding)
        db.session.commit()
        return jsonify({"status": "ok", "fingerprint": fpr}), 201

    @csrf.exempt
    @app.post("/cert/unbind/<username>")
    def unbind_certificate(username: str):
        require_client_cert()
        headers = request.headers
        cert_pem_escaped = headers.get(ESCAPED_CERT_HEADER)
        cert = cu.parse_escaped_pem_cert(cert_pem_escaped) if cert_pem_escaped else None
        if not cert:
            abort(400, description="Missing or invalid client cert header")
        fpr = cu.sha256_fingerprint(cert)
        user = User.query.filter_by(username=username).first()
        if not user:
            abort(404, description="User not found")
        binding = UserCertificate.query.filter_by(fingerprint_sha256=fpr, user_id=user.id).first()
        if not binding:
            abort(404, description="Binding not found")
        binding.is_revoked = True
        binding.revoked_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"status": "ok", "message": "Revoked", "fingerprint": fpr}), 200

    # Register admin blueprint
    from .admin.routes import admin_bp
    app.register_blueprint(admin_bp)

    @app.errorhandler(HTTPException)
    def handle_http_exc(e: HTTPException):
        wants_json = (
            request.is_json
            or request.headers.get('Content-Type','').startswith('application/json')
            or request.headers.get('Accept','').find('application/json') >= 0
            or request.path.startswith(('/login','/2fa','/dev','/cert'))
        )
        if wants_json:
            return jsonify({"error": e.name, "message": e.description, "status": e.code}), e.code
        return e

    return app
