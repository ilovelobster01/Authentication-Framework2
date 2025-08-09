from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from ..models import db, User, UserCertificate, AuditLog
from ..security import PasswordSecurity
from .. import cert_utils as cu
from .forms import CreateUserForm, ResetPasswordForm, ToggleActiveForm, ResetTOTPForm, UnbindCertForm, BindCurrentCertForm, IssueClientCertForm, CertFilterForm
from urllib.parse import unquote
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import subprocess, pathlib

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Utility to safely map usernames to filesystem paths
import os, re
SAFE_UNAME_RE = re.compile(r'^[A-Za-z0-9_.-]+$')

def client_out_dir(username: str) -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'scripts', 'ca', 'out', 'clients', username)


pwdsec = PasswordSecurity()

def admin_required():
    if not current_user.is_authenticated:
        abort(401)
    if not current_user.is_admin:
        abort(403)

@admin_bp.before_request
def _check_admin():
    admin_required()

@admin_bp.get('/')
@login_required
def index():
    users = User.query.order_by(User.username.asc()).all()
    # Presented cert preview for header-level debug
    current_fpr = None
    current_meta = None
    if request.headers.get('X-Client-Verify') == 'SUCCESS':
        esc = request.headers.get('X-Client-Cert')
        if esc:
            cert = cu.parse_escaped_pem_cert(esc)
            if cert:
                current_fpr = cu.sha256_fingerprint(cert)
                current_meta = {
                    'serial': request.headers.get('X-Client-Cert-Serial') or hex(cert.serial_number)[2:].upper(),
                    'subject': request.headers.get('X-Client-Cert-Subject'),
                    'issuer': request.headers.get('X-Client-Cert-Issuer'),
                }
    return render_template('admin/users_list.html', users=users, current_fpr=current_fpr, current_meta=current_meta)

@admin_bp.route('/users/new', methods=['GET', 'POST'])
@login_required
def create_user():
    form = CreateUserForm()
    if form.validate_on_submit():
        if User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first():
            flash('Username or email already exists', 'error')
            return redirect(url_for('admin.create_user'))
        u = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=pwdsec.hash(form.password.data),
            is_admin=bool(form.is_admin.data),
        )
        db.session.add(u)
        db.session.commit()
        flash('User created', 'success')
        return redirect(url_for('admin.index'))
    return render_template('admin/create_user.html', form=form)

@admin_bp.route('/users/<int:user_id>', methods=['GET', 'POST'])
@login_required
def user_detail(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    reset_form = ResetPasswordForm(user_id=str(user.id))
    toggle_form = ToggleActiveForm(user_id=str(user.id), active=str(int(not user.is_active)))
    totp_form = ResetTOTPForm(user_id=str(user.id))
    cert_forms = []
    for cert in user.certificates:
        f = UnbindCertForm(user_id=str(user.id), fingerprint=cert.fingerprint_sha256)
        cert_forms.append((cert, f))
    bind_form = BindCurrentCertForm(user_id=str(user.id))

    # Current presented certificate (if any)
    current_cert = None
    current_fpr = None
    current_meta = None
    if request.headers.get('X-Client-Verify') == 'SUCCESS':
        esc = request.headers.get('X-Client-Cert')
        if esc:
            cert = cu.parse_escaped_pem_cert(esc)
            if cert:
                current_cert = cert
                current_fpr = cu.sha256_fingerprint(cert)
                current_meta = {
                    'serial': request.headers.get('X-Client-Cert-Serial') or hex(cert.serial_number)[2:].upper(),
                    'subject': request.headers.get('X-Client-Cert-Subject'),
                    'issuer': request.headers.get('X-Client-Cert-Issuer'),
                    'not_before': cert.not_valid_before_utc,
                    'not_after': cert.not_valid_after_utc,
                }

    return render_template(
        'admin/user_detail.html',
        user=user,
        reset_form=reset_form,
        toggle_form=toggle_form,
        totp_form=totp_form,
        cert_forms=cert_forms,
        bind_form=bind_form,
        current_fpr=current_fpr,
        current_meta=current_meta,
    )

@admin_bp.post('/users/reset_password')
@login_required
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = db.session.get(User, int(form.user_id.data))
        if not user:
            abort(404)
        user.password_hash = pwdsec.hash(form.password.data)
        user.must_change_password = True
        db.session.commit()
        flash('Password reset; user must change at next login', 'success')
        return redirect(url_for('admin.user_detail', user_id=user.id))
    abort(400)

@admin_bp.post('/users/toggle_active')
@login_required
def toggle_active():
    form = ToggleActiveForm()
    if form.validate_on_submit():
        user = db.session.get(User, int(form.user_id.data))
        if not user:
            abort(404)
        user.is_active = not user.is_active
        db.session.commit()
        flash('User active status updated', 'success')
        return redirect(url_for('admin.user_detail', user_id=user.id))
    abort(400)

@admin_bp.post('/users/reset_totp')
@login_required
def reset_totp():
    form = ResetTOTPForm()
    if form.validate_on_submit():
        user = db.session.get(User, int(form.user_id.data))
        if not user:
            abort(404)
        user.totp_enabled = False
        user.totp_secret = None
        db.session.commit()
        flash('2FA reset; user must re-enroll', 'success')
        return redirect(url_for('admin.user_detail', user_id=user.id))
    abort(400)

@admin_bp.post('/certs/revoke')
@login_required
def revoke_cert_global():
    fp = request.form.get('fingerprint')
    if not fp:
        abort(400)
    c = UserCertificate.query.filter_by(fingerprint_sha256=fp).first_or_404()
    c.is_revoked = True
    c.revoked_at = db.func.now()
    db.session.commit()
    flash('Certificate revoked', 'success')
    return redirect(url_for('admin.certs_index'))

@admin_bp.post('/certs/unrevoke')
@login_required
def unrevoke_cert():
    fp = request.form.get('fingerprint')
    if not fp:
        abort(400)
    c = UserCertificate.query.filter_by(fingerprint_sha256=fp).first_or_404()
    c.is_revoked = False
    c.revoked_at = None
    db.session.commit()
    flash('Certificate unrevoked', 'success')
    return redirect(url_for('admin.certs_index'))

@admin_bp.post('/users/revoke_cert')
@login_required
def revoke_cert():
    form = UnbindCertForm()
    if form.validate_on_submit():
        user = db.session.get(User, int(form.user_id.data))
        if not user:
            abort(404)
        cert = UserCertificate.query.filter_by(user_id=user.id, fingerprint_sha256=form.fingerprint.data).first()
        if not cert:
            abort(404)
        cert.is_revoked = True
        cert.revoked_at = db.func.now()
        db.session.commit()
        flash('Certificate revoked', 'success')
        return redirect(url_for('admin.user_detail', user_id=user.id))
    abort(400)

@admin_bp.get('/certs/view/<fingerprint>')
@login_required
def cert_view(fingerprint: str):
    cert = UserCertificate.query.filter_by(fingerprint_sha256=fingerprint).first_or_404()
    return render_template('admin/cert_detail.html', cert=cert)

@admin_bp.get('/certs')
@login_required
def certs_index():
    issue_form = IssueClientCertForm()
    filter_form = CertFilterForm(request.args)
    q = UserCertificate.query.join(User, User.id == UserCertificate.user_id)
    # Apply filters
    if filter_form.username.data:
        q = q.filter(User.username.ilike(f"%{filter_form.username.data.strip()}%"))
    if filter_form.fingerprint.data:
        q = q.filter(UserCertificate.fingerprint_sha256.ilike(f"{filter_form.fingerprint.data.strip()}%"))
    if filter_form.status.data and filter_form.status.data != 'any':
        if filter_form.status.data == 'active':
            q = q.filter(UserCertificate.is_revoked.is_(False))
        elif filter_form.status.data == 'revoked':
            q = q.filter(UserCertificate.is_revoked.is_(True))
    # Validity filter
    from datetime import datetime as _dt
    now = _dt.utcnow()
    if filter_form.validity.data and filter_form.validity.data != 'any':
        if filter_form.validity.data == 'valid':
            q = q.filter((UserCertificate.not_before.is_(None) | (UserCertificate.not_before <= now)) & (UserCertificate.not_after.is_(None) | (UserCertificate.not_after >= now)))
        elif filter_form.validity.data == 'expired':
            q = q.filter(UserCertificate.not_after.isnot(None) & (UserCertificate.not_after < now))
        elif filter_form.validity.data == 'future':
            q = q.filter(UserCertificate.not_before.isnot(None) & (UserCertificate.not_before > now))
    certs = q.order_by(User.username.asc(), UserCertificate.created_at.desc()).all()
    return render_template('admin/certs.html', issue_form=issue_form, filter_form=filter_form, certs=certs, issued=None)

@admin_bp.get('/audit')
@login_required
def audit_index():
    # admin_required is enforced in before_request of blueprint/app
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template('admin/audit.html', logs=logs)

@admin_bp.post('/certs/issue')
@login_required
def issue_cert():
    form = IssueClientCertForm()
    if form.validate_on_submit():
        uname = form.username.data.strip()
        email = form.email.data.strip()
        p12_pass = form.p12_password.data
        ca_pass = form.ca_password.data
        if not SAFE_UNAME_RE.match(uname):
            flash('Invalid username for certificate', 'error')
            return redirect(url_for('admin.certs_index'))
        # Call script non-interactively
        script = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'scripts', 'ca', 'issue_client.sh')
        script = os.path.abspath(script)
        try:
            env = os.environ.copy()
            # Pass as 4th arg to avoid env leakage
            cmd = [script, uname, email, p12_pass, ca_pass]
            subprocess.check_call(cmd, cwd=os.path.abspath(os.path.join(script, '..')), env=env)
        except subprocess.CalledProcessError as e:
            flash('Certificate issuance failed', 'error')
            return redirect(url_for('admin.certs_index'))
        out_dir = os.path.abspath(os.path.join(os.path.dirname(script), 'out', 'clients', uname))
        if not os.path.isdir(out_dir):
            flash('Certificate output not found', 'error')
            return redirect(url_for('admin.certs_index'))

        # Attempt to auto-bind the issued certificate to the user (if user exists)
        cert_path = os.path.join(out_dir, f"{uname}.crt")
        bound_to = None
        fpr = None
        try:
            if os.path.isfile(cert_path):
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                with open(cert_path, 'rb') as fh:
                    pem = fh.read()
                cert = x509.load_pem_x509_certificate(pem, default_backend())
                fpr = cu.sha256_fingerprint(cert)
                serial = hex(cert.serial_number)[2:].upper()
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                not_before = cert.not_valid_before_utc.replace(tzinfo=None)
                not_after = cert.not_valid_after_utc.replace(tzinfo=None)
                user = User.query.filter_by(username=uname).first()
                if user:
                    existing = UserCertificate.query.filter_by(fingerprint_sha256=fpr).first()
                    if existing and existing.user_id != user.id:
                        flash('Issued certificate fingerprint already bound to another user', 'error')
                    else:
                        if existing and existing.user_id == user.id:
                            # Unrevoke / refresh metadata
                            existing.is_revoked = False
                            existing.revoked_at = None
                            existing.serial_number = serial
                            existing.issuer = issuer
                            existing.subject = subject
                            existing.not_before = not_before
                            existing.not_after = not_after
                        else:
                            db.session.add(UserCertificate(
                                user_id=user.id,
                                fingerprint_sha256=fpr,
                                serial_number=serial,
                                issuer=issuer,
                                subject=subject,
                                not_before=not_before,
                                not_after=not_after,
                                is_revoked=False,
                            ))
                        db.session.commit()
                        bound_to = user.username
                else:
                    flash('Certificate issued but user not found; create user first to bind automatically', 'warning')
        except Exception:
            flash('Certificate issued but auto-binding failed during parsing', 'error')

        issued = type('Issued', (), {'username': uname, 'fingerprint': fpr, 'bound_to': bound_to})
        return render_template('admin/certs.html', form=IssueClientCertForm(), issued=issued)
    flash('Invalid input for certificate issuance', 'error')
    return redirect(url_for('admin.certs_index'))

@admin_bp.get('/certs/download/<username>/<kind>')
@login_required
def download_cert(username: str, kind: str):
    if not SAFE_UNAME_RE.match(username):
        abort(400)
    kind = kind.lower()
    if kind not in {'p12','crt','key'}:
        abort(404)
    base = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'scripts', 'ca', 'out', 'clients', username))
    path = os.path.join(base, f"{username}.{kind}")
    if not os.path.isfile(path):
        abort(404)
    from flask import send_file
    # For p12, set appropriate mimetype
    mimetype = 'application/x-pkcs12' if kind == 'p12' else 'application/x-pem-file'
    return send_file(path, as_attachment=True, download_name=f"{username}.{kind}", mimetype=mimetype)

@admin_bp.post('/users/bind_current_cert')
@login_required
def bind_current_cert():
    form = BindCurrentCertForm()
    if form.validate_on_submit():
        user = db.session.get(User, int(form.user_id.data))
        if not user:
            abort(404)
        verified = request.headers.get('X-Client-Verify')
        if verified != 'SUCCESS':
            flash('Client certificate not verified by proxy', 'error')
            return redirect(url_for('admin.user_detail', user_id=user.id))
        esc = request.headers.get('X-Client-Cert')
        if not esc:
            flash('No client certificate presented', 'error')
            return redirect(url_for('admin.user_detail', user_id=user.id))
        try:
            cert = cu.parse_escaped_pem_cert(esc)
            if not cert:
                raise ValueError('Invalid PEM in X-Client-Cert header')
            fpr = cu.sha256_fingerprint(cert)
        except Exception:
            flash('Failed to parse presented certificate', 'error')
            return redirect(url_for('admin.user_detail', user_id=user.id))
        # Check existing binding
        existing = UserCertificate.query.filter_by(fingerprint_sha256=fpr).first()
        if existing and existing.user_id != user.id:
            flash('Certificate already bound to another user', 'error')
            return redirect(url_for('admin.user_detail', user_id=user.id))
        serial = request.headers.get('X-Client-Cert-Serial') or hex(cert.serial_number)[2:].upper()
        subject = request.headers.get('X-Client-Cert-Subject')
        issuer = request.headers.get('X-Client-Cert-Issuer')
        # Store UTC as naive datetimes for DB compatibility
        not_before = cert.not_valid_before_utc.replace(tzinfo=None)
        not_after = cert.not_valid_after_utc.replace(tzinfo=None)
        if existing:
            existing.is_revoked = False
            existing.revoked_at = None
            db.session.commit()
            flash('Certificate re-bound to user', 'success')
            return redirect(url_for('admin.user_detail', user_id=user.id))
        db.session.add(UserCertificate(
            user_id=user.id,
            fingerprint_sha256=fpr,
            serial_number=serial,
            issuer=issuer,
            subject=subject,
            not_before=not_before,
            not_after=not_after,
            is_revoked=False,
        ))
        db.session.commit()
        flash('Certificate bound to user', 'success')
        return redirect(url_for('admin.user_detail', user_id=user.id))
    abort(400)
