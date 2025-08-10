from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, current_app
from flask_login import login_required, current_user
from ..models import db, User, UserCertificate, AuditLog, DownloadRecord
from ..security import PasswordSecurity
from .. import cert_utils as cu
from .forms import CreateUserForm, ResetPasswordForm, ToggleActiveForm, ResetTOTPForm, UnbindCertForm, BindCurrentCertForm, IssueClientCertForm, CertFilterForm
from urllib.parse import unquote, urlencode
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import subprocess, pathlib, json, csv, io, base64
import requests
import redis
from rq import Queue
from rq.job import Job
from rq.registry import FailedJobRegistry, StartedJobRegistry, FinishedJobRegistry, ScheduledJobRegistry, DeferredJobRegistry

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Utility to safely map usernames to filesystem paths
import os, re
SAFE_UNAME_RE = re.compile(r'^[A-Za-z0-9_.-]+$')

def client_out_dir(username: str) -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'scripts', 'ca', 'out', 'clients', username)


pwdsec = PasswordSecurity()

def audit(event_type: str, details: dict | None = None):
    try:
        entry = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            event_type=event_type,
            ip=request.headers.get('X-Forwarded-For', request.remote_addr),
            user_agent=request.headers.get('User-Agent'),
            details=json.dumps(details) if details else None,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()

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
    audit('cert_revoked', {'fingerprint': fp, 'user': c.user.username})
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
    audit('cert_unrevoked', {'fingerprint': fp, 'user': c.user.username})
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
    audit('cert_view', {'fingerprint': fingerprint, 'user': cert.user.username})
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
    # Pagination
    page = max(int(request.args.get('page', 1) or 1), 1)
    per_page = min(max(int(request.args.get('per_page', 25) or 25), 1), 200)

    q = q.order_by(User.username.asc(), UserCertificate.created_at.desc())

    # CSV export of filtered set (all rows)
    if (request.args.get('export') or '').lower() == 'csv':
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(['username','fingerprint_sha256','serial','subject','issuer','not_before','not_after','is_revoked'])
        for c in q.all():
            w.writerow([c.user.username, c.fingerprint_sha256, c.serial_number, c.subject, c.issuer, c.not_before, c.not_after, c.is_revoked])
        from flask import Response
        return Response(out.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename="certs.csv"'})

    total = q.count()
    certs = q.offset((page-1)*per_page).limit(per_page).all()

    params = request.args.to_dict(flat=True)
    base = url_for('admin.certs_index')
    export_url = base + '?' + urlencode({**params, 'export': 'csv'})
    last_page = ((total - 1) // per_page) + 1 if total else 1
    prev_url = base + '?' + urlencode({**params, 'page': page-1, 'per_page': per_page}) if page > 1 else None
    next_url = base + '?' + urlencode({**params, 'page': page+1, 'per_page': per_page}) if page < last_page else None

    return render_template('admin/certs.html', issue_form=issue_form, filter_form=filter_form, certs=certs, issued=None, page=page, per_page=per_page, total=total, last_page=last_page, export_url=export_url, prev_url=prev_url, next_url=next_url)

@admin_bp.get('/audit')
@login_required
def audit_index():
    # admin_required is enforced in before_request of blueprint/app
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template('admin/audit.html', logs=logs)

@admin_bp.get('/downloaders')
@login_required
def downloaders_index():
    # List all downloads across users with basic filters
    q = DownloadRecord.query.join(User, User.id == DownloadRecord.user_id)
    uname = request.args.get('username','').strip()
    status = request.args.get('status','').strip().lower()
    if uname:
        q = q.filter(User.username.ilike(f"%{uname}%"))
    if status:
        q = q.filter(DownloadRecord.status.ilike(f"%{status}%"))
    items = q.order_by(DownloadRecord.created_at.desc()).limit(500).all()
    return render_template('admin/downloaders.html', items=items, username=uname, status=status)

@admin_bp.get('/queue')
@login_required
def queue_index():
    r = redis.from_url(current_app.config.get('REDIS_URL', 'redis://127.0.0.1:6379/0'))
    q = Queue('default', connection=r)
    failed = FailedJobRegistry('default', connection=r)
    started = StartedJobRegistry('default', connection=r)
    finished = FinishedJobRegistry('default', connection=r)
    scheduled = ScheduledJobRegistry('default', connection=r)
    deferred = DeferredJobRegistry('default', connection=r)
    jobs = [Job.fetch(jid, connection=r) for jid in q.job_ids]
    failed_jobs = [Job.fetch(jid, connection=r) for jid in failed.get_job_ids()]
    return render_template('admin/queue.html', q=q, jobs=jobs, failed_jobs=failed_jobs, started_count=len(started), finished_count=len(finished), scheduled_count=len(scheduled), deferred_count=len(deferred))

@admin_bp.get('/queue/job/<job_id>')
@login_required
def queue_job_detail(job_id):
    r = redis.from_url(current_app.config.get('REDIS_URL', 'redis://127.0.0.1:6379/0'))
    job = Job.fetch(job_id, connection=r)
    return render_template('admin/queue_job.html', job=job)

@admin_bp.post('/queue/requeue/<job_id>')
@login_required
def queue_requeue(job_id):
    r = redis.from_url(current_app.config.get('REDIS_URL', 'redis://127.0.0.1:6379/0'))
    job = Job.fetch(job_id, connection=r)
    job.requeue()
    flash('Job requeued', 'success')
    return redirect(url_for('admin.queue_index'))

@admin_bp.post('/queue/delete/<job_id>')
@login_required
def queue_delete(job_id):
    r = redis.from_url(current_app.config.get('REDIS_URL', 'redis://127.0.0.1:6379/0'))
    job = Job.fetch(job_id, connection=r)
    job.delete()
    flash('Job deleted', 'success')
    return redirect(url_for('admin.queue_index'))

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

        # Output dir
        base_scripts = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'scripts', 'ca'))
        out_dir = os.path.abspath(os.path.join(base_scripts, 'out', 'clients', uname))
        os.makedirs(out_dir, exist_ok=True)

        issuer_mode = os.environ.get('CA_ISSUER', 'local').lower()
        if issuer_mode == 'http':
            api_url = os.environ.get('CA_API_URL')
            api_token = os.environ.get('CA_API_TOKEN')
            if not api_url or not api_token:
                flash('CA API configuration missing (CA_API_URL/CA_API_TOKEN)', 'error')
                return redirect(url_for('admin.certs_index'))
            try:
                r = requests.post(api_url.rstrip('/') + '/issue', json={
                    'username': uname,
                    'email': email,
                    'p12_password': p12_pass,
                }, headers={'Authorization': f'Bearer {api_token}'}, timeout=60)
                r.raise_for_status()
                data = r.json()
            except Exception as e:
                flash('Certificate issuance via API failed', 'error')
                return redirect(url_for('admin.certs_index'))
            # Expect base64 fields: crt, key, p12
            try:
                crt_b = base64.b64decode(data.get('crt',''))
                key_b = base64.b64decode(data.get('key',''))
                p12_b = base64.b64decode(data.get('p12',''))
                with open(os.path.join(out_dir, f"{uname}.crt"), 'wb') as f: f.write(crt_b)
                with open(os.path.join(out_dir, f"{uname}.key"), 'wb') as f: f.write(key_b)
                with open(os.path.join(out_dir, f"{uname}.p12"), 'wb') as f: f.write(p12_b)
                os.chmod(os.path.join(out_dir, f"{uname}.key"), 0o600)
                os.chmod(os.path.join(out_dir, f"{uname}.p12"), 0o600)
            except Exception:
                flash('Failed to save issued certificate artifacts', 'error')
                return redirect(url_for('admin.certs_index'))
        else:
            # Local shell issuance
            script = os.path.join(base_scripts, 'issue_client.sh')
            try:
                env = os.environ.copy()
                cmd = [script, uname, email, p12_pass, ca_pass]
                subprocess.check_call(cmd, cwd=base_scripts, env=env)
            except subprocess.CalledProcessError:
                flash('Certificate issuance failed', 'error')
                return redirect(url_for('admin.certs_index'))

        # Verify output
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
