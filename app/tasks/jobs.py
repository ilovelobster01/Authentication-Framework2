import os, time, shutil
from datetime import datetime
from typing import Optional

from app.models import db, DownloadRecord

from flask import current_app
from app.app_factory import create_app
from contextlib import contextmanager


@contextmanager
def ensure_app_context():
    try:
        _ = current_app.name  # will raise RuntimeError if no context
        has_ctx = True
    except Exception:
        has_ctx = False
    if has_ctx:
        yield
    else:
        app = create_app()
        with app.app_context():
            yield


def echo(message: str, delay: float = 0.0):
    if delay:
        time.sleep(delay)
    return {"echo": message, "delay": delay}


def yt_download(user_id: int, url: str, format: Optional[str] = None, filename: Optional[str] = None, out_base: str = 'downloads', simulate: bool = False):
    """Download a media URL using yt-dlp.
    - user_id: assign ownership
    - url: media URL
    - format: yt-dlp format string (optional)
    - filename: desired base filename without extension (optional)
    - out_base: base downloads directory relative to repo root
    - simulate: for tests, create a dummy file instead of real download
    """
    with ensure_app_context():
        # Create DB record
        rec = DownloadRecord(user_id=user_id, url=url, status='started', started_at=datetime.utcnow())
        db.session.add(rec)
        db.session.commit()

        # Resolve output directory per user
        base_dir = os.path.abspath(out_base)
        user_dir = os.path.join(base_dir, str(user_id))
        os.makedirs(user_dir, exist_ok=True)

        try:
            if simulate:
                time.sleep(0.1)
                fname = (filename or 'test') + '.txt'
                fpath = os.path.join(user_dir, fname)
                with open(fpath, 'w') as f:
                    f.write('dummy')
                rec.title = 'Simulated Download'
                rec.filename = fname
                rec.filepath = fpath
            else:
                import yt_dlp as ydl
                outtmpl = (filename or '%(title)s') + '.%(ext)s'
                have_ffmpeg = bool(shutil.which('ffmpeg'))
                # Add cookies file if present for this user
                cookies_path = os.path.abspath(os.path.join(out_base, 'cookies', str(user_id), 'cookies.txt'))
                ydl_opts = {
                    'format': format or 'bestvideo+bestaudio/best',
                    'prefer_free_formats': True,
                    'outtmpl': os.path.join(user_dir, outtmpl),
                    'paths': {'home': user_dir},
                    'quiet': True,
                    'noprogress': True,
                    **({'cookiefile': cookies_path} if os.path.exists(cookies_path) else {}),
                }
                if have_ffmpeg:
                    ydl_opts['merge_output_format'] = 'mp4'
                from yt_dlp.utils import DownloadError
                last_err = None
                # Try user-specified format first, then fallbacks
                candidates = []
                if format:
                    candidates.append(format)
                # If the chosen format is a simple numeric id (common for yt), map to that id directly
                # Otherwise, keep as compound or keywords
                if have_ffmpeg:
                    candidates.append('bestvideo+bestaudio/best')
                candidates.append('best')

                info = None
                final_path = None
                for fmt in candidates:
                    ydl_opts['format'] = fmt
                    try:
                        with ydl.YoutubeDL(ydl_opts) as y:
                            info = y.extract_info(url, download=True)
                            # Determine final filepath
                            title = info.get('title')
                            rec.title = title
                            final_path = y.prepare_filename(info)
                            if final_path.endswith('.webm') or final_path.endswith('.mkv'):
                                alt = os.path.splitext(final_path)[0] + '.mp4'
                                if have_ffmpeg and os.path.exists(alt):
                                    final_path = alt
                            break
                    except Exception as e:
                        last_err = str(e)
                        continue
                if not info or not final_path:
                    raise RuntimeError(f"All format attempts failed: {last_err}")
                rec.filepath = final_path
                rec.filename = os.path.basename(final_path)
            rec.status = 'completed'
            rec.completed_at = datetime.utcnow()
            db.session.commit()
            return {'status': 'ok', 'id': rec.id, 'filepath': rec.filepath}
        except Exception as e:
            rec.status = 'failed'
            rec.error = str(e)
            db.session.commit()
            raise
