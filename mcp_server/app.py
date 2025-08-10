import os, json
from flask import Flask, request, jsonify
import redis
from rq import Queue

SAFE_TOOLS = {'echo', 'yt_analyze', 'yt_download'}

def create_app():
    app = Flask(__name__)
    token = os.environ.get('MCP_TOKEN')
    redis_url = os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0')
    rconn = redis.from_url(redis_url)
    q = Queue('default', connection=rconn)

    def auth(req):
        hdr = req.headers.get('Authorization','')
        return token and hdr == f'Bearer {token}'

    @app.get('/api/health')
    def health():
        return {'status':'ok'}, 200

    # Accept both /api/... and root paths for flexibility
    @app.post('/api/yt/analyze')
    @app.post('/yt/analyze')
    def yt_analyze():
        raw_flag = False
        # Accept raw flag via JSON or query string
        try:
            body = request.get_json(silent=True) or {}
            raw_flag = bool(body.get('raw'))
            url = body.get('url')
        except Exception:
            url = None
        if url is None:
            url = request.args.get('url')
            raw_flag = raw_flag or (request.args.get('raw') in ('1','true','yes'))
        if not auth(request):
            return {'message':'Unauthorized'}, 401
        data = request.get_json(force=True)
        url = data.get('url')
        if not url:
            return {'message':'url required'}, 400
        try:
            import yt_dlp as ydl
            opts = {'skip_download': True, 'quiet': True, 'noprogress': True}
            with ydl.YoutubeDL(opts) as y:
                info = y.extract_info(url, download=False)
            # Filter into valid video-only and audio-only formats, be permissive about ext
            video_formats = []
            audio_formats = []
            def add_vid(f):
                video_formats.append({
                    'format_id': f.get('format_id'), 'ext': f.get('ext') or '', 'height': f.get('height'), 'fps': f.get('fps')
                })
            def add_aud(f):
                audio_formats.append({
                    'format_id': f.get('format_id'), 'ext': f.get('ext') or '', 'acodec': f.get('acodec')
                })
            for f in info.get('formats', []):
                fid = f.get('format_id'); v = f.get('vcodec'); a = f.get('acodec'); proto = f.get('protocol')
                if not fid:
                    continue
                # Skip only HLS variants; allow DASH and others
                if proto in ('m3u8', 'm3u8_native'):
                    continue
                # Video-only candidates (common ids like 137/248 etc.)
                if v and v != 'none' and (a in (None, 'none')):
                    add_vid(f)
                # Audio-only candidates (common ids like 140/251 etc.)
                if a and a != 'none' and (v in (None, 'none')):
                    add_aud(f)
            # Progressive combined (single file) formats: both vcodec & acodec present, not HLS
            progressive_formats = []
            for f in info.get('formats', []):
                fid = f.get('format_id'); v = f.get('vcodec'); a = f.get('acodec'); proto = f.get('protocol')
                if not fid:
                    continue
                if proto in ('m3u8', 'm3u8_native'):
                    continue
                if v and v != 'none' and a and a != 'none':
                    progressive_formats.append({
                        'format_id': fid, 'ext': f.get('ext') or '', 'height': f.get('height'), 'fps': f.get('fps')
                    })
            # Always include fallbacks at the top for separate streams
            video_formats = [{'format_id': 'bestvideo', 'ext': '', 'height': None, 'fps': None}] + video_formats
            audio_formats = [{'format_id': 'bestaudio', 'ext': '', 'acodec': None}] + audio_formats
            return {
                'title': info.get('title'),
                'progressive_formats': progressive_formats,
                'video_formats': video_formats,
                'audio_formats': audio_formats
            }, 200
        except Exception as e:
            return {'message': 'analyze failed', 'error': str(e)}, 500

    @app.post('/api/jobs')
    def submit_job():
        if not auth(request):
            return {'message':'Unauthorized'}, 401
        data = request.get_json(force=True)
        tool = data.get('tool')
        args = data.get('args') or {}
        if tool not in SAFE_TOOLS:
            return {'message':'Unsupported tool'}, 400
        if tool == 'echo':
            from app.tasks.jobs import echo
            job = q.enqueue(echo, **args)
        elif tool == 'yt_download':
            from app.tasks.jobs import yt_download
            job = q.enqueue(yt_download, **args)
        else:
            return {'message':'Unknown'}, 400
        return {'job_id': job.get_id()}, 202

    return app

app = create_app()
