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
            # Filter into valid video-only and audio-only formats
            video_formats = []
            audio_formats = []
            def add_vid(f):
                video_formats.append({
                    'format_id': f.get('format_id'), 'ext': f.get('ext'), 'height': f.get('height'), 'fps': f.get('fps')
                })
            def add_aud(f):
                audio_formats.append({
                    'format_id': f.get('format_id'), 'ext': f.get('ext'), 'acodec': f.get('acodec')
                })
            for f in info.get('formats', []):
                fid = f.get('format_id'); ext = f.get('ext'); v = f.get('vcodec'); a = f.get('acodec'); proto = f.get('protocol')
                if not fid or not ext:
                    continue
                # Skip only HLS variants; allow DASH, which yt-dlp can download
                if proto in ('m3u8', 'm3u8_native'):
                    continue
                # Video-only candidates (common ids like 137/248 etc.)
                if v and v != 'none' and (a in (None, 'none')) and ext in ('mp4','webm','mkv'):
                    add_vid(f)
                # Audio-only candidates (common ids like 140/251 etc.)
                if a and a != 'none' and (v in (None, 'none')) and ext in ('m4a','mp3','opus','webm','aac'):
                    add_aud(f)
            # Always include fallbacks at the top
            video_formats = [{'format_id': 'bestvideo', 'ext': '', 'height': None, 'fps': None}] + video_formats
            audio_formats = [{'format_id': 'bestaudio', 'ext': '', 'acodec': None}] + audio_formats
            return {'title': info.get('title'), 'video_formats': video_formats, 'audio_formats': audio_formats}, 200
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
