import os, json
from flask import Flask, request, jsonify
import redis
from rq import Queue

SAFE_TOOLS = {'echo'}

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
            # Enqueue by import path so MCP doesn't need app package locally
            job = q.enqueue('app.tasks.jobs.echo', **args)
        else:
            return {'message':'Unknown'}, 400
        return {'job_id': job.get_id()}, 202

    return app

app = create_app()
