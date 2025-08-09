import os
import json
import fakeredis
import redis
from rq import Queue, SimpleWorker

from mcp_server.app import create_app


def fake_conn(monkeypatch):
    fr = fakeredis.FakeRedis()
    monkeypatch.setattr(redis, 'from_url', lambda url: fr)
    return fr


def test_mcp_submit_and_process(monkeypatch):
    conn = fake_conn(monkeypatch)
    app = create_app()
    app.config['TESTING'] = True
    os.environ['MCP_TOKEN'] = 't'
    client = app.test_client()

    # Submit job
    r = client.post('/api/jobs', json={'tool':'echo','args':{'message':'x','delay':0}}, headers={'Authorization':'Bearer t'})
    assert r.status_code == 202
    job_id = r.get_json()['job_id']

    # Process with SimpleWorker
    q = Queue('default', connection=conn)
    w = SimpleWorker([q], connection=conn)
    w.work(burst=True)

    # Check job result
    from rq.job import Job
    job = Job.fetch(job_id, connection=conn)
    assert job.is_finished
    assert job.result['echo'] == 'x'
