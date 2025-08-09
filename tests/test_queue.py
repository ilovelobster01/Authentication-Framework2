import os
import json
import fakeredis
import redis
from rq import Queue
from rq import SimpleWorker

from app.tasks.jobs import echo


def fake_conn(monkeypatch):
    fr = fakeredis.FakeRedis()
    monkeypatch.setattr(redis, 'from_url', lambda url: fr)
    return fr


def test_rq_queue_and_worker(monkeypatch):
    conn = fake_conn(monkeypatch)
    q = Queue('default', connection=conn)
    job = q.enqueue(echo, message='hi', delay=0)
    w = SimpleWorker([q], connection=conn)
    w.work(burst=True)
    job.refresh()
    assert job.is_finished
    assert job.result == {"echo": "hi", "delay": 0}
