import os
from rq import Worker, Queue, Connection
import redis
from app.app_factory import create_app
import importlib, logging
from flask import Flask

redis_url = os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0')
listen = ['default']

conn = redis.from_url(redis_url)

class AppContextWorker(Worker):
    def __init__(self, queues, app: Flask, *args, **kwargs):
        super().__init__(queues, *args, **kwargs)
        self._app = app
    def perform_job(self, job, queue, *args, **kwargs):
        # Ensure app context inside the forked work horse, too
        with self._app.app_context():
            return super().perform_job(job, queue, *args, **kwargs)

if __name__ == '__main__':
    app = create_app()
    # Preload job modules so RQ can import callables
    try:
        importlib.import_module('app.tasks.jobs')
    except Exception as e:
        logging.exception('Failed to import app.tasks.jobs: %s', e)
    with Connection(conn):
        worker = AppContextWorker([Queue(n) for n in listen], app, connection=conn)
        worker.work()
