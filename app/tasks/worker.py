import os
from rq import Worker, Queue, Connection
import redis
from app.app_factory import create_app
import importlib, logging

redis_url = os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0')
listen = ['default']

conn = redis.from_url(redis_url)

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        # Preload job modules so RQ can import by string path
        try:
            importlib.import_module('app.tasks.jobs')
        except Exception as e:
            logging.exception('Failed to import app.tasks.jobs: %s', e)
        with Connection(conn):
            worker = Worker([Queue(n) for n in listen])
            worker.work()
