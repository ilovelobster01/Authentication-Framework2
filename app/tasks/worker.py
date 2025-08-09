import os
from rq import Worker, Queue, Connection
import redis

redis_url = os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0')
listen = ['default']

conn = redis.from_url(redis_url)

if __name__ == '__main__':
    with Connection(conn):
        worker = Worker([Queue(n) for n in listen])
        worker.work()
