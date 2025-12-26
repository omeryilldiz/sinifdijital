import multiprocessing
import os

bind = "0.0.0.0:5000"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "gevent"  # Async worker for better concurrency
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
timeout = 30
keepalive = 5
graceful_timeout = 30
loglevel = os.environ.get('GUNICORN_LOG_LEVEL', 'warning')
accesslog = "/var/log/gunicorn/access.log" if os.path.isdir("/var/log/gunicorn") else "-"
errorlog = "/var/log/gunicorn/error.log" if os.path.isdir("/var/log/gunicorn") else "-"

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
