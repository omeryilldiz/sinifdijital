#!/usr/bin/env python3
"""Synthetic load generator for SF app.
Runs mixed HTTP requests against the local app and executes DB-heavy functions
from the application's services to stress PostgreSQL.

Usage: python3 scripts/synthetic_load.py --duration 60 --concurrency 20 --mode mixed
Modes: http, db, mixed
"""
import time
import argparse
import random
import threading
from sqlalchemy import text
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except Exception:
    requests = None


def http_task(targets, host):
    url = random.choice(targets)
    full = host.rstrip('/') + url
    try:
        if requests:
            r = requests.get(full, timeout=10)
            return (full, r.status_code, len(r.content))
        else:
            # fallback
            from urllib.request import urlopen
            with urlopen(full, timeout=10) as r:
                data = r.read()
                return (full, getattr(r, 'status', 200), len(data))
    except Exception as e:
        return (full, 'ERR', str(e))


def db_task(iterations=1):
    # Import app context and run some heavy service methods
    try:
        from wsgi import app
        with app.app_context():
            from SF.services.leaderboard_service import LeaderboardService
            from SF.services.performance_monitor import performance_monitor
            from SF.models import db, User, UserProgress
            svc = LeaderboardService()
            # pick some user ids
            user_ids = [u.id for u in User.query.limit(50).all()]
            if not user_ids:
                return {'error': 'no users'}
            res = []
            for _ in range(iterations):
                uid = random.choice(user_ids)
                # leaderboard (aggregations)
                try:
                    svc.get_student_leaderboard_data(uid)
                except Exception as e:
                    res.append({'leaderboard_err': str(e)})
                # performance benchmark
                try:
                    performance_monitor.run_performance_benchmark()
                except Exception as e:
                    res.append({'perf_err': str(e)})
                # run a heavy aggregate
                try:
                    q = db.session.execute(text("""
                        SELECT u.id, u.username, count(up.id) as cnt
                        FROM "user" u
                        LEFT JOIN user_progress up ON up.user_id = u.id
                        GROUP BY u.id
                        ORDER BY cnt DESC
                        LIMIT 50
                    """))
                    _ = q.fetchall()
                except Exception as e:
                    res.append({'agg_err': str(e)})
            return {'ok': True, 'details': res}
    except Exception as e:
        return {'error': str(e)}


def run_load(host, duration, concurrency, mode):
    start = time.time()
    end = start + duration
    http_targets = ["/", "/api/user/weekly-progress", "/soru/5/matematik", "/ders_notlari"]

    stats = {'http': 0, 'http_err': 0, 'db': 0, 'db_err': 0}

    def worker_loop(idx):
        while time.time() < end:
            if mode in ('http', 'mixed'):
                out = http_task(http_targets, host)
                if out[1] == 'ERR' or (isinstance(out[1], int) and out[1] >= 500):
                    stats['http_err'] += 1
                else:
                    stats['http'] += 1
            if mode in ('db', 'mixed'):
                out = db_task(iterations=1)
                if out is None or out.get('error'):
                    stats['db_err'] += 1
                else:
                    stats['db'] += 1

    threads = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = [ex.submit(worker_loop, i) for i in range(concurrency)]
        try:
            for f in as_completed(futures, timeout=duration + 5):
                pass
        except Exception:
            # timeouts expected
            pass

    return stats


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='http://127.0.0.1:8000', help='Base host for HTTP requests')
    parser.add_argument('--duration', type=int, default=60, help='Duration in seconds')
    parser.add_argument('--concurrency', type=int, default=20, help='Number of worker threads')
    parser.add_argument('--mode', choices=['http', 'db', 'mixed'], default='mixed')
    args = parser.parse_args()

    print(f"Starting synthetic load: mode={args.mode}, duration={args.duration}s, concurrency={args.concurrency}, host={args.host}")
    stats = run_load(args.host, args.duration, args.concurrency, args.mode)
    print('Done. Stats:', stats)


if __name__ == '__main__':
    main()
