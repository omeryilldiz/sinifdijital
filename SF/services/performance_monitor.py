import time
import logging
from functools import wraps
from datetime import datetime, timedelta
from SF import app, db
from sqlalchemy import text, event
from sqlalchemy.engine import Engine

class PerformanceMonitor:
    """Database performans izleme servisi"""
    
    def __init__(self):
        self.slow_query_threshold = 0.1  # 100ms
        self.logger = logging.getLogger('performance')
        self.setup_query_logging()
        
    def setup_query_logging(self):
        """Query logging setup"""
        try:
            @event.listens_for(Engine, "before_cursor_execute")
            def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
                context._query_start_time = time.time()
                context._query_statement = statement
            
            @event.listens_for(Engine, "after_cursor_execute")
            def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
                if hasattr(context, '_query_start_time'):
                    total = time.time() - context._query_start_time
                    if total > self.slow_query_threshold:
                        self.logger.warning(
                            f"SLOW QUERY ({total:.3f}s): {statement[:200]}..."
                        )
        except Exception as e:
            app.logger.error(f"Query logging setup error: {str(e)}")
    
    def monitor_query(self, func_name="Unknown"):
        """Query süresini izle decorator"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    self.logger.error(f"Query error in {func_name}: {str(e)}")
                    raise
                finally:
                    duration = time.time() - start_time
                    if duration > self.slow_query_threshold:
                        self.logger.warning(
                            f"Slow function - {func_name}: {duration:.3f}s"
                        )
            return wrapper
        return decorator
    
    @staticmethod
    def get_performance_stats():
        """Sistem performans istatistikleri"""
        try:
            engine = db.engine
            
            stats = {
                'timestamp': datetime.utcnow().isoformat(),
                'database_info': {
                    'url_safe': str(engine.url).split('@')[0] + '@***' if '@' in str(engine.url) else str(engine.url),
                    'dialect': engine.dialect.name,
                    'driver': getattr(engine.dialect, 'driver', 'unknown')
                }
            }
            
            # Pool bilgileri (varsa)
            try:
                pool = engine.pool
                stats['pool_info'] = {
                    'pool_size': pool.size(),
                    'checked_in': pool.checkedin(),
                    'checked_out': pool.checkedout(),
                    'overflow': pool.overflow(),
                    'invalidated': pool.invalidated()
                }
            except Exception as e:
                stats['pool_info'] = {'error': str(e)}
            
            # Database-specific stats
            if engine.dialect.name == 'postgresql':
                stats.update(PerformanceMonitor._get_postgresql_stats())
            elif engine.dialect.name == 'sqlite':
                stats.update(PerformanceMonitor._get_sqlite_stats())
                
            return stats
            
        except Exception as e:
            app.logger.error(f"Performance stats error: {str(e)}")
            return {
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    @staticmethod
    def _get_postgresql_stats():
        """PostgreSQL özel istatistikleri"""
        try:
            # Connection count
            conn_sql = text("""
                SELECT count(*) as active_connections
                FROM pg_stat_activity 
                WHERE state = 'active'
            """)
            
            # Database size
            size_sql = text("""
                SELECT pg_size_pretty(pg_database_size(current_database())) as db_size
            """)
            
            # Index usage (top 5)
            index_sql = text("""
                SELECT schemaname, tablename, indexname, idx_tup_fetch, idx_tup_read
                FROM pg_stat_user_indexes 
                WHERE idx_tup_fetch > 0
                ORDER BY idx_tup_fetch DESC 
                LIMIT 5
            """)
            
            active_connections = db.session.execute(conn_sql).scalar()
            db_size = db.session.execute(size_sql).scalar()
            top_indexes = db.session.execute(index_sql).fetchall()
            
            return {
                'postgresql_stats': {
                    'active_connections': active_connections,
                    'database_size': db_size,
                    'top_indexes': [dict(row._mapping) for row in top_indexes]
                }
            }
            
        except Exception as e:
            return {'postgresql_error': str(e)}
    
    @staticmethod
    def _get_sqlite_stats():
        """SQLite özel istatistikleri"""
        try:
            # Database file size
            import os
            db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
            
            if db_uri.startswith('sqlite:///'):
                db_path = db_uri.replace('sqlite:///', '')
                if os.path.exists(db_path):
                    file_size = os.path.getsize(db_path)
                    file_size_mb = round(file_size / (1024 * 1024), 2)
                else:
                    file_size_mb = 0
            else:
                file_size_mb = 0
            
            # Table count
            table_sql = text("""
                SELECT count(*) as table_count
                FROM sqlite_master 
                WHERE type='table'
            """)
            
            table_count = db.session.execute(table_sql).scalar()
            
            return {
                'sqlite_stats': {
                    'file_size_mb': file_size_mb,
                    'table_count': table_count
                }
            }
            
        except Exception as e:
            return {'sqlite_error': str(e)}
    
    @staticmethod
    def run_performance_benchmark():
        """Performans benchmark testi"""
        results = []
        
        try:
            # Test 1: Basic SELECT
            start_time = time.time()
            from SF.models import User
            user_count = User.query.count()
            test1_time = time.time() - start_time
            results.append({
                'test': 'Basic User Count',
                'time': f"{test1_time:.4f}s",
                'result': f"{user_count} users",
                'status': 'fast' if test1_time < 0.1 else 'slow'
            })
            
            # Test 2: JOIN Query
            start_time = time.time()
            users_with_schools = db.session.query(User).options(
                db.joinedload(User.school)
            ).filter(User.role == 'user').limit(5).all()
            test2_time = time.time() - start_time
            results.append({
                'test': 'Users with Schools JOIN',
                'time': f"{test2_time:.4f}s",
                'result': f"{len(users_with_schools)} users loaded",
                'status': 'fast' if test2_time < 0.1 else 'slow'
            })
            
            # Test 3: Complex Query
            start_time = time.time()
            from SF.models import UserProgress
            recent_progress = UserProgress.query.order_by(
                UserProgress.tarih.desc()
            ).limit(10).all()
            test3_time = time.time() - start_time
            results.append({
                'test': 'Recent User Progress',
                'time': f"{test3_time:.4f}s",
                'result': f"{len(recent_progress)} records",
                'status': 'fast' if test3_time < 0.1 else 'slow'
            })
            
            # Test 4: Connection Test
            start_time = time.time()
            db.session.execute(text('SELECT 1 as test'))
            test4_time = time.time() - start_time
            results.append({
                'test': 'Database Connection',
                'time': f"{test4_time:.4f}s",
                'result': 'Connected',
                'status': 'fast' if test4_time < 0.05 else 'slow'
            })
            
        except Exception as e:
            results.append({
                'test': 'ERROR',
                'time': '0.000s',
                'result': str(e),
                'status': 'error'
            })
        
        return results
    
    @staticmethod
    def get_slow_queries_report(hours=24):
        """Yavaş sorgu raporu (placeholder)"""
        return {
            'message': f'Son {hours} saatteki yavaş sorgular analiz edilecek',
            'threshold': 0.1,
            'status': 'monitoring_active',
            'recommendation': 'Query logging aktif. Yavaş sorgular otomatik loglanacak.'
        }

# Global performance monitor instance
performance_monitor = PerformanceMonitor()