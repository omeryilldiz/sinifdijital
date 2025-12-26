"""
Slow Query Logging ve Performans İzleme
SQLAlchemy event listeners ile yavaş sorguları tespit ve log et
"""
from sqlalchemy import event
from sqlalchemy.pool import Pool
import time
import logging
from datetime import datetime, timedelta
from collections import deque
import threading

class QueryLogger:
    """SQLAlchemy query performance monitoring"""
    
    def __init__(self, slow_query_threshold_seconds=0.1, max_queries_in_memory=1000):
        """
        Args:
            slow_query_threshold_seconds: Yavaş kabul edilen sorgu süresi (default 100ms)
            max_queries_in_memory: Bellekte tutulacak max sorgu sayısı
        """
        self.logger = logging.getLogger('SF.QueryLogger')
        self.slow_query_threshold = slow_query_threshold_seconds
        self.max_queries = max_queries_in_memory
        
        # Thread-safe query history
        self._queries_lock = threading.RLock()
        self.slow_queries = deque(maxlen=max_queries_in_memory)
        self.all_queries = deque(maxlen=max_queries_in_memory * 2)
        
        self.total_queries = 0
        self.total_slow_queries = 0
        self.total_execution_time = 0.0
    
    def register_listeners(self, db_engine):
        """SQLAlchemy engine'e listeners'ı kaydet"""
        
        @event.listens_for(db_engine, "before_cursor_execute")
        def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            # Sorgu başlangıcının zamanını kaydet
            conn.info.setdefault('query_start_time', []).append(time.time())
        
        @event.listens_for(db_engine, "after_cursor_execute")
        def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            # Sorgu süresini hesapla
            try:
                start_time = conn.info['query_start_time'].pop(-1)
                total_time = time.time() - start_time
                
                # Query kaydını oluştur
                query_record = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'statement': statement,
                    'parameters': parameters,
                    'execution_time': round(total_time, 4),
                    'slow': total_time >= self.slow_query_threshold
                }
                
                # İstatistikleri güncelle
                with self._queries_lock:
                    self.total_queries += 1
                    self.total_execution_time += total_time
                    self.all_queries.append(query_record)
                    
                    if query_record['slow']:
                        self.total_slow_queries += 1
                        self.slow_queries.append(query_record)
                
                # Yavaş sorguları log et
                if query_record['slow']:
                    self.logger.warning(
                        f"SLOW QUERY ({total_time:.4f}s): {statement[:100]}... "
                        f"Params: {str(parameters)[:100]}"
                    )
                
            except Exception as e:
                self.logger.error(f"Query logging error: {str(e)}")
    
    def get_stats(self) -> dict:
        """Genel istatistikleri döndür"""
        with self._queries_lock:
            avg_time = (self.total_execution_time / self.total_queries) if self.total_queries > 0 else 0
            return {
                'total_queries': self.total_queries,
                'slow_queries': self.total_slow_queries,
                'total_execution_time': round(self.total_execution_time, 4),
                'average_execution_time': round(avg_time, 4),
                'slow_query_threshold': self.slow_query_threshold,
                'slow_percentage': round((self.total_slow_queries / self.total_queries * 100), 2) if self.total_queries > 0 else 0
            }
    
    def get_slow_queries(self, limit=50, hours=1) -> list:
        """
        Son X saatteki yavaş sorguları döndür
        
        Args:
            limit: Döndürülecek max sorgu sayısı
            hours: Kaç saat geriye bakılacak
        
        Return: [{timestamp, statement, parameters, execution_time, slow}, ...]
        """
        with self._queries_lock:
            cutoff_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            
            result = []
            for query in list(self.slow_queries)[-limit:]:
                if query['timestamp'] >= cutoff_time:
                    result.append(query)
            
            # En yavaş sorgudan en hızlısına sıra
            result.sort(key=lambda x: x['execution_time'], reverse=True)
            return result
    
    def get_slowest_queries(self, limit=10) -> list:
        """En yavaş N sorguyu döndür"""
        with self._queries_lock:
            queries = sorted(
                list(self.slow_queries),
                key=lambda x: x['execution_time'],
                reverse=True
            )
            return queries[:limit]
    
    def get_most_frequent_slow_queries(self, limit=10) -> list:
        """En sık yavaş çalışan sorguları döndür (unique statement'lara göre)"""
        with self._queries_lock:
            query_stats = {}
            
            for query in self.slow_queries:
                stmt = query['statement'][:100]  # Kısalt
                if stmt not in query_stats:
                    query_stats[stmt] = {
                        'count': 0,
                        'total_time': 0,
                        'avg_time': 0,
                        'full_statement': query['statement']
                    }
                
                query_stats[stmt]['count'] += 1
                query_stats[stmt]['total_time'] += query['execution_time']
            
            # Ortalama süreyi hesapla
            for stmt in query_stats:
                query_stats[stmt]['avg_time'] = round(
                    query_stats[stmt]['total_time'] / query_stats[stmt]['count'], 4
                )
            
            # Count'a göre sırala
            sorted_queries = sorted(
                query_stats.items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )
            
            return [
                {
                    'statement': item[0],
                    'full_statement': item[1]['full_statement'],
                    'count': item[1]['count'],
                    'total_time': round(item[1]['total_time'], 4),
                    'avg_time': item[1]['avg_time']
                }
                for item in sorted_queries[:limit]
            ]
    
    def reset_stats(self):
        """İstatistikleri sıfırla"""
        with self._queries_lock:
            self.slow_queries.clear()
            self.all_queries.clear()
            self.total_queries = 0
            self.total_slow_queries = 0
            self.total_execution_time = 0.0
            self.logger.info("Query statistics reset")


# Global query logger instance
query_logger = QueryLogger(slow_query_threshold_seconds=0.1)
