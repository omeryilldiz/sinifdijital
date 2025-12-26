from sqlalchemy.orm import load_only, defer, joinedload, selectinload
from sqlalchemy import text, func, case, and_, or_
from datetime import datetime, timedelta
from SF import db
from SF.models import *
from SF.services.query_optimizer import QueryOptimizer

class AdvancedQueryOptimizer(QueryOptimizer):
    """Gelişmiş query optimizasyon servisi"""
    
    @staticmethod
    def get_minimal_user_data(user_id):
        """Minimal user data - sadece gerekli alanlar"""
        return db.session.query(User).options(
            load_only(
                User.id, 
                User.username, 
                User.first_name, 
                User.last_name,
                User.class_no,
                User.role
            )
        ).filter(User.id == user_id).first()
    
    @staticmethod
    def get_content_summary_optimized(limit=50):
        """Content summary - minimal veri transferi"""
        return db.session.query(Icerik).options(
            load_only(Icerik.id, Icerik.baslik, Icerik.created_at),
            joinedload(Icerik.unite).load_only(Unite.id, Unite.unite),
            defer(Icerik.icerik)  # Büyük content alanını defer et
        ).limit(limit).all()
    
    @staticmethod
    def get_leaderboard_raw_sql(time_period='weekly', class_filter=None, limit=100):
        """Raw SQL ile optimize edilmiş leaderboard"""
        
        # Time period için date filter
        if time_period == 'daily':
            date_filter = "AND up.tarih >= CURRENT_DATE"
        elif time_period == 'weekly':
            date_filter = "AND up.tarih >= CURRENT_DATE - INTERVAL '7 days'"
        elif time_period == 'monthly':
            date_filter = "AND up.tarih >= CURRENT_DATE - INTERVAL '30 days'"
        else:
            date_filter = ""
        
        # Class filter
        class_filter_sql = ""
        if class_filter:
            class_filter_sql = f"AND u.class_no = '{class_filter}'"
        
        sql = text(f"""
            SELECT 
                u.id,
                u.username,
                u.first_name,
                u.last_name, 
                u.class_no,
                COALESCE(SUM(up.puan), 0) as total_points,
                COUNT(up.id) as activity_count,
                ROW_NUMBER() OVER (ORDER BY COALESCE(SUM(up.puan), 0) DESC) as rank
            FROM "user" u
            LEFT JOIN user_progress up ON u.id = up.user_id 
                AND up.puan IS NOT NULL
                {date_filter}
            WHERE u.role = 'user' 
                AND u.profile_completed = true
                {class_filter_sql}
            GROUP BY u.id, u.username, u.first_name, u.last_name, u.class_no
            ORDER BY total_points DESC
            LIMIT :limit
        """)
        
        return db.session.execute(sql, {'limit': limit}).fetchall()
    
    @staticmethod
    def get_user_activity_summary(user_id, days=30):
        """Kullanıcı aktivite özeti - optimize edilmiş"""
        
        sql = text("""
            SELECT 
                DATE(up.tarih) as activity_date,
                up.activity_type,
                COUNT(*) as activity_count,
                SUM(up.puan) as daily_points,
                SUM(up.dogru_sayisi) as correct_answers,
                SUM(up.yanlis_sayisi) as wrong_answers
            FROM user_progress up
            WHERE up.user_id = :user_id
                AND up.tarih >= CURRENT_DATE - (INTERVAL '1 day' * :days)
            GROUP BY DATE(up.tarih), up.activity_type
            ORDER BY activity_date DESC, up.activity_type
        """)
        
        return db.session.execute(sql, {
            'user_id': user_id,
            'days': days
        }).fetchall()
    
    @staticmethod
    def bulk_insert_progress(progress_data):
        """Toplu progress insert - performans için"""
        if not progress_data:
            return False
            
        try:
            db.session.bulk_insert_mappings(UserProgress, progress_data)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            from SF import app
            app.logger.error(f"Bulk insert error: {str(e)}")
            return False
    
    @staticmethod
    def get_content_with_stats(icerik_id):
        """İçerik ve istatistikleri birlikte getir"""
        
        # Ana content query
        content = db.session.query(Icerik).options(
            joinedload(Icerik.unite).options(
                joinedload(Unite.ders).options(
                    joinedload(Ders.sinif)
                )
            ),
            selectinload(Icerik.videolar).options(
                load_only(VideoIcerik.id, VideoIcerik.video_title, VideoIcerik.video_url, VideoIcerik.sira)
            ),
            defer(Icerik.icerik)  # İlk yüklemede content'i defer et
        ).filter(Icerik.id == icerik_id).first()
        
        if not content:
            return None, None
        
        # İstatistikleri ayrı sorguda al
        stats_sql = text("""
            SELECT 
                COUNT(DISTINCT up.user_id) as unique_users,
                COUNT(up.id) as total_activities,
                AVG(up.puan) as avg_points,
                SUM(CASE WHEN up.activity_type = 'content_reading' THEN 1 ELSE 0 END) as reading_count,
                SUM(CASE WHEN up.activity_type = 'question_solving' THEN 1 ELSE 0 END) as question_count
            FROM user_progress up
            WHERE up.icerik_id = :icerik_id
        """)
        
        stats = db.session.execute(stats_sql, {'icerik_id': icerik_id}).fetchone()
        
        return content, {
            'unique_users': stats.unique_users or 0,
            'total_activities': stats.total_activities or 0,
            'avg_points': round(float(stats.avg_points or 0), 2),
            'reading_count': stats.reading_count or 0,
            'question_count': stats.question_count or 0
        }
    
    @staticmethod
    def search_content_advanced(search_term, user_class=None, limit=20):
        """Gelişmiş içerik arama - class filter ile"""
        search = f"%{search_term}%"
        
        query = db.session.query(Icerik).options(
            joinedload(Icerik.unite).options(
                joinedload(Unite.ders).options(
                    joinedload(Ders.sinif)
                )
            ),
            load_only(Icerik.id, Icerik.baslik, Icerik.created_at),
            defer(Icerik.icerik)
        ).filter(
            or_(
                Icerik.baslik.ilike(search),
                Icerik.icerik.ilike(search)
            )
        )
        
        # Class filter ekle
        if user_class:
            query = query.join(Unite).join(Ders).join(Sinif).filter(
                Sinif.sinif.like(f"%{user_class}%")
            )
        
        return query.limit(limit).all()
    
    @staticmethod
    def get_dashboard_data_optimized(user_id):
        """Dashboard için optimize edilmiş veri çekme"""
        # Tek sorguda tüm istatistikleri al
        stats = AdvancedQueryOptimizer.get_user_progress_stats(user_id)
        
        # Son aktiviteler - minimal veri
        recent_activities = db.session.query(UserProgress).options(
            load_only(UserProgress.id, UserProgress.tarih, UserProgress.activity_type, UserProgress.puan),
            joinedload(UserProgress.icerik).load_only(Icerik.id, Icerik.baslik)
        ).filter(
            UserProgress.user_id == user_id
        ).order_by(UserProgress.tarih.desc()).limit(5).all()
        
        # Yanlış sorular - optimize
        wrong_questions = db.session.query(UserProgress).options(
            load_only(UserProgress.id, UserProgress.tarih, UserProgress.yanlis_sayisi),
            joinedload(UserProgress.soru).load_only(Soru.id, Soru.soru_resim)  # soru_metni -> soru_resim
        ).filter(
            UserProgress.user_id == user_id,
            UserProgress.yanlis_sayisi > 0,
            UserProgress.soru_id.isnot(None)
        ).order_by(UserProgress.tarih.desc()).limit(5).all()
        
        return {
            'stats': stats,
            'recent_activities': recent_activities,
            'wrong_questions': wrong_questions
        }