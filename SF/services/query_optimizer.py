from sqlalchemy.orm import joinedload, selectinload, contains_eager
from sqlalchemy import func, case, and_, or_, text
from datetime import datetime, timedelta
from SF import db
from SF.models import *

class QueryOptimizer:
    """Veritabanı sorgu optimizasyon servisi"""
    
    @staticmethod
    def get_students_optimized(filters=None):
        """Optimize edilmiş öğrenci listesi"""
        query = db.session.query(User).options(
            joinedload(User.school).options(
                joinedload(School.district).options(
                    joinedload(District.province)
                ),
                joinedload(School.school_type)
            )
        ).filter(User.role == 'user')
        
        if filters:
            if filters.get('search'):
                search = f"%{filters['search']}%"
                query = query.filter(
                    or_(
                        User.username.ilike(search),
                        User.first_name.ilike(search),
                        User.last_name.ilike(search),
                        User.email.ilike(search)
                    )
                )
            
            if filters.get('class_no'):
                query = query.filter(User.class_no == filters['class_no'])
                
            if filters.get('school_id'):
                query = query.filter(User.school_id == filters['school_id'])
                
            if filters.get('province_id'):
                query = query.join(School).join(District).filter(
                    District.province_id == filters['province_id']
                )
        
        return query.order_by(User.date_created.desc())
    
    @staticmethod
    def get_user_progress_stats(user_id):
        """Optimize edilmiş kullanıcı istatistikleri"""
        today = datetime.utcnow().date()
        week_ago = datetime.utcnow() - timedelta(days=7)
        month_ago = datetime.utcnow() - timedelta(days=30)
        
        # Tek sorguda tüm istatistikleri al
        stats = db.session.query(
            func.coalesce(func.sum(UserProgress.puan), 0).label('total_points'),
            func.coalesce(func.sum(
                case(
                    (func.date(UserProgress.tarih) == today, UserProgress.puan),
                    else_=0
                )
            ), 0).label('daily_points'),
            func.coalesce(func.sum(
                case(
                    (UserProgress.tarih >= week_ago, UserProgress.puan),
                    else_=0
                )
            ), 0).label('weekly_points'),
            func.coalesce(func.sum(
                case(
                    (UserProgress.tarih >= month_ago, UserProgress.puan),
                    else_=0
                )
            ), 0).label('monthly_points'),
            func.count(UserProgress.id).label('total_activities')
        ).filter(
            UserProgress.user_id == user_id,
            UserProgress.puan.isnot(None)
        ).first()
        
        return {
            'total_points': int(stats.total_points or 0),
            'daily_points': int(stats.daily_points or 0),
            'weekly_points': int(stats.weekly_points or 0),
            'monthly_points': int(stats.monthly_points or 0),
            'total_activities': int(stats.total_activities or 0)
        }
    
    @staticmethod
    def get_recent_activities(user_id, limit=10):
        """Son aktiviteler optimize edilmiş"""
        return db.session.query(UserProgress).options(
            joinedload(UserProgress.icerik).options(
                joinedload(Icerik.unite).options(
                    joinedload(Unite.ders).options(
                        joinedload(Ders.sinif)
                    )
                )
            ),
            joinedload(UserProgress.soru).options(
                joinedload(Soru.icerik).options(
                    joinedload(Icerik.unite).options(
                        joinedload(Unite.ders).options(
                            joinedload(Ders.sinif)
                        )
                    )
                )
            )
        ).filter(
            UserProgress.user_id == user_id
        ).order_by(UserProgress.tarih.desc()).limit(limit)
    
    @staticmethod
    def get_messages_optimized(user_id, limit=50, unread_only=False):
        """Optimize edilmiş mesaj listesi"""
        query = db.session.query(Message).options(
            joinedload(Message.sender).load_only(
                User.id, User.username, User.first_name, User.last_name
            )
        ).filter(
            Message.receiver_id == user_id,
            Message.is_deleted == False
        )
        
        if unread_only:
            query = query.filter(Message.read_at.is_(None))
        
        return query.order_by(Message.sent_at.desc()).limit(limit)
    
    @staticmethod
    def get_user_wrong_questions(user_id, limit=10):
        """Yanlış çözülen sorular optimize edilmiş"""
        return db.session.query(UserProgress).options(
            joinedload(UserProgress.soru).options(
                joinedload(Soru.icerik).options(
                    joinedload(Icerik.unite).options(
                        joinedload(Unite.ders).options(
                            joinedload(Ders.sinif)
                        )
                    )
                )
            )
        ).filter(
            UserProgress.user_id == user_id,
            UserProgress.yanlis_sayisi > 0,
            UserProgress.soru_id.isnot(None)
        ).order_by(UserProgress.tarih.desc()).limit(limit)
    
    @staticmethod
    def get_leaderboard_raw_sql(time_period='weekly', class_filter=None, limit=100):
        """Raw SQL ile optimize edilmiş leaderboard"""
        
        # Time period için date filter - PostgreSQL uyumlu
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
        
        # ✅ DÜZELTME: PostgreSQL uyumlu tablo isimleri
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