from datetime import datetime, timedelta
from sqlalchemy import func, distinct, extract, case, and_, text
from SF.models import UserProgress, Icerik, Unite, Ders, Soru, ActivityType
from SF import db

class StatisticsService:
    def __init__(self, user_id):
        self.user_id = user_id
        self.today = datetime.utcnow().date()

    def get_time_based_stats(self):
        """Ana İstatistik Metodu - Zaman Bazlı İstatistikler ve Genel İstatistikler"""
        try:
            today = datetime.utcnow().date()
            week_ago = today - timedelta(days=7)
            month_ago = today - timedelta(days=30)

            # ✅ DÜZELTİLDİ: Soru sayısı hesaplaması - SUM kullanarak toplam soru sayısını al
            # Her kayıtta birden fazla soru olabilir (test sonuçları), bu yüzden COUNT yerine SUM kullanıyoruz
            user_stats = db.session.query(
                # Günlük çözülen soru sayısı (doğru + yanlış + boş)
                func.sum(case((func.date(UserProgress.tarih) == today, 
                              UserProgress.dogru_sayisi + UserProgress.yanlis_sayisi + UserProgress.bos_sayisi), 
                              else_=0)).label('daily'),
                # Haftalık çözülen soru sayısı
                func.sum(case((func.date(UserProgress.tarih) >= week_ago, 
                              UserProgress.dogru_sayisi + UserProgress.yanlis_sayisi + UserProgress.bos_sayisi), 
                              else_=0)).label('weekly'),
                # Aylık çözülen soru sayısı
                func.sum(case((func.date(UserProgress.tarih) >= month_ago, 
                              UserProgress.dogru_sayisi + UserProgress.yanlis_sayisi + UserProgress.bos_sayisi), 
                              else_=0)).label('monthly'),
                # Toplam çözülen soru sayısı
                func.sum(UserProgress.dogru_sayisi + UserProgress.yanlis_sayisi + UserProgress.bos_sayisi).label('all_time_total'),
                func.sum(UserProgress.dogru_sayisi).label('correct_count'),
                func.sum(UserProgress.yanlis_sayisi).label('wrong_count')
            ).filter(
                UserProgress.user_id == self.user_id,
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            ).first()

            # Başarı oranı hesaplama
            total_attempts = (user_stats.correct_count or 0) + (user_stats.wrong_count or 0)
            success_rate = (user_stats.correct_count / total_attempts * 100) if total_attempts > 0 else 0

            # Sıralama hesaplama
            all_users = db.session.query(
                UserProgress.user_id,
                func.sum(UserProgress.dogru_sayisi).label('user_correct'),
                func.sum(UserProgress.yanlis_sayisi).label('user_wrong')
            ).filter(
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            ).group_by(
                UserProgress.user_id
            ).having(
                func.sum(UserProgress.dogru_sayisi + UserProgress.yanlis_sayisi) > 0
            ).all()

            # Kullanıcıları başarı oranına göre sırala
            user_rates = []
            for user in all_users:
                total = (user.user_correct or 0) + (user.user_wrong or 0)
                if total > 0:
                    rate = (user.user_correct or 0) / total * 100
                    user_rates.append({'user_id': user.user_id, 'rate': rate})

            user_rates.sort(key=lambda x: x['rate'], reverse=True)
            user_position = next((i + 1 for i, user in enumerate(user_rates) 
                                if user['user_id'] == self.user_id), len(user_rates))
            
            percentile = (user_position / len(user_rates) * 100) if user_rates else 100
            streak = self._get_streak_days()
            
            # ✅ SORU ÇÖZME SÜRELERİ - DÜZELTİLMİŞ
            question_time_data = db.session.query(
                func.sum(UserProgress.harcanan_sure).label('total_time'),
                func.sum(case(
                    (func.date(UserProgress.tarih) == today, UserProgress.harcanan_sure),
                    else_=0
                )).label('daily_time'),
                func.sum(case(
                    (func.date(UserProgress.tarih) >= week_ago, UserProgress.harcanan_sure),
                    else_=0
                )).label('weekly_time'),
                func.sum(case(
                    (func.date(UserProgress.tarih) >= month_ago, UserProgress.harcanan_sure),
                    else_=0
                )).label('monthly_time')
            ).filter(
                UserProgress.user_id == self.user_id,
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING,
                UserProgress.harcanan_sure.isnot(None)
            ).first()

            # ✅ İÇERİK OKUMA SÜRELERİ - DÜZELTİLMİŞ  
            content_time_data = db.session.query(
                func.sum(UserProgress.harcanan_sure).label('total_time'),
                func.sum(case(
                    (func.date(UserProgress.tarih) == today, UserProgress.harcanan_sure),
                    else_=0
                )).label('daily_time'),
                func.sum(case(
                    (func.date(UserProgress.tarih) >= week_ago, UserProgress.harcanan_sure),
                    else_=0
                )).label('weekly_time'),
                func.sum(case(
                    (func.date(UserProgress.tarih) >= month_ago, UserProgress.harcanan_sure),
                    else_=0
                )).label('monthly_time')
            ).filter(
                UserProgress.user_id == self.user_id,
                UserProgress.activity_type == ActivityType.CONTENT_READING,
                UserProgress.harcanan_sure.isnot(None)
            ).first()

            # ✅ SÜRE VERİLERİNİ GÜVENLİ ŞEKİLDE AL
            # Soru çözme süreleri (saniye -> dakika)
            question_total_minutes = int((question_time_data.total_time or 0) / 60)
            question_daily_minutes = int((question_time_data.daily_time or 0) / 60)
            question_weekly_minutes = int((question_time_data.weekly_time or 0) / 60)
            question_monthly_minutes = int((question_time_data.monthly_time or 0) / 60)

            # İçerik okuma süreleri (saniye -> dakika)
            content_total_minutes = int((content_time_data.total_time or 0) / 60)
            content_daily_minutes = int((content_time_data.daily_time or 0) / 60)
            content_weekly_minutes = int((content_time_data.weekly_time or 0) / 60)
            content_monthly_minutes = int((content_time_data.monthly_time or 0) / 60)

            # Toplam süreler
            total_minutes = question_total_minutes + content_total_minutes
            daily_minutes = question_daily_minutes + content_daily_minutes
            weekly_minutes = question_weekly_minutes + content_weekly_minutes
            monthly_minutes = question_monthly_minutes + content_monthly_minutes

            # Yüzdelik hesaplama
            content_percentage = round((content_total_minutes / total_minutes * 100), 1) if total_minutes > 0 else 0
            question_percentage = round((question_total_minutes / total_minutes * 100), 1) if total_minutes > 0 else 0

            # ✅ Çalışma günleri sayısı
            study_days_count = db.session.query(
                func.count(func.distinct(func.date(UserProgress.tarih)))
            ).filter(
                UserProgress.user_id == self.user_id,
                UserProgress.harcanan_sure.isnot(None),
                UserProgress.harcanan_sure > 0
            ).scalar() or 0

            # ✅ RETURN İFADESİ - EKSIKSIZ
            return {
                'daily_solved': user_stats.daily or 0,
                'weekly_solved': user_stats.weekly or 0,
                'monthly_solved': user_stats.monthly or 0,
                'all_time_solved': user_stats.all_time_total or 0,
                'streak_days': streak,
                'success_rate': round(success_rate, 1),
                'percentile': round(percentile, 1),
                'rank': user_position,
                'total_users': len(user_rates),
                
                # ✅ TOPLAM SÜRELER
                'total_time': {
                    'hours': total_minutes // 60,
                    'minutes': total_minutes % 60
                },
                'daily_time': {
                    'hours': daily_minutes // 60, 
                    'minutes': daily_minutes % 60
                },
                'weekly_time': {
                    'hours': weekly_minutes // 60,
                    'minutes': weekly_minutes % 60
                },
                'monthly_time': {
                    'hours': monthly_minutes // 60,
                    'minutes': monthly_minutes % 60
                },
                
                # ✅ AKTİVİTE TÜRÜ AYRINTILARI
                'content_reading_time': {
                    'hours': content_total_minutes // 60,
                    'minutes': content_total_minutes % 60
                },
                'question_solving_time': {
                    'hours': question_total_minutes // 60,
                    'minutes': question_total_minutes % 60,
                    'seconds': int(question_time_data.total_time or 0) % 60  # Saniye değerini ekle
                },
                'content_reading_percentage': content_percentage,
                'question_solving_percentage': question_percentage,
                
                # ✅ EK İSTATİSTİKLER
                'average_session_time': round(total_minutes / study_days_count) if study_days_count > 0 else 0,
                'study_days': study_days_count,
                
                # ✅ DETAYLI SÜRELER (İSTEĞE BAĞLI)
                'question_total_time': {
                    'hours': question_total_minutes // 60,
                    'minutes': question_total_minutes % 60
                },
                'question_daily_time': {
                    'hours': question_daily_minutes // 60,
                    'minutes': question_daily_minutes % 60
                },
                'question_weekly_time': {
                    'hours': question_weekly_minutes // 60,
                    'minutes': question_weekly_minutes % 60
                },
                'question_monthly_time': {
                    'hours': question_monthly_minutes // 60,
                    'minutes': question_monthly_minutes % 60
                },
                'content_total_time': {
                    'hours': content_total_minutes // 60,
                    'minutes': content_total_minutes % 60
                },
                'content_daily_time': {
                    'hours': content_daily_minutes // 60,
                    'minutes': content_daily_minutes % 60
                },
                'content_weekly_time': {
                    'hours': content_weekly_minutes // 60,
                    'minutes': content_weekly_minutes % 60
                },
                'content_monthly_time': {
                    'hours': content_monthly_minutes // 60,
                    'minutes': content_monthly_minutes % 60
                }
            }
            
        except Exception as e:
            print(f"İstatistik hesaplama hatası: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def get_performance_stats(self):
        """Performans İstatistikleri - Ders bazında başarı oranları"""
        try:
            last_30_days = self.today - timedelta(days=30)
            
            performance_by_subject = db.session.query(
                Ders.ders_adi,
                func.count(UserProgress.id).label('total_questions'),
                func.sum(UserProgress.dogru_sayisi).label('correct_count'),
                func.avg(UserProgress.puan).label('avg_score'),
                (func.sum(UserProgress.dogru_sayisi) * 100.0 / 
                 func.count(UserProgress.id)).label('success_rate')
            ).join(
                Icerik, UserProgress.icerik_id == Icerik.id
            ).join(
                Unite, Icerik.unite_id == Unite.id
            ).join(
                Ders, Unite.ders_id == Ders.id
            ).filter(
                UserProgress.user_id == self.user_id,
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING,
                UserProgress.soru_id.isnot(None),
                func.date(UserProgress.tarih) >= last_30_days
            ).group_by(
                Ders.id, Ders.ders_adi
            ).order_by(
                text('success_rate DESC')
            ).all()
            
            return {
                'subject_performance': [
                    {
                        'subject': row.ders_adi,
                        'total_questions': row.total_questions,
                        'success_rate': int(row.success_rate or 0),
                        'avg_score': round(row.avg_score or 0, 1)
                    }
                    for row in performance_by_subject
                ]
            }
            
        except Exception as e:
            print(f"Performans istatistiği hatası: {str(e)}")
            return {'subject_performance': []}

    def get_course_stats(self):
        """Ders Bazında İstatistikler - En çok çalışılan dersler"""
        try:
            most_studied = db.session.query(
                Ders.ders_adi,
                func.sum(UserProgress.harcanan_sure).label('total_time'),
                func.count(distinct(UserProgress.icerik_id)).label('content_count')
            ).join(
                Icerik, UserProgress.icerik_id == Icerik.id
            ).join(
                Unite, Icerik.unite_id == Unite.id
            ).join(
                Ders, Unite.ders_id == Ders.id
            ).filter(
                UserProgress.user_id == self.user_id,
                UserProgress.activity_type == ActivityType.CONTENT_READING,
                UserProgress.harcanan_sure.isnot(None)
            ).group_by(
                Ders.id, Ders.ders_adi
            ).order_by(
                text('total_time DESC')
            ).limit(5).all()
            
            return {
                'most_studied_subjects': [
                    {
                        'subject': row.ders_adi,
                        'total_time_minutes': int((row.total_time or 0) / 60),
                        'content_count': row.content_count
                    }
                    for row in most_studied
                ]
            }
            
        except Exception as e:
            print(f"Ders istatistikleri hatası: {str(e)}")
            return {'most_studied_subjects': []}

    def _get_streak_days(self):
        """Aralıksız giriş yapılan gün sayısı"""
        try:
            days_query = db.session.query(
                func.date(UserProgress.tarih)
            ).filter(
                UserProgress.user_id == self.user_id,
                UserProgress.tarih.isnot(None)
            ).distinct().order_by(
                func.date(UserProgress.tarih)
            ).all()

            if not days_query:
                return 0

            dates = [day[0] for day in days_query if day[0] is not None]
            
            if not dates:
                return 0
                
            today = datetime.utcnow().date()
            
            if dates[-1] != today:
                return 0
                
            streak = 1
            
            for i in range(len(dates)-1, 0, -1):
                if (dates[i] - dates[i-1]).days == 1:
                    streak += 1
                else:
                    break
                    
            return streak
                
        except Exception as e:
            print(f"Streak hesaplama hatası: {str(e)}")
            return 0