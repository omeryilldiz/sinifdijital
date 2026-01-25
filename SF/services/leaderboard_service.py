from datetime import datetime, timedelta
from sqlalchemy import func, desc
from SF.models import db, User, UserProgress, Soru, Icerik, Unite, Ders, Sinif, School, District, ActivityType
from flask import current_app

class LeaderboardService:
    def __init__(self):
        self.current_time = datetime.utcnow()
    
    def get_student_leaderboard_data(self, student_id):
        """Öğrenci için tüm leaderboard verilerini al"""
        try:
            student = User.query.get(student_id)
            if not student:
                current_app.logger.error(f"❌ Student {student_id} not found")
                return self._empty_leaderboard()
            
            user_info = self._get_user_competition_info(student)
            
            return {
                'daily': self._get_daily_leaderboard(student),
                'weekly': self._get_weekly_leaderboard(student),
                'monthly': self._get_monthly_leaderboard(student),
                'all_time': self._get_alltime_leaderboard(student),
                'user_info': user_info
            }
        except Exception as e:
            current_app.logger.error(f"❌ Leaderboard service error: {str(e)}")
            return self._empty_leaderboard()

    def _empty_scope(self):
        return {'my_rank': None, 'my_points': 0, 'top_students': []}

    def _empty_leaderboard(self):
        return {
            'general': self._empty_scope(),
            'province': self._empty_scope(),
            'school': self._empty_scope(),
            'class': self._empty_scope()
        }

    def _get_daily_leaderboard(self, student):
        try:
            today = self.current_time.date()
            daily_stats = db.session.query(
                User.id, User.username,
                func.sum(UserProgress.puan).label('total_points'),
                func.count(UserProgress.id).label('total_questions')
            ).join(UserProgress, User.id == UserProgress.user_id).filter(
                func.date(UserProgress.tarih) == today,
                User.role == 'user',
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            ).group_by(User.id, User.username).order_by(desc('total_points')).limit(50).all()
            
            if not daily_stats:
                return self._empty_leaderboard()
            
            return {
                'general': self._format_general_leaderboard(daily_stats, student, today, 'daily'),
                'province': self._get_province_ranking(student, today, 'daily'),
                'school': self._get_school_ranking(student, today, 'daily'),
                'class': self._get_class_ranking(student, today, 'daily')
            }
        except Exception as e:
            current_app.logger.error(f"Daily leaderboard error: {str(e)}")
            return self._empty_leaderboard()

    def _get_weekly_leaderboard(self, student):
        try:
            today = self.current_time.date()
            week_start = today - timedelta(days=today.weekday())
            weekly_stats = db.session.query(
                User.id,
                User.username,
                func.sum(UserProgress.puan).label('total_points'),
                func.count(UserProgress.id).label('total_questions')
            ).join(
                UserProgress, User.id == UserProgress.user_id
            ).filter(
                func.date(UserProgress.tarih) >= week_start,
                func.date(UserProgress.tarih) <= today,
                User.role == 'user',
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            ).group_by(
                User.id, User.username
            ).order_by(
                desc('total_points')
            ).limit(50).all()
            
            if not weekly_stats:
                return self._empty_leaderboard()
            
            return {
                'general': self._format_general_leaderboard(weekly_stats, student, week_start, 'weekly'),
                'province': self._get_province_ranking(student, week_start, 'weekly'),
                'school': self._get_school_ranking(student, week_start, 'weekly'),
                'class': self._get_class_ranking(student, week_start, 'weekly')
            }
        except Exception as e:
            current_app.logger.error(f"Weekly leaderboard error: {str(e)}")
            return self._empty_leaderboard()

    def _get_monthly_leaderboard(self, student):
        try:
            today = self.current_time.date()
            month_start = today.replace(day=1)
            monthly_stats = db.session.query(
                User.id,
                User.username,
                func.sum(UserProgress.puan).label('total_points'),
                func.count(UserProgress.id).label('total_questions')
            ).join(
                UserProgress, User.id == UserProgress.user_id
            ).filter(
                func.date(UserProgress.tarih) >= month_start,
                func.date(UserProgress.tarih) <= today,
                User.role == 'user',
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            ).group_by(
                User.id, User.username
            ).order_by(
                desc('total_points')
            ).limit(100).all()
            
            if not monthly_stats:
                return self._empty_leaderboard()
            
            return {
                'general': self._format_general_leaderboard(monthly_stats, student, month_start, 'monthly'),
                'province': self._get_province_ranking(student, month_start, 'monthly'),
                'school': self._get_school_ranking(student, month_start, 'monthly'),
                'class': self._get_class_ranking(student, month_start, 'monthly')
            }
        except Exception as e:
            current_app.logger.error(f"Monthly leaderboard error: {str(e)}")
            return self._empty_leaderboard()

    def _get_alltime_leaderboard(self, student):
        try:
            alltime_stats = db.session.query(
                User.id,
                User.username,
                func.sum(UserProgress.puan).label('total_points'),
                func.count(UserProgress.id).label('total_questions')
            ).join(
                UserProgress, User.id == UserProgress.user_id
            ).filter(
                User.role == 'user',
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            ).group_by(
                User.id, User.username
            ).order_by(
                desc('total_points')
            ).limit(100).all()
            
            if not alltime_stats:
                return self._empty_leaderboard()
            
            return {
                'general': self._format_general_leaderboard(alltime_stats, student, None, 'alltime'),
                'province': self._get_province_ranking(student, None, 'alltime'),
                'school': self._get_school_ranking(student, None, 'alltime'),
                'class': self._get_class_ranking(student, None, 'alltime')
            }
        except Exception as e:
            current_app.logger.error(f"All-time leaderboard error: {str(e)}")
            return self._empty_leaderboard()
    
    def _format_general_leaderboard(self, stats, student, date_filter, period):
        try:
            top_students = []
            student_rank = None
            student_points = 0
            
            # ✅ OPTIMIZED: Fetch all user IDs and get users in single batch query
            user_ids = [stat.id for stat in stats]
            if user_ids:
                # Single batch query with eager loading
                users_batch = db.session.query(User).filter(User.id.in_(user_ids)).all()
                users_dict = {u.id: u for u in users_batch}
            else:
                users_dict = {}
            
            for rank, stat in enumerate(stats, 1):
                user_data = {
                    'user_id': stat.id,
                    'username': stat.username,
                    'points': int(stat.total_points or 0),
                    'school_name': 'Okul Bilgisi Yok',
                    'class_info': '?'
                }
                # Use batch-fetched user instead of individual query
                user = users_dict.get(stat.id)
                if user:
                    if user.school:
                        user_data['school_name'] = user.school.name
                    if user.class_no:
                        user_data['class_info'] = str(user.class_no)
                top_students.append(user_data)
                if stat.id == student.id:
                    student_rank = rank
                    student_points = int(stat.total_points or 0)
            if student_rank is None:
                student_points = self._get_student_points(student, date_filter, period)
                student_rank = self._calculate_student_rank(student, date_filter, period, student_points)
            return {
                'my_rank': student_rank or 999,
                'my_points': student_points,
                'top_students': top_students
            }
        except Exception as e:
            current_app.logger.error(f"Format general leaderboard error: {str(e)}")
            return self._empty_scope()
    
    def _get_student_points(self, student, date_filter, period):
        try:
            query = db.session.query(
                func.sum(UserProgress.puan).label('points')
            ).filter(
                UserProgress.user_id == student.id,
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            )
            if period == 'daily' and date_filter:
                query = query.filter(func.date(UserProgress.tarih) == date_filter)
            elif period == 'weekly' and date_filter:
                today = self.current_time.date()
                query = query.filter(
                    func.date(UserProgress.tarih) >= date_filter,
                    func.date(UserProgress.tarih) <= today
                )
            elif period == 'monthly' and date_filter:
                today = self.current_time.date()
                query = query.filter(
                    func.date(UserProgress.tarih) >= date_filter,
                    func.date(UserProgress.tarih) <= today
                )
            result = query.first()
            return int(result.points or 0) if result else 0
        except Exception as e:
            current_app.logger.error(f"Get student points error: {str(e)}")
            return 0
    
    def _calculate_student_rank(self, student, date_filter, period, student_points):
        try:
            subquery = db.session.query(
                UserProgress.user_id,
                func.sum(UserProgress.puan).label('user_total')
            ).filter(
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            )
            if period == 'daily' and date_filter:
                subquery = subquery.filter(func.date(UserProgress.tarih) == date_filter)
            elif period == 'weekly' and date_filter:
                today = self.current_time.date()
                subquery = subquery.filter(
                    func.date(UserProgress.tarih) >= date_filter,
                    func.date(UserProgress.tarih) <= today
                )
            elif period == 'monthly' and date_filter:
                today = self.current_time.date()
                subquery = subquery.filter(
                    func.date(UserProgress.tarih) >= date_filter,
                    func.date(UserProgress.tarih) <= today
                )
            subquery = subquery.group_by(UserProgress.user_id).subquery()
            better_count = db.session.query(
                func.count(subquery.c.user_id)
            ).join(
                User, User.id == subquery.c.user_id
            ).filter(
                User.role == 'user',
                User.id != student.id,
                subquery.c.user_total > student_points
            ).scalar()
            return (better_count or 0) + 1
        except Exception as e:
            current_app.logger.error(f"Calculate student rank error: {str(e)}")
            return 999
    
    def _get_province_ranking(self, student, date_filter, period):
        if not student.school or not student.school.district or not student.school.district.province_id:
            current_app.logger.warning(f"No province info for student {student.id}")
            return self._empty_scope()
        try:
            province_id = student.school.district.province_id
            query = db.session.query(
                User.id,
                User.username,
                func.sum(UserProgress.puan).label('total_points')
            ).join(
                UserProgress, User.id == UserProgress.user_id
            ).join(
                School, User.school_id == School.id
            ).join(
                District, School.district_id == District.id
            ).filter(
                District.province_id == province_id,
                User.role == 'user',
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            )
            if period == 'daily' and date_filter:
                query = query.filter(func.date(UserProgress.tarih) == date_filter)
            elif period == 'weekly' and date_filter:
                today = self.current_time.date()
                query = query.filter(
                    func.date(UserProgress.tarih) >= date_filter,
                    func.date(UserProgress.tarih) <= today
                )
            elif period == 'monthly' and date_filter:
                today = self.current_time.date()
                query = query.filter(
                    func.date(UserProgress.tarih) >= date_filter,
                    func.date(UserProgress.tarih) <= today
                )
            province_stats = query.group_by(
                User.id, User.username
            ).order_by(
                desc('total_points')
            ).limit(20).all()
            if not province_stats:
                return self._empty_scope()
            return self._format_scope_leaderboard(province_stats, student, 'province')
        except Exception as e:
            current_app.logger.error(f"Province ranking error: {str(e)}")
            return self._empty_scope()

    def _get_school_ranking(self, student, date_filter, period):
        if not student.school:
            current_app.logger.warning(f"No school info for student {student.id}")
            return self._empty_scope()
        try:
            query = db.session.query(
                User.id,
                User.username,
                func.sum(UserProgress.puan).label('total_points')
            ).join(
                UserProgress, User.id == UserProgress.user_id
            ).filter(
                User.school_id == student.school_id,
                User.role == 'user',
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            )
            if period == 'daily' and date_filter:
                query = query.filter(func.date(UserProgress.tarih) == date_filter)
            elif period == 'weekly' and date_filter:
                today = self.current_time.date()
                query = query.filter(
                    func.date(UserProgress.tarih) >= date_filter,
                    func.date(UserProgress.tarih) <= today
                )
            elif period == 'monthly' and date_filter:
                today = self.current_time.date()
                query = query.filter(
                    func.date(UserProgress.tarih) >= date_filter,
                    func.date(UserProgress.tarih) <= today
                )
            school_stats = query.group_by(
                User.id, User.username
            ).order_by(
                desc('total_points')
            ).limit(20).all()
            if not school_stats:
                return self._empty_scope()
            return self._format_scope_leaderboard(school_stats, student, 'school')
        except Exception as e:
            current_app.logger.error(f"School ranking error: {str(e)}")
            return self._empty_scope()

    def _get_class_ranking(self, student, date_filter, period):
        if not student.class_no:
            current_app.logger.warning(f"No class info for student {student.id}")
            return self._empty_scope()
        try:
            query = db.session.query(
                User.id,
                User.username,
                func.sum(UserProgress.puan).label('total_points')
            ).join(
                UserProgress, User.id == UserProgress.user_id
            ).filter(
                User.class_no == student.class_no,
                User.role == 'user',
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            )
            if period == 'daily' and date_filter:
                query = query.filter(func.date(UserProgress.tarih) == date_filter)
            elif period == 'weekly' and date_filter:
                today = self.current_time.date()
                query = query.filter(
                    func.date(UserProgress.tarih) >= date_filter,
                    func.date(UserProgress.tarih) <= today
                )
            elif period == 'monthly' and date_filter:
                today = self.current_time.date()
                query = query.filter(
                    func.date(UserProgress.tarih) >= date_filter,
                    func.date(UserProgress.tarih) <= today
                )
            class_stats = query.group_by(
                User.id, User.username
            ).order_by(
                desc('total_points')
            ).all()
            if not class_stats:
                return self._empty_scope()
            return self._format_scope_leaderboard(class_stats, student, 'class')
        except Exception as e:
            current_app.logger.error(f"Class ranking error: {str(e)}")
            return self._empty_scope()

    def _format_scope_leaderboard(self, stats, student, scope_type):
        try:
            top_students = []
            student_rank = None
            student_points = 0
            
            # ✅ OPTIMIZED: Batch fetch all users
            user_ids = [stat.id for stat in stats]
            if user_ids:
                users_batch = db.session.query(User).filter(User.id.in_(user_ids)).all()
                users_dict = {u.id: u for u in users_batch}
            else:
                users_dict = {}
            
            for rank, stat in enumerate(stats, 1):
                user_data = {
                    'user_id': stat.id,
                    'username': stat.username,
                    'points': int(stat.total_points or 0),
                    'school_name': 'Okul Bilgisi Yok',
                    'class_info': '?'
                }
                user = users_dict.get(stat.id)
                if user:
                    if user.school:
                        user_data['school_name'] = user.school.name
                    if user.class_no:
                        user_data['class_info'] = str(user.class_no)
                top_students.append(user_data)
                if stat.id == student.id:
                    student_rank = rank
                    student_points = int(stat.total_points or 0)
            if student_rank is None:
                student_rank = len(stats) + 1
                student_points = 0
            return {
                'my_rank': student_rank,
                'my_points': student_points,
                'top_students': top_students
            }
        except Exception as e:
            current_app.logger.error(f"Format {scope_type} leaderboard error: {str(e)}")
            return self._empty_scope()

    def _get_user_competition_info(self, student):
        return {
            'school_name': student.school.name if student.school else 'Belirtilmemiş',
            'district_name': student.school.district.name if student.school and student.school.district else 'Belirtilmemiş',
            'province_name': student.school.district.province.name if student.school and student.school.district and student.school.district.province else 'Belirtilmemiş',
            'class_no': student.class_no if student.class_no else 'Belirtilmemiş',
            'competition_group_name': (
                f"{student.class_no}. Sınıf Grubu" if student.class_no else
                student.school.name if student.school else
                'Standart Grup'
            )
        }