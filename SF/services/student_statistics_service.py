from datetime import datetime, timedelta
from sqlalchemy import func, case, distinct, and_, cast, String
from flask import current_app
from SF.models import User, UserProgress, Icerik, Unite, Ders, Soru, ActivityType, Sinif
from SF import db

class StudentStatisticsService:
    def __init__(self, student_id):
        self.student_id = student_id
        self.student = User.query.get(student_id)
        
    def get_comprehensive_stats(self):
        """Öğrenci için kapsamlı istatistikleri getir"""
        try:
            return {
                'subject_completion_stats': self.get_subject_completion_stats(),
                'question_analytics': self.get_question_analytics(),
                'performance_trends': self.get_performance_trends(),
                'time_analytics': self.get_time_analytics(),
                'risk_analysis': self.get_risk_analysis(),
                'achievement_summary': self.get_achievement_summary()
            }
        except Exception as e:
            current_app.logger.error(f"Comprehensive stats error: {str(e)}", exc_info=True)
            return self._get_empty_stats()
    
    def get_subject_completion_stats(self):
        """2. KONU TAMAMLAMA İSTATİSTİKLERİ"""
        try:
            if not self.student.class_no:
                return {'subjects': [], 'overall_completion': 0}
            
            current_app.logger.debug(f"Student class_no: {self.student.class_no} (type: {type(self.student.class_no)})")
            
            # ✅ VERİTABANI KONTROLÜ: Tüm sınıfları listele
            all_siniflar = Sinif.query.all()
            current_app.logger.debug("Veritabanındaki tüm sınıflar:")
            for sinif in all_siniflar:
                current_app.logger.debug(f"  ID: {sinif.id}, Sınıf: '{sinif.sinif}' (type: {type(sinif.sinif)})")
            
            # ✅ ESNEK SINIF BULMA: Birden fazla yöntem dene
            matching_sinif = None
            
            # Yöntem 1: Tam eşleştirme
            for sinif in all_siniflar:
                if str(sinif.sinif).strip() == str(self.student.class_no).strip():
                    matching_sinif = sinif
                    current_app.logger.debug(f"Tam eşleştirme bulundu: {sinif.id} - {sinif.sinif}")
                    break
            
            # Yöntem 2: Kısmi eşleştirme (örn: "5. Sınıf" vs "5")
            if not matching_sinif:
                for sinif in all_siniflar:
                    if str(self.student.class_no) in str(sinif.sinif):
                        matching_sinif = sinif
                        current_app.logger.debug(f"Kısmi eşleştirme bulundu: {sinif.id} - {sinif.sinif}")
                        break
            
            # Yöntem 3: Sadece rakam karşılaştırması
            if not matching_sinif:
                import re
                student_number = re.findall(r'\d+', str(self.student.class_no))
                if student_number:
                    student_class_num = student_number[0]
                    for sinif in all_siniflar:
                        sinif_numbers = re.findall(r'\d+', str(sinif.sinif))
                        if sinif_numbers and sinif_numbers[0] == student_class_num:
                            matching_sinif = sinif
                            current_app.logger.debug(f"Rakam eşleştirmesi bulundu: {sinif.id} - {sinif.sinif}")
                            break
            
            if not matching_sinif:
                current_app.logger.warning(f"No matching sinif found for class_no: {self.student.class_no}")
                current_app.logger.debug(f"Available sinif values: {[s.sinif for s in all_siniflar]}")
                
                # ✅ DEMO VERİSİ: Eğer sınıf bulunamazsa ilk sınıfı kullan (test için)
                if all_siniflar:
                    matching_sinif = all_siniflar[0]
                    current_app.logger.warning(f"DEMO: Using first available sinif: {matching_sinif.sinif}")
                else:
                    return {'subjects': [], 'overall_completion': 0}
            
            current_app.logger.debug(f"Final matching sinif: {matching_sinif.id} - {matching_sinif.sinif}")
            
            # Sınıfa ait dersleri al
            class_subjects = Ders.query.filter_by(sinif_id=matching_sinif.id).all()
            current_app.logger.debug(f"Found {len(class_subjects)} subjects for sinif_id: {matching_sinif.id}")
            
            # Eğer ders bulunamazsa boş dersleri göster
            if not class_subjects:
                current_app.logger.warning(f"No subjects found for sinif_id: {matching_sinif.id}")
                return {
                    'subjects': [{
                        'id': 0,
                        'name': 'Henüz Ders Eklenmemiş',
                        'completion_percent': 0,
                        'completed_contents': 0,
                        'total_contents': 0,
                        'units': [],
                        'color_class': 'secondary'
                    }],
                    'overall_completion': 0
                }
            
            subject_stats = []
            total_completion = 0
            
            for subject in class_subjects:
                current_app.logger.debug(f"Processing subject: {subject.ders_adi}")
                
                # Bu dersteki toplam içerik sayısı
                total_contents = db.session.query(func.count(Icerik.id)).join(
                    Unite, Icerik.unite_id == Unite.id
                ).filter(Unite.ders_id == subject.id).scalar() or 0
                
                current_app.logger.debug(f"Total contents in {subject.ders_adi}: {total_contents}")
                
                # Öğrencinin tamamladığı içerik sayısı
                completed_contents = db.session.query(func.count(UserProgress.id)).join(
                    Icerik, UserProgress.icerik_id == Icerik.id
                ).join(
                    Unite, Icerik.unite_id == Unite.id
                ).filter(
                    UserProgress.user_id == self.student_id,
                    UserProgress.okundu == True,
                    Unite.ders_id == subject.id
                ).scalar() or 0
                
                current_app.logger.debug(f"Completed contents in {subject.ders_adi}: {completed_contents}")
                
                completion_percent = int((completed_contents / total_contents * 100) if total_contents > 0 else 0)
                
                # Unite bazında detay
                units = self._get_unit_details(subject.id)
                
                subject_stats.append({
                    'id': subject.id,
                    'name': subject.ders_adi,
                    'completion_percent': completion_percent,
                    'completed_contents': completed_contents,
                    'total_contents': total_contents,
                    'units': units,
                    'color_class': self._get_progress_color(completion_percent)
                })
                
                total_completion += completion_percent
                current_app.logger.debug(f"Subject {subject.ders_adi}: {completion_percent}% completed")
            
            overall_completion = int(total_completion / len(class_subjects)) if class_subjects else 0
            current_app.logger.debug(f"Overall completion: {overall_completion}%")
            
            return {
                'subjects': subject_stats,
                'overall_completion': overall_completion
            }
            
        except Exception as e:
            current_app.logger.warning(f"Subject completion stats error: {str(e)}", exc_info=True)
            return {'subjects': [], 'overall_completion': 0}
    
    def _get_unit_details(self, subject_id):
        """Ders için ünite detaylarını getir"""
        try:
            units = Unite.query.filter_by(ders_id=subject_id).all()
            unit_details = []
            
            for unit in units:
                # Ünitedeki toplam içerik sayısı
                total_contents = Icerik.query.filter_by(unite_id=unit.id).count()
                
                # Tamamlanan içerik sayısı - DİNAMİK
                completed_contents = db.session.query(func.count(UserProgress.id)).join(
                    Icerik, UserProgress.icerik_id == Icerik.id
                ).filter(
                    UserProgress.user_id == self.student_id,
                    UserProgress.okundu == True,
                    Icerik.unite_id == unit.id
                    # activity_type kontrolü kaldırıldı
                ).scalar() or 0
                
                completion_percent = int((completed_contents / total_contents * 100) if total_contents > 0 else 0)
                
                # İçerik detayları
                contents = self._get_content_details(unit.id)
                
                unit_details.append({
                    'id': unit.id,
                    'name': unit.unite,
                    'completion_percent': completion_percent,
                    'completed_contents': completed_contents,
                    'total_contents': total_contents,
                    'contents': contents,
                    'color_class': self._get_progress_color(completion_percent)
                })
            
            return unit_details
            
        except Exception as e:
            current_app.logger.warning(f"Unit details error: {str(e)}", exc_info=True)
            return []
    
    def _get_content_details(self, unit_id):
        """Ünite için içerik detaylarını getir"""
        try:
            contents = Icerik.query.filter_by(unite_id=unit_id).all()
            content_details = []
            
            for content in contents:
                # İçeriğin okunup okunmadığını kontrol et - DİNAMİK
                progress = UserProgress.query.filter_by(
                    user_id=self.student_id,
                    icerik_id=content.id
                ).filter(
                    UserProgress.okundu == True
                ).first()
                
                # Harcanan süre - TÜMÜ
                total_time = db.session.query(func.sum(UserProgress.harcanan_sure)).filter_by(
                    user_id=self.student_id,
                    icerik_id=content.id
                ).scalar() or 0
                
                status = 'completed' if progress else 'not_started'
                if not progress and total_time > 0:
                    status = 'in_progress'
                
                content_details.append({
                    'id': content.id,
                    'name': content.baslik,
                    'status': status,
                    'status_icon': self._get_status_icon(status),
                    'spent_time': self._format_time(total_time),
                    'last_viewed': progress.tarih if progress else None
                })
            
            return content_details
            
        except Exception as e:
            current_app.logger.warning(f"Content details error: {str(e)}", exc_info=True)
            return []
    
    def get_question_analytics(self):
        try:
            if not self.student.class_no:
                return {'subject_stats': [], 'weak_topics': []}

            # Sınıf bulma (mevcut esnek yöntemler)
            all_siniflar = Sinif.query.all()
            matching_sinif = None

            for sinif in all_siniflar:
                if str(sinif.sinif).strip() == str(self.student.class_no).strip():
                    matching_sinif = sinif
                    break
            if not matching_sinif:
                for sinif in all_siniflar:
                    if str(self.student.class_no) in str(sinif.sinif) or str(sinif.sinif) in str(self.student.class_no):
                        matching_sinif = sinif
                        break
            if not matching_sinif:
                import re
                student_numbers = re.findall(r'\d+', str(self.student.class_no))
                if student_numbers:
                    student_class_num = student_numbers[0]
                    for sinif in all_siniflar:
                        sinif_numbers = re.findall(r'\d+', str(sinif.sinif))
                        if sinif_numbers and sinif_numbers[0] == student_class_num:
                            matching_sinif = sinif
                            break
            if not matching_sinif and all_siniflar:
                matching_sinif = all_siniflar[0]

            if not matching_sinif:
                return {
                    'subject_stats': [{
                        'name': 'Sınıf Bulunamadı',
                        'units': [{
                            'name': f'Sınıf {self.student.class_no} bulunamadı',
                            'total_questions': 0,
                            'correct_answers': 0,
                            'wrong_answers': 0,
                            'success_rate': 0,
                            'color_class': 'secondary'
                        }]
                    }],
                    'weak_topics': []
                }

            # Sınıfa ait dersleri al
            class_subjects = Ders.query.filter_by(sinif_id=matching_sinif.id).all()
            if not class_subjects:
                return {
                    'subject_stats': [{
                        'name': f'{matching_sinif.sinif} - Ders Yok',
                        'units': [{
                            'name': 'Henüz ders eklenmemiş',
                            'total_questions': 0,
                            'correct_answers': 0,
                            'wrong_answers': 0,
                            'success_rate': 0,
                            'color_class': 'secondary'
                        }]
                    }],
                    'weak_topics': []
                }

            subject_question_stats = []
            
            # ✅ OPTIMIZED: Single query to get all unit stats for all subjects
            all_units = Unite.query.filter(Unite.ders_id.in_([s.id for s in class_subjects])).all()
            unit_ids = [u.id for u in all_units]
            
            # ✅ Get all user progress for all units in one query
            if unit_ids:
                all_sorular = Soru.query.filter(Soru.unite_id.in_(unit_ids)).all()
                soru_ids = [s.id for s in all_sorular]
                
                # ✅ Single batch query for user progress
                all_progress = db.session.query(
                    UserProgress.soru_id,
                    func.sum(UserProgress.dogru_sayisi).label('dogru'),
                    func.sum(UserProgress.yanlis_sayisi).label('yanlis')
                ).filter(
                    UserProgress.user_id == self.student_id,
                    UserProgress.soru_id.in_(soru_ids),
                    UserProgress.activity_type == ActivityType.QUESTION_SOLVING
                ).group_by(UserProgress.soru_id).all() if soru_ids else []
                
                # ✅ Convert to dict for O(1) lookup
                progress_dict = {p.soru_id: {'dogru': p.dogru or 0, 'yanlis': p.yanlis or 0} for p in all_progress}
            else:
                progress_dict = {}

            for subject in class_subjects:
                units_stats = []
                units = [u for u in all_units if u.ders_id == subject.id]

                for unit in units:
                    # --- OPTIMIZED: Use pre-fetched progress dictionary ---
                    sorular = [s for s in all_sorular if s.unite_id == unit.id] if unit_ids else []
                    dogru = yanlis = 0
                    for soru in sorular:
                        if soru.id in progress_dict:
                            dogru += progress_dict[soru.id]['dogru']
                            yanlis += progress_dict[soru.id]['yanlis']
                    
                    toplam = dogru + yanlis
                    success_rate = int((dogru / toplam * 100) if toplam > 0 else 0)

                    if toplam > 0:
                        units_stats.append({
                            'name': unit.unite,
                            'total_questions': toplam,
                            'correct_answers': dogru,
                            'wrong_answers': yanlis,
                            'success_rate': success_rate,
                            'color_class': self._get_success_color(success_rate)
                        })

                if not units_stats:
                    units_stats.append({
                        'name': 'Henüz soru çözülmemiş',
                        'total_questions': 0,
                        'correct_answers': 0,
                        'wrong_answers': 0,
                        'success_rate': 0,
                        'color_class': 'secondary'
                    })

                subject_question_stats.append({
                    'name': subject.ders_adi,
                    'units': units_stats
                })

            # ✅ OPTIMIZED: Zayıf yönler analizi - single query with date
            weak_topics = []
            
            # Build unit name to unit object mapping
            unit_map = {u.unite: u for u in all_units}
            
            # Get last wrong attempt dates for weak units in single query
            weak_unit_ids = [
                unit_map[unit_dict['name']].id 
                for subject in subject_question_stats 
                for unit_dict in subject['units']
                if unit_dict['success_rate'] < 70 and unit_dict['total_questions'] >= 5 
                and unit_dict['name'] in unit_map
            ]
            
            if weak_unit_ids:
                # Single query to get last wrong attempts per unit
                last_wrongs = db.session.query(
                    Soru.unite_id,
                    func.max(UserProgress.tarih).label('last_wrong')
                ).join(
                    Soru, UserProgress.soru_id == Soru.id
                ).filter(
                    UserProgress.user_id == self.student_id,
                    Soru.unite_id.in_(weak_unit_ids),
                    UserProgress.yanlis_sayisi > 0,
                    UserProgress.activity_type == ActivityType.QUESTION_SOLVING
                ).group_by(Soru.unite_id).all()
                
                last_wrong_dict = {lw.unite_id: lw.last_wrong for lw in last_wrongs}
            else:
                last_wrong_dict = {}
            
            for subject in subject_question_stats:
                for unit_dict in subject['units']:
                    if unit_dict['success_rate'] < 70 and unit_dict['total_questions'] >= 5:
                        unit_name = unit_dict['name']
                        unite_obj = unit_map.get(unit_name)
                        last_wrong = last_wrong_dict.get(unite_obj.id) if unite_obj else None
                        
                        weak_topics.append({
                            'subject': subject['name'],
                            'unit': unit_name,
                            'success_rate': unit_dict['success_rate'],
                            'total_questions': unit_dict['total_questions'],
                            'last_wrong': last_wrong
                        })

            weak_topics.sort(key=lambda x: x['success_rate'])

            return {
                'subject_stats': subject_question_stats,
                'weak_topics': weak_topics[:5]
            }

        except Exception as e:
            current_app.logger.warning(f"Question analytics error: {str(e)}", exc_info=True)
            return {
                'subject_stats': [{
                    'name': 'Veri Yükleme Hatası',
                    'units': [{
                        'name': f'Hata: {str(e)[:50]}...',
                        'total_questions': 0,
                        'correct_answers': 0,
                        'wrong_answers': 0,
                        'success_rate': 0,
                        'color_class': 'danger'
                    }]
                }],
                'weak_topics': []
            }
    
    def get_performance_trends(self):
        """4. OPTİMİZE EDİLMİŞ PERFORMANS TRENDLERİ"""
        try:
            # ✅ Cache kontrolü
            cache_key = f"perf_trends_{self.student_id}"
            cache_time_key = f"{cache_key}_time"
            
            # Session cache kontrolü (5 dakika)
            from flask import current_app, session
            cached_data = session.get(cache_key)
            cache_time = session.get(cache_time_key)
            
            if cached_data and cache_time:
                from datetime import datetime
                try:
                    last_update = datetime.fromisoformat(cache_time)
                    if (datetime.now() - last_update).total_seconds() < 300:  # 5 dakika
                        current_app.logger.debug(f"Using cached performance trends for student {self.student_id}")
                        return cached_data
                except:
                    pass
            
            current_app.logger.debug(f"Generating fresh performance trends for student {self.student_id}")
            
            # Tek sorgu ile son 30 günlük verileri al
            from datetime import datetime, timedelta
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            
            # ✅ Optimize edilmiş sorgu - tek seferde tüm günleri al
            daily_stats = db.session.query(
                func.date(UserProgress.tarih).label('date'),
                func.count(UserProgress.id).label('total_questions'),
                func.sum(UserProgress.dogru_sayisi).label('correct_answers'),
                func.sum(UserProgress.puan).label('points')
            ).filter(
                UserProgress.user_id == self.student_id,
                UserProgress.soru_id.isnot(None),
                UserProgress.tarih >= thirty_days_ago
            ).group_by(
                func.date(UserProgress.tarih)
            ).all()
            
            # ✅ Dictionary'ye dönüştür (hızlı erişim için)
            stats_dict = {}
            for stat in daily_stats:
                stats_dict[stat.date.strftime('%Y-%m-%d')] = {
                    'total_questions': stat.total_questions or 0,
                    'correct_answers': stat.correct_answers or 0,
                    'points': stat.points or 0
                }
            
            # ✅ Son 30 günü doldur
            daily_performance = []
            for i in range(30):
                day = thirty_days_ago + timedelta(days=i)
                day_str = day.strftime('%Y-%m-%d')
                
                if day_str in stats_dict:
                    stat = stats_dict[day_str]
                    total = stat['total_questions']
                    correct = stat['correct_answers']
                    success_rate = int((correct / total * 100) if total > 0 else 0)
                else:
                    total = correct = success_rate = 0
                    stat = {'points': 0}
                
                daily_performance.append({
                    'date': day_str,
                    'date_display': day.strftime('%d.%m'),
                    'total_questions': total,
                    'correct_answers': correct,
                    'success_rate': success_rate,
                    'points': stat['points']
                })
            
            # ✅ Subject distribution (sadece veri varsa hesapla)
            subject_distribution = []
            if any(d['total_questions'] > 0 for d in daily_performance):
                subject_distribution = self._get_subject_distribution_optimized()
            
            result = {
                'daily_performance': daily_performance,
                'subject_distribution': subject_distribution
            }
            
            # ✅ Cache'e kaydet
            session[cache_key] = result
            session[cache_time_key] = datetime.now().isoformat()
            
            current_app.logger.debug(f"Performance trends generated and cached for student {self.student_id}")
            return result
            
        except Exception as e:
            current_app.logger.warning(f"Performance trends error: {str(e)}", exc_info=True)
            return {
                'daily_performance': [],
                'subject_distribution': []
            }
    
    def _get_subject_distribution_optimized(self):
        """Optimized subject distribution"""
        try:
            if not self.student.class_no:
                return []
            
            # Esnek sınıf bulma (cache'lenmiş)
            matching_sinif = self._find_matching_sinif_cached()
            if not matching_sinif:
                return []
            
            # Tek sorguda tüm ders istatistiklerini al
            subject_stats = db.session.query(
                Ders.ders_adi,
                func.count(UserProgress.id).label('question_count')
            ).join(
                Unite, Ders.id == Unite.ders_id
            ).join(
                Icerik, Unite.id == Icerik.unite_id
            ).join(
                Soru, Icerik.id == Soru.icerik_id
            ).join(
                UserProgress, Soru.id == UserProgress.soru_id
            ).filter(
                Ders.sinif_id == matching_sinif.id,
                UserProgress.user_id == self.student_id,
                UserProgress.soru_id.isnot(None)
            ).group_by(
                Ders.id, Ders.ders_adi
            ).having(
                func.count(UserProgress.id) > 0
            ).all()
            
            return [
                {
                    'name': stat.ders_adi,
                    'question_count': stat.question_count
                }
                for stat in subject_stats
            ]
            
        except Exception as e:
            current_app.logger.warning(f"Subject distribution error: {str(e)}", exc_info=True)
            return []
    
    def _find_matching_sinif_cached(self):
        """Cache'lenmiş sınıf bulma"""
        cache_key = f"sinif_match_{self.student_id}"
        
        from flask import session
        cached_sinif_id = session.get(cache_key)
        
        if cached_sinif_id:
            return Sinif.query.get(cached_sinif_id)
        
        # Sınıf bulma işlemi (mevcut kod)
        matching_sinif = self._find_matching_sinif()
        
        if matching_sinif:
            session[cache_key] = matching_sinif.id
        
        return matching_sinif
    
    def _find_matching_sinif(self):
        """Esnek sınıf bulma (önceki kod)"""
        # ... (mevcut esnek sınıf bulma kodunu buraya kopyalayın)
        # Bu kod önceki örneklerde verilmişti
        pass
    
    def get_time_analytics(self):
        """5. ZAMAN ANALİTİĞİ"""
        try:
            # Toplam çalışma süresi
            total_time_seconds = db.session.query(func.sum(UserProgress.harcanan_sure)).filter_by(
                user_id=self.student_id
            ).scalar() or 0
            
            # Son 30 günlük çalışma süresi
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            recent_time_seconds = db.session.query(func.sum(UserProgress.harcanan_sure)).filter(
                UserProgress.user_id == self.student_id,
                UserProgress.tarih >= thirty_days_ago
            ).scalar() or 0
            
            # Ortalama günlük süre
            days_active = db.session.query(func.count(distinct(func.date(UserProgress.tarih)))).filter(
                UserProgress.user_id == self.student_id,
                UserProgress.tarih >= thirty_days_ago
            ).scalar() or 1
            
            avg_daily_seconds = recent_time_seconds / days_active if days_active > 0 else 0
            
            return {
                'total_time': self._format_time_detailed(total_time_seconds),
                'recent_time': self._format_time_detailed(recent_time_seconds),
                'avg_daily_time': self._format_time_detailed(avg_daily_seconds),
                'active_days': days_active
            }
            
        except Exception as e:
            current_app.logger.warning(f"Time analytics error: {str(e)}", exc_info=True)
            return {
                'total_time': {'hours': 0, 'minutes': 0},
                'recent_time': {'hours': 0, 'minutes': 0},
                'avg_daily_time': {'hours': 0, 'minutes': 0},
                'active_days': 0
            }
    
    def get_risk_analysis(self):
        """6. ERKEN UYARI SİSTEMİ"""
        try:
            risks = []
            
            # Son giriş kontrolü
            last_activity = db.session.query(func.max(UserProgress.tarih)).filter_by(
                user_id=self.student_id
            ).scalar()
            
            if last_activity:
                days_inactive = (datetime.utcnow() - last_activity).days
                if days_inactive >= 7:
                    risks.append({
                        'type': 'inactive',
                        'level': 'high' if days_inactive >= 14 else 'medium',
                        'message': f'{days_inactive} gün boyunca aktif değil',
                        'icon': '⚠️' if days_inactive >= 14 else '🟡'
                    })
            
            # Düşük başarı oranları
            weak_subjects = self.get_question_analytics()['weak_topics']
            if len(weak_subjects) >= 3:
                risks.append({
                    'type': 'low_performance',
                    'level': 'medium',
                    'message': f'{len(weak_subjects)} konuda düşük başarı',
                    'icon': '🔴'
                })
            
            # Profil eksiklikleri
            if not self.student.profile_completed:
                risks.append({
                    'type': 'incomplete_profile',
                    'level': 'low',
                    'message': 'Profil bilgileri eksik',
                    'icon': '🟡'
                })
            
            return risks
            
        except Exception as e:
            current_app.logger.warning(f"Risk analysis error: {str(e)}", exc_info=True)
            return []
    
    def get_achievement_summary(self):
        """Başarı özeti"""
        try:
            # Toplam puan
            total_points = db.session.query(func.sum(UserProgress.puan)).filter(
                UserProgress.user_id == self.student_id,
                UserProgress.puan.isnot(None)
            ).scalar() or 0

            # Toplam soru sayısı - DİNAMİK
            total_questions = db.session.query(func.count(UserProgress.id)).filter(
                UserProgress.user_id == self.student_id,
                UserProgress.soru_id.isnot(None)
            ).scalar() or 0

            # Doğru cevap sayısı - DİNAMİK
            correct_answers = db.session.query(func.sum(UserProgress.dogru_sayisi)).filter(
                UserProgress.user_id == self.student_id,
                UserProgress.soru_id.isnot(None)
            ).scalar() or 0

            # Genel başarı oranı
            overall_success_rate = int((correct_answers / total_questions * 100) if total_questions > 0 else 0)

            # --- EKLENENLER ---
            # Haftalık artış (son 7 gün ve önceki 7 gün)
            today = datetime.utcnow().date()
            week_ago = today - timedelta(days=7)
            prev_week_ago = today - timedelta(days=14)
            prev_week = db.session.query(func.count(UserProgress.id)).filter(
                UserProgress.user_id == self.student_id,
                UserProgress.soru_id.isnot(None),
                func.date(UserProgress.tarih) >= prev_week_ago,
                func.date(UserProgress.tarih) < week_ago
            ).scalar() or 0
            this_week = db.session.query(func.count(UserProgress.id)).filter(
                UserProgress.user_id == self.student_id,
                UserProgress.soru_id.isnot(None),
                func.date(UserProgress.tarih) >= week_ago,
                func.date(UserProgress.tarih) <= today
            ).scalar() or 0
            weekly_increase = this_week - prev_week

            # Streak (aralıksız gün)
            streak = self._get_streak_days() if hasattr(self, '_get_streak_days') else 0

            # Yeni rozetler (örnek: başarı oranı %80 üstü, 1000 puan, vs.)
            new_badges = []
            if overall_success_rate >= 80:
                new_badges.append("Başarı Ustası")
            if total_points >= 1000:
                new_badges.append("1000+ Puan")
            if streak >= 7:
                new_badges.append("7 Günlük Seri")

            return {
                'total_points': int(total_points),
                'total_questions': total_questions,
                'correct_answers': correct_answers,
                'overall_success_rate': overall_success_rate,
                'weekly_increase': weekly_increase,
                'streak': streak,
                'new_badges': new_badges
            }

        except Exception as e:
            current_app.logger.warning(f"Achievement summary error: {str(e)}", exc_info=True)
            return {
                'total_points': 0,
                'total_questions': 0,
                'correct_answers': 0,
                'overall_success_rate': 0,
                'weekly_increase': 0,
                'streak': 0,
                'new_badges': []
            }
    
    # Yardımcı metodlar
    def _get_progress_color(self, percent):
        """İlerleme yüzdesine göre renk sınıfı"""
        if percent >= 80: return 'success'
        elif percent >= 60: return 'info' 
        elif percent >= 40: return 'warning'
        elif percent >= 20: return 'danger'
        else: return 'secondary'
    
    def _get_success_color(self, percent):
        """Başarı oranına göre renk sınıfı"""
        if percent >= 80: return 'success'
        elif percent >= 70: return 'info'
        elif percent >= 60: return 'warning'
        else: return 'danger'
    
    def _get_status_icon(self, status):
        """Durum ikonları"""
        icons = {
            'completed': '✅',
            'in_progress': '🔄', 
            'not_started': '⏳'
        }
        return icons.get(status, '❓')
    
    def _format_time(self, seconds):
        """Saniyeyi saat:dakika formatına çevir"""
        if not seconds: return "0dk"
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        if hours > 0:
            return f"{hours}s {minutes}dk"
        return f"{minutes}dk"
    
    def _format_time_detailed(self, seconds):
        """Detaylı zaman formatı"""
        if not seconds: return {'hours': 0, 'minutes': 0}
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return {'hours': hours, 'minutes': minutes}
    
    def _get_empty_stats(self):
        """Hata durumunda boş istatistikler"""
        return {
            'subject_completion_stats': {'subjects': [], 'overall_completion': 0},
            'question_analytics': {'subject_stats': [], 'weak_topics': []},
            'performance_trends': {'daily_performance': [], 'subject_distribution': []},
            'time_analytics': {'total_time': {'hours': 0, 'minutes': 0}, 'recent_time': {'hours': 0, 'minutes': 0}, 'avg_daily_time': {'hours': 0, 'minutes': 0}, 'active_days': 0},
            'risk_analysis': [],
            'achievement_summary': {'total_points': 0, 'total_questions': 0, 'correct_answers': 0, 'overall_success_rate': 0}
        }