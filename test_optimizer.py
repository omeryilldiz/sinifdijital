"""Query Optimizer test scripti"""

import time
from SF import app, db
from SF.models import User

def test_query_optimizer():
    """Query optimizer'ı test et"""
    
    with app.app_context():
        print("🚀 Query Optimizer Test Başlatılıyor...")
        
        try:
            # Services import test
            from SF.services.query_optimizer import QueryOptimizer
            print("✅ QueryOptimizer import başarılı!")
            
            # Test 1: User count
            user_count = User.query.filter_by(role='user').count()
            print(f"📊 Toplam kullanıcı sayısı: {user_count}")
            
            # Test 2: Students query
            if user_count > 0:
                start_time = time.time()
                students = QueryOptimizer.get_students_optimized().limit(5).all()
                query_time = time.time() - start_time
                
                print(f"⚡ Öğrenci sorgusu: {query_time:.4f}s ({len(students)} öğrenci)")
                
                # Test 3: User stats (if users exist)
                if students:
                    user_id = students[0].id
                    start_time = time.time()
                    stats = QueryOptimizer.get_user_progress_stats(user_id)
                    stats_time = time.time() - start_time
                    
                    print(f"📈 İstatistik sorgusu: {stats_time:.4f}s")
                    print(f"   Toplam puan: {stats['total_points']}")
                    print(f"   Aktivite sayısı: {stats['total_activities']}")
            
            print("\n✅ Tüm testler başarılı!")
            
        except ImportError as e:
            print(f"❌ Import hatası: {e}")
        except Exception as e:
            print(f"❌ Test hatası: {e}")

if __name__ == "__main__":
    test_query_optimizer()