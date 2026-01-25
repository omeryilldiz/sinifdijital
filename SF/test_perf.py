#!/usr/bin/env python3
"""
Performance test script - runs inside docker container
Monitors query count for /guclendirme-merkezi route
"""
import os
import sys

# Set environment
os.environ['FLASK_ENV'] = 'development'

sys.path.insert(0, '/app')

from SF import app, db
from SF.models import User, UserProgress, ActivityType, Soru
from datetime import datetime, timedelta

def test_performance():
    """Test the optimized route"""
    with app.app_context():
        from SF.services.student_statistics_service import StudentStatisticsService
        from SF.services.leaderboard_service import LeaderboardService
        
        # Get test user
        test_user = User.query.filter_by(username='Ömer').first()
        if not test_user:
            print("❌ Test user not found")
            return
        
        student_id = test_user.id
        progress_count = UserProgress.query.filter_by(
            user_id=student_id, 
            activity_type='question_solving'
        ).count()
        soru_count = Soru.query.count()
        
        print(f"📊 Test User: {test_user.username} (ID={student_id})")
        print(f"📈 User Progress Records: {progress_count}")
        print(f"📖 Total Questions: {soru_count}")
        
        # Hook into SQLAlchemy to count queries
        query_count = [0]
        
        def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            query_count[0] += 1
            # Print first 100 chars of query
            query_short = statement[:100].replace('\n', ' ')
            print(f"  [{query_count[0]}] {query_short}...")
        
        from sqlalchemy import event
        event.listen(db.engine, "after_cursor_execute", receive_after_cursor_execute)
        
        print("\n" + "="*60)
        print("🔥 Testing StudentStatisticsService.get_comprehensive_stats()")
        print("="*60)
        query_count[0] = 0
        
        stats_service = StudentStatisticsService(student_id)
        stats = stats_service.get_comprehensive_stats()
        
        stats_query_count = query_count[0]
        print(f"\n✅ StudentStatisticsService: {stats_query_count} queries")
        if stats:
            print(f"   Keys: {', '.join(stats.keys())}")
        
        print("\n" + "="*60)
        print("🏆 Testing LeaderboardService.get_student_leaderboard_data()")
        print("="*60)
        query_count[0] = 0
        
        leaderboard_service = LeaderboardService()
        leaderboard = leaderboard_service.get_student_leaderboard_data(student_id)
        
        leaderboard_query_count = query_count[0]
        print(f"\n✅ LeaderboardService: {leaderboard_query_count} queries")
        if leaderboard:
            print(f"   Keys: {', '.join(leaderboard.keys())}")
        
        event.remove(db.engine, "after_cursor_execute", receive_after_cursor_execute)
        
        total_queries = stats_query_count + leaderboard_query_count
        print("\n" + "="*60)
        print(f"📊 TOTAL QUERIES FOR /guclendirme-merkezi: {total_queries}")
        print("="*60)
        
        if total_queries <= 20:
            print("✅ OPTIMIZATION SUCCESSFUL! (Expected <20 queries, got", total_queries, ")")
        else:
            print("⚠️  Still high query count. Target: <20 queries")

if __name__ == '__main__':
    test_performance()
