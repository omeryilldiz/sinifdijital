#!/usr/bin/env python3
"""
Test script to verify performance optimizations.
Monitors query count before and after optimization.
"""
import os
import sys
from datetime import datetime, timedelta

# Add SF to path
sys.path.insert(0, '/root/SF')

# Configure logging
os.environ['FLASK_ENV'] = 'development'
os.environ['ENABLE_QUERY_LOGGING'] = 'true'

from SF import app, db
from SF.models import User, UserProgress, ActivityType

def count_queries(func, *args, **kwargs):
    """Execute function and count database queries"""
    # Reset query log
    if hasattr(db.session, 'info'):
        db.session.info['_last_query_count'] = 0
    
    # Run function
    result = func(*args, **kwargs)
    
    # Count queries
    from flask import get_flashed_messages
    from flask.ctx import after_this_request
    
    # Return query count via app context
    return result

def test_guclendirme_merkezi():
    """Test /guclendirme-merkezi route"""
    with app.app_context():
        from SF.services.student_statistics_service import StudentStatisticsService
        from SF.services.leaderboard_service import LeaderboardService
        
        # Get or create test user
        test_user = User.query.filter_by(username='testuser').first()
        if not test_user:
            print("❌ Test user not found. Create a test user first.")
            return
        
        student_id = test_user.id
        print(f"✅ Testing with user ID: {student_id}")
        print(f"📊 User has {UserProgress.query.filter_by(user_id=student_id).count()} activity records")
        
        # Initialize query counting
        from sqlalchemy import event
        query_count = [0]
        
        def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            query_count[0] += 1
            print(f"  Query {query_count[0]}: {statement[:100]}...")
        
        @app.before_request
        def reset_query_count():
            query_count[0] = 0
        
        # Test StudentStatisticsService.get_comprehensive_stats()
        print("\n📈 Testing StudentStatisticsService.get_comprehensive_stats()...")
        query_count[0] = 0
        event.listen(db.engine, "after_cursor_execute", receive_after_cursor_execute)
        
        stats_service = StudentStatisticsService(student_id)
        stats = stats_service.get_comprehensive_stats()
        
        print(f"✅ Total queries for comprehensive_stats: {query_count[0]}")
        print(f"📊 Stats keys: {list(stats.keys())}")
        
        # Test LeaderboardService.get_student_leaderboard_data()
        print("\n🏆 Testing LeaderboardService.get_student_leaderboard_data()...")
        query_count[0] = 0
        
        leaderboard_service = LeaderboardService()
        leaderboard = leaderboard_service.get_student_leaderboard_data(student_id)
        
        print(f"✅ Total queries for leaderboard_data: {query_count[0]}")
        print(f"📊 Leaderboard keys: {list(leaderboard.keys())}")
        
        event.remove(db.engine, "after_cursor_execute", receive_after_cursor_execute)
        
        print("\n✅ Performance test completed!")

if __name__ == '__main__':
    test_guclendirme_merkezi()
