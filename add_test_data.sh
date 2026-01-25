#!/bin/bash
# Add dummy user progress data for testing

cd /root/SF

# Create test data SQL
cat > /tmp/test_data.sql << 'EOF'
-- Insert test user progress data (50 questions, 7 days)
DO $$
DECLARE
  v_user_id INT := 18;
  v_soru_id INT;
  v_date DATE;
  i INT;
BEGIN
  FOR i IN 1..50 LOOP
    SELECT id INTO v_soru_id FROM soru LIMIT 1 OFFSET (i-1);
    IF v_soru_id IS NOT NULL THEN
      v_date := NOW()::DATE - (i % 7);
      INSERT INTO user_progress (
        user_id, soru_id, dogru_sayisi, yanlis_sayisi, 
        puan, harcanan_sure, activity_type, tarih, okundu
      ) VALUES (
        v_user_id,
        v_soru_id,
        CASE WHEN random() > 0.3 THEN 1 ELSE 0 END,  -- 70% correct
        CASE WHEN random() <= 0.3 THEN 1 ELSE 0 END, -- 30% wrong
        CASE WHEN random() > 0.3 THEN 10 ELSE 0 END, -- points
        random() * 600 + 30,  -- spent time 30-630 seconds
        'question_solving',
        v_date::timestamp + (random() * 86400 || ' seconds')::interval,
        true
      );
    END IF;
  END LOOP;
END $$;

-- Verify
SELECT COUNT(*) as total_progress, COUNT(DISTINCT soru_id) as unique_questions FROM user_progress WHERE user_id=18;
EOF

# Execute
echo "Adding test data..."
docker compose exec -T db psql -U sfuser -d sfdb -f /tmp/test_data.sql
echo "✅ Test data added successfully"
