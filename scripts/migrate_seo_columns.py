#!/usr/bin/env python3
"""
icerik tablosuna yeni SEO sütunlarını ekleyen migration scripti.
"""
import os
import sys
import psycopg2

def run_migration():
    # Öncelik sırasıyla DATABASE_URL veya bağlantı parametreleri
    db_url = os.environ.get('DATABASE_URL')
    
    if not db_url:
        db_user = os.environ.get('DB_USER') or os.environ.get('POSTGRES_USER', 'sfuser')
        db_pass = os.environ.get('POSTGRES_PASSWORD') or os.environ.get('DB_PASSWORD', '1174')
        db_host = os.environ.get('DB_HOST') or os.environ.get('POSTGRES_HOST', 'localhost')
        db_port = os.environ.get('DB_PORT') or os.environ.get('POSTGRES_PORT', '5432')
        db_name = os.environ.get('DB_NAME') or os.environ.get('POSTGRES_DB', 'sfdb')
        db_url = f"postgresql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"

    print(f"Bağlanılıyor: {db_url.split('@')[-1]} ...")

    queries = [
        "ALTER TABLE icerik ADD COLUMN IF NOT EXISTS meta_title VARCHAR(255);",
        "ALTER TABLE icerik ADD COLUMN IF NOT EXISTS meta_description VARCHAR(300);",
        "ALTER TABLE icerik ADD COLUMN IF NOT EXISTS meta_keywords VARCHAR(255);"
    ]

    try:
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        with conn.cursor() as cur:
            for q in queries:
                print(f"Çalıştırılıyor: {q}")
                cur.execute(q)
            
            # Kontrol et
            cur.execute("""
                SELECT column_name, data_type, character_maximum_length 
                FROM information_schema.columns 
                WHERE table_name = 'icerik' AND column_name IN ('meta_title', 'meta_description', 'meta_keywords');
            """)
            rows = cur.fetchall()
            print("\nEklenen / Mevcut Sütunlar:")
            for row in rows:
                print(f"  - {row[0]}: {row[1]} ({row[2]})")

        conn.close()
        print("\n✅ Migration başarıyla tamamlandı!")
        return 0
    except Exception as e:
        print(f"\n❌ Migration hatası: {str(e)}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(run_migration())
