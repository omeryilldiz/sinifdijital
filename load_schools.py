#!/usr/bin/env python3
"""
Load schools from CSV into database
"""
import os
import sys
import csv
from pathlib import Path

# Set environment
os.environ['SECRET_KEY'] = open('/root/SF/deploy/secrets/secret_key.txt').read().strip()

sys.path.insert(0, '/root/SF')

from SF import app, db
from SF.models import School, District, SchoolType

def load_schools_from_csv():
    """Load schools from CSV file"""
    csv_path = Path('/root/SF/SF/data/school.csv')
    
    if not csv_path.exists():
        print(f"❌ CSV file not found: {csv_path}")
        return
    
    with app.app_context():
        # Get school types
        school_types = {st.name: st.id for st in SchoolType.query.all()}
        if not school_types:
            print("❌ No school types found in database")
            return
        
        print(f"✅ Found {len(school_types)} school types: {school_types}")
        
        # Get districts for quick lookup
        districts = {d.name: d.id for d in District.query.all()}
        if not districts:
            print("❌ No districts found in database")
            return
        
        print(f"✅ Found {len(districts)} districts")
        
        # Statistics
        success = 0
        skipped = 0
        errors = 0
        
        # Read CSV
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f, fieldnames=['school_type', 'district_name', 'school_name'])
            
            for row_num, row in enumerate(reader, 1):
                try:
                    school_type_name = row.get('school_type', '').strip()
                    district_name = row.get('district_name', '').strip()
                    school_name = row.get('school_name', '').strip()
                    
                    # Validate
                    if not school_name or not district_name:
                        skipped += 1
                        continue
                    
                    # Get IDs
                    school_type_id = school_types.get(school_type_name)
                    if not school_type_id:
                        # Try to find it with fuzzy match or use default
                        school_type_id = school_types.get('Diğer', list(school_types.values())[0])
                    
                    district_id = districts.get(district_name)
                    if not district_id:
                        skipped += 1
                        continue
                    
                    # Check if already exists
                    existing = School.query.filter_by(
                        name=school_name,
                        district_id=district_id
                    ).first()
                    
                    if existing:
                        skipped += 1
                        continue
                    
                    # Create school
                    school = School(
                        name=school_name,
                        school_type_id=school_type_id,
                        district_id=district_id
                    )
                    db.session.add(school)
                    success += 1
                    
                    # Commit every 100 rows
                    if success % 100 == 0:
                        db.session.commit()
                        print(f"  Committed {success} schools...")
                    
                except Exception as e:
                    errors += 1
                    if errors <= 5:  # Print first 5 errors
                        print(f"  Row {row_num} error: {str(e)}")
        
        # Final commit
        db.session.commit()
        
        print(f"\n✅ Load complete!")
        print(f"  Success: {success}")
        print(f"  Skipped: {skipped}")
        print(f"  Errors: {errors}")
        
        # Verify
        school_count = School.query.count()
        print(f"\n📊 Total schools in database: {school_count}")

if __name__ == '__main__':
    load_schools_from_csv()
