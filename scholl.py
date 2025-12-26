import pandas as pd
from SF import db, app
from SF.models import SchoolType

try:
    with app.app_context():
        df = pd.read_csv("SF/data/schooltype.csv")
        
        # Mevcut okul türlerini al
        existing_types = {st.name for st in SchoolType.query.all()}
        
        new_types = []
        skipped_count = 0
        
        for _, row in df.iterrows():
            if row['name'] not in existing_types:
                new_types.append(SchoolType(name=row['name']))
            else:
                skipped_count += 1
        
        if new_types:
            db.session.add_all(new_types)
            db.session.commit()
            print(f"{len(new_types)} new school types imported.")
        
        if skipped_count > 0:
            print(f"{skipped_count} school types skipped (already exist).")
        
        if not new_types and skipped_count == 0:
            print("No school types to import.")
            
except FileNotFoundError:
    print("Error: schooltype.csv file not found!")
except Exception as e:
    db.session.rollback()
    print(f"Error importing school types: {str(e)}")