import pandas as pd
from SF import db, app
from SF.models import District, Province

try:
    with app.app_context():
        df = pd.read_csv("SF/data/ilceler.csv")
        
        # Mevcut ilçeleri al (name + province_id kombinasyonu ile)
        existing_districts = {(d.name, d.province_id) for d in District.query.all()}
        
        new_districts = []
        skipped_count = 0
        
        for _, row in df.iterrows():
            # Province'in var olup olmadığını kontrol et (modern yöntem)
            province = db.session.get(Province, row['il_id'])
            if not province:
                print(f"Warning: Province ID {row['il_id']} not found for district {row['name']}")
                skipped_count += 1
                continue
            
            # Duplicate kontrolü
            if (row['name'], row['il_id']) not in existing_districts:
                new_districts.append(District(
                    name=row['name'], 
                    province_id=row['il_id']
                ))
            else:
                skipped_count += 1
        
        if new_districts:
            db.session.add_all(new_districts)
            db.session.commit()
            print(f"{len(new_districts)} new districts imported.")
        
        if skipped_count > 0:
            print(f"{skipped_count} districts skipped (already exist or invalid province_id).")
        
        if not new_districts and skipped_count == 0:
            print("No districts to import.")
            
except FileNotFoundError:
    print("Error: ilceler.csv file not found!")
except Exception as e:
    db.session.rollback()
    print(f"Error importing districts: {str(e)}")