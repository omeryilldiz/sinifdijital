import pandas as pd
from SF import db, app
from SF.models import Province

try:
    with app.app_context():
        df = pd.read_csv("SF/data/provinces.csv")
        
        # Mevcut province code'larını al
        existing_codes = {p.code for p in Province.query.all()}
        
        # Yeni province'leri toplu ekle
        new_provinces = []
        for _, row in df.iterrows():
            if row['id'] not in existing_codes:
                new_provinces.append(Province(code=row['id'], name=row['name']))
        
        if new_provinces:
            db.session.add_all(new_provinces)
            db.session.commit()
            print(f"{len(new_provinces)} new provinces imported.")
        else:
            print("No new provinces to import.")
            
except Exception as e:
    db.session.rollback()
    print(f"Error: {str(e)}")