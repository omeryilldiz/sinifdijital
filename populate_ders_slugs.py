# populate_ders_slugs.py dosyası oluşturun
from SF import app, db
from SF.models import Ders
import re
from unidecode import unidecode

def create_slug(text):
    if not text:
        return ""
    
    text = unidecode(text)
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s-]', '', text)
    text = re.sub(r'\s+', '-', text)
    text = re.sub(r'-+', '-', text)
    return text.strip('-')

def populate_ders_slugs():
    with app.app_context():
        dersler = Ders.query.filter(Ders.slug.is_(None)).all()
        
        for ders in dersler:
            base_slug = create_slug(ders.ders_adi)
            slug = base_slug
            counter = 1
            
            while Ders.query.filter_by(slug=slug).first():
                slug = f"{base_slug}-{counter}"
                counter += 1
            
            ders.slug = slug
            db.session.commit()
            print(f"Ders slug eklendi: {ders.ders_adi} -> {slug}")
        
        print(f"Toplam {len(dersler)} ders için slug eklendi!")

if __name__ == "__main__":
    populate_ders_slugs()