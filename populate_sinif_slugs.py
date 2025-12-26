# populate_sinif_slugs.py dosyası oluşturun
from SF import app, db
from SF.models import Sinif
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

def populate_sinif_slugs():
    with app.app_context():
        siniflar = Sinif.query.filter(Sinif.slug.is_(None)).all()
        
        for sinif in siniflar:
            base_slug = create_slug(sinif.sinif)
            slug = base_slug
            counter = 1
            
            while Sinif.query.filter_by(slug=slug).first():
                slug = f"{base_slug}-{counter}"
                counter += 1
            
            sinif.slug = slug
            db.session.commit()
            print(f"Sinif slug eklendi: {sinif.sinif} -> {slug}")
        
        print(f"Toplam {len(siniflar)} sınıf için slug eklendi!")

if __name__ == "__main__":
    populate_sinif_slugs()