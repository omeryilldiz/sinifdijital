# populate_icerik_slugs.py
from SF import app, db
from SF.models import Icerik
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

def populate_icerik_slugs():
    with app.app_context():
        icerikler = Icerik.query.filter(Icerik.slug.is_(None)).all()
        
        for icerik in icerikler:
            base_slug = create_slug(icerik.baslik)
            slug = base_slug
            counter = 1
            
            while Icerik.query.filter_by(slug=slug).first():
                slug = f"{base_slug}-{counter}"
                counter += 1
            
            icerik.slug = slug
            db.session.commit()
            print(f"İçerik slug eklendi: {icerik.baslik} -> {slug}")
        
        print(f"Toplam {len(icerikler)} içerik için slug eklendi!")

if __name__ == "__main__":
    populate_icerik_slugs()