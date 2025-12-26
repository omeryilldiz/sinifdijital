from SF import app, db
from SF.models import Unite
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

def populate_unite_slugs():
    with app.app_context():
        uniteler = Unite.query.filter(Unite.slug.is_(None)).all()
        
        for unite in uniteler:
            base_slug = create_slug(unite.unite)
            slug = base_slug
            counter = 1
            
            while Unite.query.filter_by(slug=slug).first():
                slug = f"{base_slug}-{counter}"
                counter += 1
            
            unite.slug = slug
            db.session.commit()
            print(f"Unite slug eklendi: {unite.unite} -> {slug}")
        
        print(f"Toplam {len(uniteler)} ünite için slug eklendi!")

if __name__ == "__main__":
    populate_unite_slugs()