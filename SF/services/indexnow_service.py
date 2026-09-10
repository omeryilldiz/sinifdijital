import logging
import os
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
from flask import current_app

logger = logging.getLogger('indexnow')

class IndexNowService:
    """
    IndexNow API servisi - Bing, Yandex, Seznam, Naver vb. arama motorlarına
    içerik değişikliklerini anında bildiren protokol entegrasyonu.
    """
    
    DEFAULT_API_ENDPOINT = "https://api.indexnow.org/indexnow"
    MAX_URLS_PER_REQUEST = 10000
    REQUEST_TIMEOUT = 10
    MAX_RETRIES = 3

    # Son gönderim durumu takibi (in-memory)
    _last_submission = {
        'timestamp': None,
        'url_count': 0,
        'success': None,
        'status_code': None,
        'message': 'Henüz gönderim yapılmadı'
    }

    @classmethod
    def get_api_key(cls) -> str:
        """API Key'i config veya env'den al"""
        try:
            if current_app:
                return current_app.config.get('INDEXNOW_API_KEY') or os.environ.get('INDEXNOW_API_KEY', '')
        except RuntimeError:
            pass
        return os.environ.get('INDEXNOW_API_KEY', '')

    @classmethod
    def is_enabled(cls) -> bool:
        """IndexNow aktif mi?"""
        try:
            if current_app:
                val = current_app.config.get('INDEXNOW_ENABLED')
                if val is not None:
                    return bool(val)
        except RuntimeError:
            pass
        env_val = os.environ.get('INDEXNOW_ENABLED', 'True')
        return env_val.lower() in ('true', '1', 'yes')

    @classmethod
    def get_base_url(cls) -> str:
        """Sitenin temel URL'sini al"""
        try:
            if current_app:
                val = current_app.config.get('BASE_URL')
                if val:
                    return val.rstrip('/')
        except RuntimeError:
            pass
        return os.environ.get('BASE_URL', 'https://sinifdijital.com').rstrip('/')

    @classmethod
    def get_host(cls) -> str:
        """Host domain adını al (ör: sinifdijital.com)"""
        base_url = cls.get_base_url()
        parsed = urlparse(base_url)
        return parsed.netloc or 'sinifdijital.com'

    @classmethod
    def get_key_location(cls) -> str:
        """API Key doğrulama dosyasının tam URL'si"""
        base_url = cls.get_base_url()
        api_key = cls.get_api_key()
        return f"{base_url}/{api_key}.txt"

    @classmethod
    def get_status(cls) -> dict:
        """IndexNow durum bilgilerini döndür"""
        return {
            'enabled': cls.is_enabled(),
            'api_key': cls.get_api_key(),
            'host': cls.get_host(),
            'key_location': cls.get_key_location(),
            'endpoint': cls.DEFAULT_API_ENDPOINT,
            'last_submission': cls._last_submission
        }

    @classmethod
    def normalize_urls(cls, urls: list[str]) -> list[str]:
        """URL'leri tam ve geçerli hale getir, tekrar edenleri kaldır"""
        base_url = cls.get_base_url()
        host = cls.get_host()
        normalized = []
        seen = set()

        for url in urls:
            if not url:
                continue
            url_str = str(url).strip()
            if not url_str:
                continue
            
            # Göreceli path ise tam URL yap
            if url_str.startswith('/'):
                url_str = f"{base_url}{url_str}"
            elif not url_str.startswith(('http://', 'https://')):
                url_str = f"https://{url_str}"

            # Sadece kendi sitemize ait URL'leri filtrele
            parsed = urlparse(url_str)
            if parsed.netloc == host and url_str not in seen:
                seen.add(url_str)
                normalized.append(url_str)

        return normalized

    @classmethod
    def submit_url(cls, url: str, background: bool = True) -> tuple[bool, str]:
        """Tek bir URL'yi IndexNow'a bildir"""
        return cls.submit_urls([url], background=background)

    @classmethod
    def submit_urls(cls, urls: list[str], background: bool = True) -> tuple[bool, str]:
        """
        URL listesini IndexNow'a bildir.
        
        Args:
            urls: Gönderilecek URL listesi
            background: True ise arka planda (thread) çalışır, request'i bloklamaz
            
        Returns:
            (success: bool, message: str)
        """
        if not cls.is_enabled():
            logger.info("IndexNow devre dışı bırakılmış (INDEXNOW_ENABLED=False).")
            return False, "IndexNow devre dışı."

        api_key = cls.get_api_key()
        if not api_key:
            logger.warning("IndexNow API key bulunamadı. Gönderim yapılmadı.")
            return False, "IndexNow API key tanımlanmamış."

        clean_urls = cls.normalize_urls(urls)
        if not clean_urls:
            return False, "Gönderilecek geçerli URL bulunamadı."

        if background:
            thread = threading.Thread(
                target=cls._execute_batch_submissions,
                args=(clean_urls,),
                daemon=True,
                name="indexnow-submission"
            )
            thread.start()
            return True, f"{len(clean_urls)} URL arka planda IndexNow'a gönderiliyor."
        else:
            return cls._execute_batch_submissions(clean_urls)

    @classmethod
    def _execute_batch_submissions(cls, urls: list[str]) -> tuple[bool, str]:
        """URL'leri batch'lere böl ve IndexNow API'sine gönder"""
        total_urls = len(urls)
        host = cls.get_host()
        api_key = cls.get_api_key()
        key_location = cls.get_key_location()

        all_success = True
        last_message = ""
        last_status_code = None

        # MAX_URLS_PER_REQUEST (10,000) boyutunda dilimlere ayır
        for i in range(0, total_urls, cls.MAX_URLS_PER_REQUEST):
            batch = urls[i:i + cls.MAX_URLS_PER_REQUEST]
            payload = {
                "host": host,
                "key": api_key,
                "keyLocation": key_location,
                "urlList": batch
            }

            success, status_code, message = cls._send_payload_with_retry(payload)
            last_status_code = status_code
            last_message = message

            if not success:
                all_success = False
                logger.error(f"IndexNow gönderim hatası (Batch {i // cls.MAX_URLS_PER_REQUEST + 1}): {message}")
            else:
                logger.info(f"IndexNow başarılı ({len(batch)} URL gönderildi): {message}")

        # Son gönderim durumunu güncelle
        cls._last_submission = {
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
            'url_count': total_urls,
            'success': all_success,
            'status_code': last_status_code,
            'message': last_message
        }

        return all_success, last_message

    @classmethod
    def _send_payload_with_retry(cls, payload: dict) -> tuple[bool, int | None, str]:
        """Payload'ı retry mekanizması ile POST et"""
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'User-Agent': 'SinifDijital-IndexNow/1.0'
        }

        for attempt in range(1, cls.MAX_RETRIES + 1):
            try:
                response = requests.post(
                    cls.DEFAULT_API_ENDPOINT,
                    json=payload,
                    headers=headers,
                    timeout=cls.REQUEST_TIMEOUT
                )

                status_code = response.status_code

                if status_code in (200, 202):
                    msg = "URL'ler IndexNow tarafından kabul edildi." if status_code == 200 else "URL'ler alındı, key doğrulaması bekleniyor."
                    return True, status_code, msg
                elif status_code == 400:
                    return False, status_code, "Geçersiz istek (Bad Request). Format hatalı."
                elif status_code == 403:
                    return False, status_code, "Yasaklı (Forbidden). API key geçersiz veya key dosyası bulunamadı."
                elif status_code == 422:
                    return False, status_code, "İşlenemeyen Varlık (Unprocessable Entity). URL'ler domain ile eşleşmiyor."
                elif status_code == 429:
                    logger.warning(f"IndexNow Rate limit (429). Deneme {attempt}/{cls.MAX_RETRIES}...")
                    if attempt < cls.MAX_RETRIES:
                        time.sleep(2 ** attempt)
                        continue
                    return False, status_code, "Çok fazla istek (Rate Limit aşıldı)."
                else:
                    logger.warning(f"IndexNow beklenmeyen yanıt ({status_code}). Deneme {attempt}/{cls.MAX_RETRIES}")
                    if attempt < cls.MAX_RETRIES:
                        time.sleep(1 * (2 ** attempt))
                        continue
                    return False, status_code, f"API hatası: HTTP {status_code}"

            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                logger.warning(f"IndexNow bağlantı hatası (Deneme {attempt}/{cls.MAX_RETRIES}): {str(e)}")
                if attempt < cls.MAX_RETRIES:
                    time.sleep(1 * (2 ** attempt))
                    continue
                return False, None, f"Bağlantı hatası: {str(e)}"
            except Exception as e:
                logger.error(f"IndexNow beklenmeyen hata: {str(e)}")
                return False, None, f"Beklenmeyen hata: {str(e)}"

        return False, None, "Maksimum deneme sayısına ulaşıldı."

    @classmethod
    def notify_content_change(cls, sinif_slug: str = None, ders_slug: str = None,
                              unite_slug: str = None, icerik_slug: str = None,
                              base_url: str = None, background: bool = True) -> tuple[bool, str]:
        """
        İçerik hiyerarşisine göre ilgili URL'yi tespit edip IndexNow'a bildir.
        
        - İçerik: /{sinif_slug}/{ders_slug}/{unite_slug}/{icerik_slug}
        - Ünite/Ders: /{sinif_slug}/{ders_slug}
        - Sınıf: /{sinif_slug}
        """
        if not base_url:
            base_url = cls.get_base_url()

        urls_to_submit = []

        if sinif_slug and ders_slug and unite_slug and icerik_slug:
            urls_to_submit.append(f"{base_url}/{sinif_slug}/{ders_slug}/{unite_slug}/{icerik_slug}")
            # Ayrıca ders sayfasını da güncelle
            urls_to_submit.append(f"{base_url}/{sinif_slug}/{ders_slug}")
        elif sinif_slug and ders_slug:
            urls_to_submit.append(f"{base_url}/{sinif_slug}/{ders_slug}")
        elif sinif_slug:
            urls_to_submit.append(f"{base_url}/{sinif_slug}")

        if urls_to_submit:
            return cls.submit_urls(urls_to_submit, background=background)
        return False, "Geçerli bir slug hiyerarşisi belirtilmedi."

    @classmethod
    def get_all_public_urls(cls, db_session=None) -> list[str]:
        """Tüm yayındaki sınıf, ders ve içerik URL'lerini veritabanından topla"""
        from SF.models import Sinif, Ders, Unite, Icerik

        base_url = cls.get_base_url()
        urls = []

        try:
            # 1. Sınıflar
            siniflar = Sinif.query.filter(Sinif.slug.isnot(None)).all()
            for s in siniflar:
                if s.slug:
                    urls.append(f"{base_url}/{s.slug}")

            # 2. Dersler
            dersler = Ders.query.join(Sinif, Ders.sinif_id == Sinif.id).all()
            for d in dersler:
                if d.sinif and d.sinif.slug and d.slug:
                    urls.append(f"{base_url}/{d.sinif.slug}/{d.slug}")

            # 3. İçerikler
            icerikler = Icerik.query.join(Unite, Icerik.unite_id == Unite.id)\
                .join(Ders, Unite.ders_id == Ders.id)\
                .join(Sinif, Ders.sinif_id == Sinif.id).all()

            for ic in icerikler:
                try:
                    unite = ic.unite
                    ders = unite.ders if unite else None
                    sinif = ders.sinif if ders else None
                    if sinif and ders and unite and ic.slug:
                        urls.append(f"{base_url}/{sinif.slug}/{ders.slug}/{unite.slug}/{ic.slug}")
                except Exception:
                    continue

        except Exception as e:
            logger.error(f"Tüm URL'leri toplarken hata: {str(e)}")

        return cls.normalize_urls(urls)

    @classmethod
    def submit_all_public_urls(cls, background: bool = True) -> tuple[bool, str]:
        """Veritabanındaki tüm public URL'leri IndexNow'a gönder"""
        urls = cls.get_all_public_urls()
        if not urls:
            return False, "Gönderilecek public URL bulunamadı."
        return cls.submit_urls(urls, background=background)
