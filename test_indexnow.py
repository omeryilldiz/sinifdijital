import pytest
from unittest.mock import patch, MagicMock
from SF import app
from SF.services.indexnow_service import IndexNowService

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['INDEXNOW_API_KEY'] = 'be8b0e0a9c5b9afed0d072c643ed9120'
    app.config['INDEXNOW_ENABLED'] = True
    app.config['BASE_URL'] = 'https://sinifdijital.com'
    with app.test_client() as client:
        yield client

class TestIndexNowService:

    def test_config_retrieval(self, client):
        with app.app_context():
            assert IndexNowService.get_api_key() == 'be8b0e0a9c5b9afed0d072c643ed9120'
            assert IndexNowService.is_enabled() is True
            assert IndexNowService.get_host() == 'sinifdijital.com'
            assert IndexNowService.get_key_location() == 'https://sinifdijital.com/be8b0e0a9c5b9afed0d072c643ed9120.txt'

    def test_normalize_urls(self, client):
        with app.app_context():
            raw_urls = [
                '/8-sinif/matematik',
                'https://sinifdijital.com/8-sinif/matematik',  # Tekrar eden
                'https://sinifdijital.com/8-sinif/turkce',
                'https://otherdomain.com/bad-url',  # Farklı domain
                '',
                None
            ]
            normalized = IndexNowService.normalize_urls(raw_urls)
            assert len(normalized) == 2
            assert 'https://sinifdijital.com/8-sinif/matematik' in normalized
            assert 'https://sinifdijital.com/8-sinif/turkce' in normalized
            assert 'https://otherdomain.com/bad-url' not in normalized

    @patch('SF.services.indexnow_service.requests.post')
    def test_submit_urls_success(self, mock_post, client):
        with app.app_context():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_post.return_value = mock_resp

            success, msg = IndexNowService.submit_urls(
                ['https://sinifdijital.com/8-sinif/matematik'],
                background=False
            )

            assert success is True
            assert mock_post.called
            call_args, call_kwargs = mock_post.call_args
            assert call_kwargs['json']['host'] == 'sinifdijital.com'
            assert call_kwargs['json']['key'] == 'be8b0e0a9c5b9afed0d072c643ed9120'
            assert 'https://sinifdijital.com/8-sinif/matematik' in call_kwargs['json']['urlList']

    @patch('SF.services.indexnow_service.requests.post')
    def test_submit_urls_accepted_202(self, mock_post, client):
        with app.app_context():
            mock_resp = MagicMock()
            mock_resp.status_code = 202
            mock_post.return_value = mock_resp

            success, msg = IndexNowService.submit_urls(
                ['https://sinifdijital.com/8-sinif/matematik'],
                background=False
            )

            assert success is True
            assert "alındı" in msg.lower() or "key" in msg.lower()

    @patch('SF.services.indexnow_service.requests.post')
    def test_submit_urls_forbidden_403(self, mock_post, client):
        with app.app_context():
            mock_resp = MagicMock()
            mock_resp.status_code = 403
            mock_post.return_value = mock_resp

            success, msg = IndexNowService.submit_urls(
                ['https://sinifdijital.com/8-sinif/matematik'],
                background=False
            )

            assert success is False
            assert "Yasaklı" in msg

    @patch('SF.services.indexnow_service.IndexNowService.submit_urls')
    def test_notify_content_change_hierarchy(self, mock_submit, client):
        with app.app_context():
            mock_submit.return_value = (True, "OK")

            # İçerik değişikliği
            IndexNowService.notify_content_change(
                sinif_slug='8-sinif',
                ders_slug='matematik',
                unite_slug='carpanlar-ve-katlar',
                icerik_slug='ebob-ekok',
                background=False
            )
            mock_submit.assert_called_once()
            called_urls = mock_submit.call_args[0][0]
            assert 'https://sinifdijital.com/8-sinif/matematik/carpanlar-ve-katlar/ebob-ekok' in called_urls
            assert 'https://sinifdijital.com/8-sinif/matematik' in called_urls

    def test_get_status(self, client):
        with app.app_context():
            status = IndexNowService.get_status()
            assert status['enabled'] is True
            assert status['api_key'] == 'be8b0e0a9c5b9afed0d072c643ed9120'
            assert status['host'] == 'sinifdijital.com'
            assert 'last_submission' in status


class TestIndexNowRoutes:

    def test_key_verification_success(self, client):
        response = client.get('/be8b0e0a9c5b9afed0d072c643ed9120.txt')
        assert response.status_code == 200
        assert 'text/plain' in response.content_type
        assert response.data.decode('utf-8').strip() == 'be8b0e0a9c5b9afed0d072c643ed9120'

    def test_key_verification_404_invalid_key(self, client):
        response = client.get('/nonexistent_key_12345.txt')
        assert response.status_code == 404
