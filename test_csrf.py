import unittest
from flask import Flask, request
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)

@app.route('/icerik-sure-kaydet', methods=['POST'])
def icerik_sure_kaydet():
    if not request.form.get('csrf_token'):
        return 'CSRF token is missing.', 400
    return 'Success', 200

class TestCSRFToken(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    def test_missing_csrf_token(self):
        response = self.app.post('/icerik-sure-kaydet', data={})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'CSRF token is missing.', response.data)

if __name__ == '__main__':
    unittest.main()