"""
WSGI entry point for Gunicorn
"""
from SF import app

if __name__ == "__main__":
    app.run()
