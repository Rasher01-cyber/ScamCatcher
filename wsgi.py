"""Production WSGI entry for gunicorn / Render."""

from app import create_app

app = create_app()
