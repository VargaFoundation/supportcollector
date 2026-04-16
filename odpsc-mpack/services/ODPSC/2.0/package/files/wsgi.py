"""
WSGI entry point for gunicorn.

Usage:
    gunicorn --bind 0.0.0.0:8085 wsgi:application
"""

from odpsc_master import create_app

application = create_app()
