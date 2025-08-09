import os
import tempfile
import pytest

os.environ.setdefault('DATABASE_URL', 'sqlite:///test_app.db')

from app.app_factory import create_app
from app.models import db

@pytest.fixture
def app():
    app = create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with app.app_context():
        db.drop_all()
        db.create_all()
    yield app
    # Teardown
    with app.app_context():
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()
