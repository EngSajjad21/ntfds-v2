import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ntfds import create_app  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_settings_cache():
    from ntfds import settings
    settings._cache.update(t=0, v=None)


@pytest.fixture()
def app(tmp_path):
    app = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "MONITOR_ENABLED": False,
                      "TESTING": True, "API_TOKEN": ""})
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def engine(app):
    return app.extensions["ntfds_engine"]
