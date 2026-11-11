"""Network Troubleshooting & Fault Detection System (NTFDS) v2."""
import logging
import os

from flask import Flask, render_template, request

from .config import Config
from .extensions import db, socketio

__version__ = "2.0.0"


def create_app(config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if config:
        app.config.update(config)

    db.init_app(app)
    # Same-origin websockets only, unless the operator opts in to more.
    origins = [o for o in os.getenv("NTFDS_CORS_ORIGINS", "").split(",") if o]
    socketio.init_app(app, cors_allowed_origins=origins or None, async_mode="threading")

    from . import diagnostics
    from .api import bp, metrics_bp
    from .engine import Engine
    from .models import ensure_schema
    from .security import check_token

    diagnostics.init_limits(app.config["TOOL_CONCURRENCY"])
    app.register_blueprint(bp, url_prefix="/api")
    app.register_blueprint(metrics_bp)

    with app.app_context():
        ensure_schema()

    engine = Engine(app)
    app.extensions["ntfds_engine"] = engine
    if app.config["MONITOR_ENABLED"]:
        engine.start()

    @app.get("/")
    def dashboard():
        return render_template("index.html", version=__version__, auth=bool(app.config["API_TOKEN"]), tile_url=app.config["TILE_URL"])

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")  # OSM blocks tile requests with no Referer
        if request.path.startswith("/api") or request.path == "/metrics":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @socketio.on("connect")
    def _ws_connect(auth):
        if app.config["API_TOKEN"]:
            tok = (auth or {}).get("token") if isinstance(auth, dict) else None
            if not check_token(tok):
                return False   # refuse the connection

    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    return app
