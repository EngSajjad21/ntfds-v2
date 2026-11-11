import time

from .config import DEFAULT_SETTINGS
from .extensions import db
from .models import Setting

_cache = {"t": 0, "v": None}


def get_settings(force=False):
    if not force and _cache["v"] is not None and time.time() - _cache["t"] < 10:
        return _cache["v"]
    vals = dict(DEFAULT_SETTINGS)
    for row in Setting.query.all():
        if row.key in vals:
            d = DEFAULT_SETTINGS[row.key]
            try:
                vals[row.key] = (row.value == "1") if isinstance(d, bool) else type(d)(row.value)
            except ValueError:
                pass
    _cache.update(t=time.time(), v=vals)
    return vals


def save_settings(data):
    errors = {}
    for key, default in DEFAULT_SETTINGS.items():
        if key not in data:
            continue
        v = data[key]
        try:
            v = bool(v) if isinstance(default, bool) else type(default)(v)
        except (TypeError, ValueError):
            errors[key] = "invalid"
            continue
        if not isinstance(default, bool) and v <= 0:
            errors[key] = "must be > 0"
            continue
        row = db.session.get(Setting, key) or Setting(key=key)
        row.value = ("1" if v else "0") if isinstance(default, bool) else str(v)
        db.session.add(row)
    if errors:
        db.session.rollback()
        return errors
    db.session.commit()
    get_settings(force=True)
    return {}
