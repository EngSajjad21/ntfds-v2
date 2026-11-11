"""Entry point:  python app.py   (or: gunicorn -k gthread -w 1 --threads 8 'app:app')"""
from ntfds import create_app
from ntfds.extensions import socketio

app = create_app()

if __name__ == "__main__":
    c = app.config
    print(f"NTFDS listening on http://{c['HOST']}:{c['PORT']}  (auth {'ON' if c['API_TOKEN'] else 'OFF'})")
    socketio.run(app, host=c["HOST"], port=c["PORT"], debug=c["DEBUG"], use_reloader=False,
                 allow_unsafe_werkzeug=True)
