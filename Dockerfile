FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 NTFDS_HOST=0.0.0.0 DATABASE_URL=sqlite:////data/network_monitor.db
# ping / traceroute / ip are what the probes and diagnostics shell out to
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping traceroute iproute2 \
    && rm -rf /var/lib/apt/lists/* && useradd -r -u 10001 ntfds && mkdir /data && chown ntfds /data
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt gunicorn
COPY ntfds ./ntfds
COPY app.py .
USER ntfds
VOLUME /data
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=4s CMD python -c "import urllib.request as u;u.urlopen('http://127.0.0.1:5000/api/health',timeout=3)"
# One process on purpose: the monitoring engine and websocket hub live in-process.
CMD ["gunicorn", "-k", "gthread", "-w", "1", "--threads", "64", "-b", "0.0.0.0:5000", "--access-logfile", "-", "app:app"]
