# Network Troubleshooting & Fault Detection System (NTFDS) v2

NTFDS v2 is a self-hosted network monitoring and fault detection platform.
It provides real-time device checks, incident management, diagnostics, and SLA reporting.
The system supports ICMP, TCP, HTTP(S), DNS, discovery, dependency-aware analysis, and alerts.
It runs locally with Python or Docker and includes English/Arabic interfaces with offline-friendly assets.

<p align="center">
  <img src="screenshots/dashboard1.png" width="900" alt="NTFDS monitoring dashboard"><br>
  <img src="screenshots/dashboard2.png" width="900" alt="NTFDS dependency topology"><br>
  <img src="screenshots/dashboard3.png" width="900" alt="NTFDS incidents interface in Arabic and dark mode">
</p>

## Highlights

- Self-hosted and offline-first: no cloud account, external CDN, or mandatory third-party service.
- Multi-protocol monitoring for hosts, network devices, APIs, and services.
- Dependency-aware incident detection that distinguishes root failures from downstream impact.
- Built-in diagnostic tools, subnet discovery, live updates, charts, SLA reports, and alert integrations.
- English and Arabic interface support, including RTL layout and dark mode.
- Secure-by-default local binding, optional API authentication, input validation, and private-range scan protection.

## Feature list

### Monitoring

- **ICMP probes:** packet loss, latency, and jitter measured over repeated pings.
- **TCP probes:** verify that a host and port are reachable.
- **HTTP(S) probes:** inspect status codes, response latency, TLS expiry, and untrusted certificates.
- **DNS probes:** query a selected resolver through the built-in UDP client.
- Concurrent checks through a configurable worker pool.
- Per-device intervals, thresholds, enable/disable controls, and maintenance mode.
- TCP liveness fallback when the system does not provide a `ping` executable.

### Fault detection and incidents

- Debounced state changes requiring consecutive failures before declaring a device offline.
- Flapping detection to reduce alert storms caused by unstable links.
- Dependency-aware root-cause analysis: configure a parent device so downstream devices are marked **Unreachable** instead of generating duplicate alerts when the parent fails.
- Incident lifecycle management: **open → acknowledge → resolved**.
- Incident duration, downtime, MTTR, affected downstream device counts, and resolution tracking.
- Learned latency baselines and anomaly detection for sustained performance changes.
- Detection for high latency, packet loss, jitter, HTTP errors, TLS expiry, and service failures.

### Troubleshooting toolbox

- **Auto-diagnose workflow:** DNS → default gateway → Internet reference hosts → target ICMP → service check → traceroute.
- Diagnostic verdicts such as target down, local network failure, WAN/ISP outage, service down, degraded link, and ICMP blocked.
- On-demand ping, traceroute, DNS lookup, port scan with banners, HTTP probe, and diagnostic commands.
- CIDR network discovery using ICMP/TCP checks, reverse DNS, and ARP MAC lookup where available.
- Add discovered hosts to monitoring directly from the interface.

### Analytics and reporting

- Live time-series charts covering the last hour through the last 30 days.
- Uptime windows for 24 hours, 7 days, and 30 days.
- Minimum, average, P50, P95, and P99 latency statistics.
- Raw checks retained for 7 days by default, with hourly roll-ups retained for approximately 400 days to keep SQLite compact.
- SLA reports with uptime, incidents, MTTR, and downtime metrics.
- CSV export for SLA reports and CSV/JSON import and export for devices.
- Prometheus metrics at `/metrics`.
- REST API under `/api` and Socket.IO live updates for dashboard refreshes.

### Notifications

Alert channels include:

- Webhooks
- Slack
- Discord
- Telegram
- E-mail through SMTP

Alerts support severity filters, resolve notifications, and a test action so integrations can be verified before production use.

### User interface

- Monitoring dashboard with device status, incidents, latency, and availability.
- Interactive map using Leaflet, with an offline grid fallback when map tiles are unavailable.
- SVG dependency topology for understanding upstream and downstream impact.
- Dark and light themes.
- English and Arabic translations with RTL support.
- Toast messages and desktop notifications.
- All JavaScript and CSS dependencies are vendored locally; no CDN is required at runtime.

### Security and safe operation

- Optional API token for the UI, REST API, Prometheus endpoint, and websocket connection.
- Strict host, URL, and port validation; user input is never passed to a shell.
- HTML escaping in the interface and CSV formula-injection protection.
- Port scanning and discovery are restricted to private address ranges unless `NTFDS_ALLOW_PUBLIC_SCAN=1` is explicitly enabled.
- Concurrency limits for resource-intensive diagnostic tools.
- Default bind address is `127.0.0.1`, preventing accidental network exposure during local use.

## Quick start

### Python

```bash
python -m venv .venv
source .venv/bin/activate                 # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
python app.py                             # http://127.0.0.1:5000
```

Existing v1 databases are upgraded automatically; missing columns are added in place.

### Docker Compose

```bash
export NTFDS_API_TOKEN="change-me"
export SECRET_KEY="use-a-long-random-value"
docker compose up -d
```

Open `http://127.0.0.1:5000`. The Compose configuration persists application data in the `ntfds-data` volume and grants `NET_RAW` so unprivileged ICMP checks can run inside the container.

To monitor or scan the host's real LAN from Docker on Linux, use host networking as described in `docker-compose.yml` and remove the published `ports` mapping.

### Demo data

Create a sample database and start NTFDS without the background monitor:

```bash
python scripts/seed_demo.py demo.db
DATABASE_URL=sqlite:///$PWD/demo.db NTFDS_MONITOR=0 python app.py
```

Optional system tools improve diagnostics:

- Linux/macOS: `ping`, `traceroute` or `tracepath`
- Windows: `tracert`

## Configuration

Copy `.env.example` to `.env` or export the variables in your deployment environment. The most important settings are:

| Variable | Purpose | Default |
|---|---|---|
| `NTFDS_HOST` | Interface used by the web server | `127.0.0.1` |
| `NTFDS_PORT` | Web server port | `5000` |
| `NTFDS_API_TOKEN` | Token for UI/API/metrics/websocket authentication | Empty |
| `SECRET_KEY` | Application secret used by the web layer | Empty |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///network_monitor.db` |
| `NTFDS_MAX_WORKERS` | Maximum concurrent probes | `32` |
| `NTFDS_RAW_RETENTION_DAYS` | Retention for raw check rows | `7` |
| `NTFDS_ALLOW_PUBLIC_SCAN` | Allow discovery and scans outside private ranges | `0` |
| `NTFDS_REFERENCE_HOSTS` | Hosts used to distinguish LAN and ISP failures | `1.1.1.1,8.8.8.8` |
| `NTFDS_TILE_URL` | Map tile URL template | OpenStreetMap tile URL |

SMTP variables in `.env.example` configure e-mail alerts. In production, set a strong `SECRET_KEY`, protect the API with `NTFDS_API_TOKEN`, and use an appropriate tile provider or self-hosted tile server.

## API overview

| Endpoint | Description |
|---|---|
| `GET/POST /api/devices` | List or create devices |
| `PUT/DELETE /api/devices/<id>` | Update or remove a device |
| `POST /api/devices/<id>/check` | Run a check immediately |
| `POST /api/devices/<id>/diagnose` | Run automatic diagnosis |
| `GET /api/devices/<id>/metrics?range=24h` | Retrieve series, statistics, and uptime |
| `GET /api/incidents?status=open` | List incidents |
| `POST /api/incidents/<id>/ack` | Acknowledge an incident |
| `POST /api/tools/{ping,traceroute,dns,ports,http,diagnose}` | Run a troubleshooting tool |
| `POST /api/discovery` | Start subnet discovery |
| `GET /api/discovery/<job>` | Read discovery job status and results |
| `GET /api/reports/sla?days=30` | Generate an SLA report |
| `GET /api/reports/sla?days=30&format=csv` | Download an SLA report as CSV |
| `GET /metrics` | Prometheus metrics |

When authentication is enabled, send the token using either header:

```http
Authorization: Bearer <token>
```

or:

```http
X-API-Key: <token>
```

## Project layout

```text
app.py                 Application entry point
ntfds/engine.py        Scheduler, state machine, incidents, and roll-ups
ntfds/checks.py        ICMP, TCP, HTTP, and DNS probes
ntfds/diagnostics.py   Traceroute, scans, auto-diagnosis, and discovery
ntfds/api.py           REST API, websocket integration, and Prometheus endpoint
ntfds/alerts.py        Notification channels
ntfds/analytics.py     Uptime, time series, and SLA calculations
ntfds/templates/       Web interface templates
ntfds/static/          Frontend JavaScript, CSS, and vendored libraries
scripts/seed_demo.py   Demo database generator
tests/                 Pytest test suite
```

## Development and tests

Install development dependencies and run the test suite:

```bash
pip install -r requirements-dev.txt
pytest
```

The repository includes CI configuration under `.github/workflows/ci.yml`.

## Responsible use

Active tools such as port scanning, subnet discovery, traceroute, and service probing must only be used on networks and systems that you own or are explicitly authorized to test. Enable public-range scanning only when you understand and accept the operational and legal implications.

## License

NTFDS v2 is released under the GPL-3.0 license. See [LICENSE](LICENSE) for the full license text.
