# HONEYPOT // Threat Operations Center

A multi-sensor honeypot deployment combining **Cowrie** (SSH/Telnet) and **Dionaea** (malware/SMB/HTTP) with a real-time threat dashboard and pipeline engine.

## Architecture

| Component | Description |
|-----------|-------------|
| **Cowrie** | Medium-interaction SSH/Telnet honeypot recording attacker sessions |
| **Dionaea** | Low-interaction honeypot capturing malware payloads via SMB, HTTP, FTP, etc. |
| **Dashboard** | Real-time map, scorecards, session viewer, and geo-tracking |
| **Pipeline** | Python engine consuming logs from both honeypots, deduplicating attacks, and broadcasting live events via WebSocket |

## Pipeline Engine

- **Live mode** – reads real-time logs from Cowrie (JSON) and Dionaea (SQLite), deduplicates, and pushes events to the WebSocket dashboard
- **Simulation mode** – replays past events from the history databases
- Exposes an HTTP API on port `8765`

## Dashboard

- Real-time world map of attacker geo-locations (Leaflet + OpenStreetMap)
- Live scorecards (total attacks, unique IPs, blocked sessions, active threats)
- Session viewer with full command history replay
- Protocol breakdown charts

## Quick Start

```bash
# Activate environment
source env/bin/activate

# Start the pipeline (live mode)
python3 pipeline/server.py

# Open dashboard
open dashboard/index.html       # or serve with any HTTP server
```

## Configuration

Edit `config.json` to toggle between `live` and `simulation` modes:

```json
{"mode": "live"}
```

## Database

- `database/cowrie_history.db` – archived Cowrie sessions
- `database/dionaea_history.db` – archived Dionaea connections
- `database/dionaea_history.db-wal` – WAL journal
