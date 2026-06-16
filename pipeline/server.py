#!/usr/bin/env python3
"""
Honeypot Pipeline Engine - Dual Mode (Live / Simulation)
WebSocket broadcaster on :8765, HTTP API on :8765
"""

import asyncio
import json
import os
import re
import sqlite3
from datetime import datetime, timezone

import aiohttp
from aiohttp import web

CONFIG_PATH = "/opt/honeypot/config.json"
COWRIE_JSON = "/opt/honeypot/cowrie/var/log/cowrie/cowrie.json"
COWRIE_DB = "/opt/honeypot/database/cowrie_history.db"
DIONAEA_DB = "/opt/honeypot/database/dionaea_history.db"
WEB_TRAP_LOG = "/opt/honeypot/dashboard/web_trap.log"

CONFIG = {}
WEBSOCKET_CLIENTS = set()
EVENT_QUEUE = asyncio.Queue(maxsize=5000)

PUBLIC_PORT_MAP = {
    "ssh": 22,
    "telnet": 23,
    "SMB": 445,
    "MSSQL": 1433,
    "MySQL": 3306,
}


def load_config():
    global CONFIG
    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)
    return CONFIG


def iso_now():
    return datetime.now(timezone.utc).isoformat()


CLOUD_ASN_PATTERNS = [
    "DIGITALOCEAN", "AMAZON", "AWS", "GOOGLE", "GOOGLE-CLOUD", "MICROSOFT",
    "LINODE", "AKAMAI", "VULTR", "HETZNER", "OVH", "ALIBABA", "TENCENT",
    "CHINA TELECOM", "CHINANET", "CHINA UNICOM", "CHINA MOBILE",
    "QUADRANET", "BUYVM", "RAMNODE", "CHOOPA", "CONSTANT",
    "HOSTWINDS", "LEASEWEB", "ONLINE S.A.S", "SCALEWAY", "CLOUDFLARE",
]


def classify_ip(org_str):
    if not org_str:
        return ""
    org_upper = org_str.upper()
    for pat in CLOUD_ASN_PATTERNS:
        if pat in org_upper:
            return "CLOUD"
    tor_vpn_indicators = ["TOR", "VPN", "PROXY", "EXIT", "RELAY", "NORDVPN",
                           "EXPRESSVPN", "PROTONVPN", "MULLVAD", "HIDEMYASS",
                           "PIA", "PRIVATEINTERNETACCESS", "SURFSHARK", "CYBERGHOST"]
    for ind in tor_vpn_indicators:
        if ind in org_upper:
            return "TOR/VPN"
    return "RESIDENTIAL"


def store_text_payload(source, protocol, src_ip, payload_text):
    db_path = DIONAEA_DB if source == "dionaea" else DIONAEA_DB
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO malware_captures (timestamp, protocol, src_ip, md5, sha256, file_size, payload_path) VALUES (?,?,?,?,?,?,?)",
            (iso_now(), protocol, src_ip, "", "", len(payload_text), payload_text[:2048])
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def sanitize_credentials(username, password):
    combined = (username + " " + password).lower()
    if any(x in combined for x in ("get ", "post ", "options ", "put ", "delete ", "head ", "patch ",
                                     "http/1.1", "http/1.0", "http/2", "host:")):
        return False
    if any(x in combined for x in ("rtsp://", "cseq:", "rtsp/1.0")):
        return False
    if any(x in combined for x in ("*1", "$4", "\r", "\n")):
        if username.startswith("*") or username.startswith("$"):
            return False
    if "\\x" in combined:
        return False
    return True


# ─── Cowrie JSON tailing ────────────────────────────────────────────

def parse_cowrie_event(line_dict):
    eid = line_dict.get("eventid", "")
    src_ip = line_dict.get("src_ip", "0.0.0.0")
    raw_dst_port = line_dict.get("dst_port", 0)

    ALLOWED = (
        "cowrie.login.success",
        "cowrie.login.failed",
        "cowrie.command.input",
        "cowrie.command.failed",
    )
    has_download = "download" in eid.lower()
    if eid not in ALLOWED and not has_download:
        return None

    if eid in ("cowrie.login.success", "cowrie.login.failed"):
        protocol = "ssh"
        dst_port = 22
    elif eid in ("cowrie.command.input", "cowrie.command.failed"):
        protocol = "ssh"
        dst_port = 22
    elif raw_dst_port in (23, 2223):
        protocol = "telnet"
        dst_port = 23
    else:
        protocol = "ssh"
        dst_port = 22

    event = {
        "type": "cowrie",
        "source": "cowrie",
        "eventid": eid,
        "timestamp": line_dict.get("timestamp", iso_now()),
        "src_ip": src_ip,
        "src_port": line_dict.get("src_port", 0),
        "dst_port": dst_port,
        "session": line_dict.get("session", ""),
        "protocol": protocol,
    }

    if eid == "cowrie.login.success":
        u = line_dict.get("username", "")
        p = line_dict.get("password", "")
        if not p:
            return None
        if not sanitize_credentials(u, p):
            event["username"] = ""
            event["password"] = ""
            event["auth_event"] = "filtered"
        else:
            event["username"] = u
            event["password"] = p
            event["auth_event"] = "success"
    elif eid == "cowrie.login.failed":
        u = line_dict.get("username", "")
        p = line_dict.get("password", "")
        has_key = bool(line_dict.get("key", ""))
        if not p and not has_key:
            return None
        if not sanitize_credentials(u, p):
            event["username"] = ""
            event["password"] = ""
            event["auth_event"] = "filtered"
        else:
            event["username"] = u
            event["password"] = p
            event["auth_event"] = "failed"
        if has_key:
            event["auth_method"] = line_dict.get("type", "pubkey")
            event["fingerprint"] = line_dict.get("fingerprint", "")
    elif eid == "cowrie.command.input":
        event["command"] = line_dict.get("input", "")
    elif eid == "cowrie.command.failed":
        event["command"] = line_dict.get("input", "")
        event["failed"] = True
    elif eid == "cowrie.client.kex":
        event["hassh"] = line_dict.get("hassh", "")
    elif eid == "cowrie.client.version":
        event["client_version"] = line_dict.get("version", "")
    if "download" in eid.lower():
        event["url"] = line_dict.get("url", "")
        event["shasum"] = line_dict.get("shasum", "")

    return event


# ─── Dionaea SQLite polling ─────────────────────────────────────────

_MSSQL_DEDUP = set()


def normalize_dionaea_port(protocol, internal_port):
    m = PUBLIC_PORT_MAP.get(protocol)
    if m: return m
    return internal_port


def get_dionaea_last_id(conn):
    cur = conn.execute("SELECT MAX(id) FROM connections")
    row = cur.fetchone()
    return row[0] or 0


def query_dionaea_new(conn, last_id):
    _MSSQL_DEDUP.clear()
    cur = conn.execute(
        "SELECT id, timestamp, protocol, src_ip, src_port, dst_port, payload_hex, payload_size FROM connections WHERE id > ? ORDER BY id ASC",
        (last_id,)
    )
    rows = cur.fetchall()
    new_max = last_id
    events = []
    for r in rows:
        new_max = r[0]
        proto = r[2]
        dst = normalize_dionaea_port(proto, r[5])
        payload = r[6] or ""
        payload_size = r[7] or 0
        src_ip = r[3]
        internal_dst = r[5]
        if payload_size == 0 or len(payload) < 4:
            continue
        if internal_dst in (33306, 14433):
            plow = payload[:6].lower()
            if plow.startswith("474554") or plow.startswith("160301"):
                continue
        if proto == "MSSQL" and payload_size < 128:
            dedup_key = (src_ip, payload[:24])
            if dedup_key in _MSSQL_DEDUP:
                continue
            _MSSQL_DEDUP.add(dedup_key)
            if len(_MSSQL_DEDUP) > 2000:
                _MSSQL_DEDUP.clear()
        events.append({
            "type": "dionaea", "source": "dionaea",
            "id": r[0], "timestamp": r[1], "protocol": proto,
            "src_ip": src_ip, "src_port": r[4], "dst_port": dst,
            "payload_hex": payload[:128], "payload_size": payload_size,
            "ip_tag": "",
        })
        if payload and len(payload) > 2:
            try:
                text = bytes.fromhex(payload).decode("ascii", errors="replace")
                if any(c.isprintable() for c in text) and len(text.strip()) > 1:
                    store_text_payload("dionaea", proto, src_ip, text[:512])
            except Exception:
                pass
    return events, new_max


# ─── Web Trap log tailing ───────────────────────────────────────────

WEB_TRAP_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*) HTTP[^"]*" (\d+) (\d+) "([^"]*)" "([^"]*)"'
    r'(?: ssl_proto=(\S+))?(?: ssl_cipher=(\S+))?'
)

TLS_PROBE_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] ".*(\\x16\\x03\\x0[0-9a-fA-F]).*" 400'
)

EXPLOIT_PATTERNS = re.compile(
    r'(\$?\{jndi:(ldap|rmi|dns|ldaps)://'
    r'|\.\.[/%]|%2e%2e[%2f/]|%252e%252e'
    r'|/etc/(passwd|shadow|hosts)'
    r'|/bin/(sh|bash)|/usr/bin/'
    r'|\b(curl|wget)\s+'
    r'|\bchmod\s+\+|whoami\b|\bid\b'
    r'|\b(cmd|powershell)\.exe'
    r'|\bcat\s+/etc/|\buname\s+-a)',
    re.IGNORECASE
)

ENTERPRISE_PATH_RE = re.compile(
    r'^/(tmui|remote/(login|fct_download|portal)'
    r'|clients/Logon|csLogon|POST/General'
    r'|\+CSCOE\+|global-protect|ssl-vpn'
    r'|dana-na|api/v1/totp|vpn/|logon/)',
    re.IGNORECASE
)


def parse_web_trap_line(line):
    stripped = line.strip()
    tls_match = TLS_PROBE_RE.match(stripped)
    if tls_match:
        ts = tls_match.group(2)
        try:
            import datetime as _dt
            ts = _dt.datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").isoformat()
        except Exception:
            pass
        return {
            "type": "web_trap", "source": "nginx", "timestamp": ts,
            "src_ip": tls_match.group(1), "method": "TLS-PROBE",
            "path": "HTTPS Probe / TLS Client Hello on Plain HTTP (400 Bad Request)",
            "user_agent": "TLS-Handshake", "dst_port": 80,
            "tls_probe": True, "ip_tag": "",
        }
    m = WEB_TRAP_RE.match(stripped)
    if not m:
        ip = "unknown"; ts = iso_now(); method = "UNKNOWN"; raw_request = stripped[:512]
        pm = re.match(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)"', stripped)
        if pm:
            ip = pm.group(1)
            try:
                import datetime as _dt
                ts = _dt.datetime.strptime(pm.group(2), "%d/%b/%Y:%H:%M:%S %z").isoformat()
            except Exception:
                pass
            req = pm.group(3).strip()
            if req and req not in ("-", ""):
                method = req.split(" ")[0][:32] if " " in req else req[:32]
                raw_request = req[:256]
        if any(x in raw_request.upper() for x in ("MGLNDD_", "ZGX_", "MASSCAN")):
            return None
        return {"type": "web_trap", "source": "nginx", "timestamp": ts, "src_ip": ip, "method": method, "path": raw_request, "user_agent": "", "dst_port": 80}
    raw_ts = m.group(2)
    try:
        import datetime as _dt
        parsed = _dt.datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S %z")
        iso_ts = parsed.isoformat()
    except Exception:
        iso_ts = raw_ts
    method = m.group(3); path = m.group(4); referer = m.group(7)
    body_size = int(m.group(6)); user_agent = m.group(8)
    if path == "/" and "?" not in path:
        if method in ("GET", "POST", "OPTIONS", "HEAD", "PROPFIND"):
            return None
    if path:
        path_upper = path.upper()
        if any(x in path_upper for x in ("MGLNDD_", "ZGX_", "NMASCAN", "MASSCAN")):
            return None
    if user_agent:
        if any(x in user_agent.upper() for x in ("MGLNDD_", "ZGX_", "NMASCAN", "MASSCAN", "ZGSCAN")):
            return None
    if not path or path == "*" or method == "PRI":
        return None
    if ENTERPRISE_PATH_RE.match(path):
        query_string = path.split("?", 1)[1] if "?" in path else ""
        from urllib.parse import unquote
        decoded = unquote(f"{path} {query_string} {user_agent}")
        if not EXPLOIT_PATTERNS.search(decoded):
            return None
    return {
        "type": "web_trap", "source": "nginx", "timestamp": iso_ts,
        "ts_raw": raw_ts, "src_ip": m.group(1), "method": method,
        "path": path, "status": int(m.group(5)), "body_size": body_size,
        "referer": referer, "user_agent": m.group(8), "dst_port": 80,
        "ssl_protocol": m.group(9) or "", "ssl_cipher": m.group(10) or "",
        "ip_tag": "",
    }


# ─── WebSocket Server ──────────────────────────────────────────────

async def ws_handler(request):
    ws = web.WebSocketResponse(max_msg_size=1024 * 1024, heartbeat=15.0)
    await ws.prepare(request)
    WEBSOCKET_CLIENTS.add(ws)
    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                pass
            elif msg.type == aiohttp.WSMsgType.ERROR:
                break
    finally:
        WEBSOCKET_CLIENTS.discard(ws)
    return ws


async def broadcast_event(event):
    payload = json.dumps(event, default=str)
    dead = set()
    for ws in WEBSOCKET_CLIENTS:
        try:
            await ws.send_str(payload)
        except Exception:
            dead.add(ws)
    for ws in dead:
        WEBSOCKET_CLIENTS.discard(ws)


# ─── HTTP API Router ───────────────────────────────────────────────

def get_time_filter(range_param):
    return "-1 day"


async def api_stats(request):
    range_param = request.query.get("range", "7d")
    time_filter = get_time_filter(range_param)

    stats = {
        "range": range_param,
        "top_credentials": [],
        "hourly_trends": [],
        "protocol_distribution": {},
        "malware_hashes": [],
        "total_connections": 0,
        "unique_ips": set(),
        "web_exploits": 0,
        "port_breakdown": {},
    }

    if os.path.exists(COWRIE_DB):
        try:
            conn = sqlite3.connect(COWRIE_DB)
            conn.row_factory = sqlite3.Row

            try:
                cur = conn.execute(
                    f"SELECT username, password, COUNT(*) as cnt FROM auth WHERE timestamp > datetime('now','{time_filter}') GROUP BY username, password ORDER BY cnt DESC LIMIT 10"
                )
                rows = cur.fetchall()
                if rows:
                    stats["top_credentials"] = [
                        {"username": r["username"], "password": r["password"], "count": r["cnt"]}
                        for r in rows if sanitize_credentials(r["username"] or "", r["password"] or "")
                    ]
            except Exception:
                pass

            if os.path.exists(COWRIE_JSON):
                creds = {}
                for c in stats.get("top_credentials", []):
                    creds[c["username"] + ":" + c["password"]] = c["count"]
                try:
                    with open(COWRIE_JSON) as jf:
                        for line in jf:
                            if '"eventid":"cowrie.login.success"' in line or '"eventid":"cowrie.login.failed"' in line:
                                try:
                                    obj = json.loads(line)
                                    u = obj.get("username", "")
                                    p = obj.get("password", "")
                                    if u and p and sanitize_credentials(u, p):
                                        k = u + ":" + p
                                        creds[k] = creds.get(k, 0) + 1
                                except json.JSONDecodeError:
                                    pass
                    stats["top_credentials"] = sorted(
                        [{"username": k.split(":")[0], "password": k.split(":")[1], "count": v} for k, v in creds.items()],
                        key=lambda x: x["count"], reverse=True
                    )[:10]
                except Exception:
                    pass

            try:
                ssh_cnt = 0
                telnet_cnt = 0
                if os.path.exists(COWRIE_JSON):
                    try:
                        with open(COWRIE_JSON) as jf:
                            for line in jf:
                                line = line.strip()
                                if not line or not line.startswith("{"):
                                    continue
                                if '"eventid":"cowrie.login.success"' in line or '"eventid":"cowrie.login.failed"' in line:
                                    try:
                                        obj = json.loads(line)
                                        proto = obj.get("protocol", "")
                                        if proto == "telnet":
                                            telnet_cnt += 1
                                        else:
                                            ssh_cnt += 1
                                    except json.JSONDecodeError:
                                        pass
                                elif '"eventid":"cowrie.command.input"' in line or '"eventid":"cowrie.command.failed"' in line:
                                    try:
                                        obj = json.loads(line)
                                        proto = obj.get("protocol", "")
                                        if proto == "telnet":
                                            telnet_cnt += 1
                                        else:
                                            ssh_cnt += 1
                                    except json.JSONDecodeError:
                                        pass
                    except Exception:
                        pass
                if ssh_cnt:
                    stats["port_breakdown"]["22 (SSH)"] = ssh_cnt
                    stats["total_connections"] += ssh_cnt
                    stats["protocol_distribution"]["SSH"] = ssh_cnt
                if telnet_cnt:
                    stats["port_breakdown"]["23 (TELNET)"] = telnet_cnt
                    stats["total_connections"] += telnet_cnt
                    stats["protocol_distribution"]["TELNET"] = telnet_cnt

                # Supplement with DB auth count (more complete than JSON alone)
                try:
                    cur = conn.execute(
                        f"SELECT COUNT(*) as cnt FROM auth WHERE timestamp > datetime('now','{time_filter}')"
                    )
                    r = cur.fetchone()
                    if r and r["cnt"]:
                        db_auth = r["cnt"]
                        stats["total_connections"] += db_auth
                        if stats["port_breakdown"].get("22 (SSH)", 0) < db_auth:
                            stats["port_breakdown"]["22 (SSH)"] = max(stats["port_breakdown"].get("22 (SSH)", 0), db_auth)
                            stats["protocol_distribution"]["SSH"] = max(stats["protocol_distribution"].get("SSH", 0), db_auth)
                except Exception:
                    pass
            except Exception:
                pass

            try:
                cur = conn.execute(
                    f"SELECT ip, COUNT(*) as cnt FROM auth WHERE timestamp > datetime('now','{time_filter}') GROUP BY ip"
                )
                for r in cur.fetchall():
                    stats["unique_ips"].add(r["ip"])
            except Exception:
                pass

            conn.close()
        except Exception:
            pass

    if os.path.exists(DIONAEA_DB):
        try:
            conn = sqlite3.connect(DIONAEA_DB)
            conn.row_factory = sqlite3.Row
            try:
                cur = conn.execute(
                    f"SELECT protocol, COUNT(*) as cnt FROM connections WHERE timestamp > datetime('now','{time_filter}') AND payload_size > 0 AND length(payload_hex) >= 4 AND NOT (dst_port IN (33306, 14433) AND (lower(substr(payload_hex,1,6)) = '474554' OR lower(substr(payload_hex,1,6)) = '160301')) GROUP BY protocol"
                )
                for r in cur.fetchall():
                    proto = r["protocol"]
                    port_key = f"{PUBLIC_PORT_MAP.get(proto, 0)} ({proto})"
                    stats["protocol_distribution"][proto] = r["cnt"]
                    stats["port_breakdown"][port_key] = r["cnt"]
                    stats["total_connections"] += r["cnt"]
            except Exception:
                pass
            conn.close()
        except Exception:
            pass

    try:
        if os.path.exists(WEB_TRAP_LOG):
            filtered_lines = []
            with open(WEB_TRAP_LOG) as f:
                for l in f:
                    l = l.strip()
                    if not l:
                        continue
                    ev = parse_web_trap_line(l)
                    if ev is not None:
                        filtered_lines.append(ev)
                        stats["unique_ips"].add(ev.get("src_ip", ""))
            stats["web_exploits"] = len(filtered_lines)
            stats["port_breakdown"]["80 (HTTP)"] = len(filtered_lines)
            stats["total_connections"] += len(filtered_lines)
    except Exception:
        stats["web_exploits"] = 0

    stats["unique_ips"] = sorted(list(stats["unique_ips"]))

    return web.json_response(stats)


async def api_events(request):
    limit = int(request.query.get("limit", 50))
    range_param = request.query.get("range", "7d")
    time_filter = get_time_filter(range_param)
    events = []

    for db_path in [COWRIE_DB, DIONAEA_DB]:
        if not os.path.exists(db_path):
            continue
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            if "cowrie" in db_path:
                cur = conn.execute(
                    f"SELECT * FROM auth WHERE timestamp > datetime('now','{time_filter}') ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                )
                for r in cur.fetchall():
                    events.append({"source": "cowrie", "table": "auth", "data": dict(r)})
            else:
                cur = conn.execute(
                    f"SELECT * FROM connections WHERE timestamp > datetime('now','{time_filter}') ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                )
                for r in cur.fetchall():
                    events.append({"source": "dionaea", "table": "connections", "data": dict(r)})
            conn.close()
        except Exception:
            pass
    return web.json_response(events[:limit])


async def api_recent(request):
    range_param = request.query.get("range", "7d")
    limit = int(request.query.get("limit", 100000))
    time_filter = get_time_filter(range_param)
    per_source = max(limit, 500)
    events = []

    if os.path.exists(COWRIE_JSON):
        try:
            with open(COWRIE_JSON) as f:
                for line in f:
                    line = line.strip()
                    if not line or not line.startswith("{"):
                        continue
                    try:
                        obj = json.loads(line)
                        ev = parse_cowrie_event(obj)
                        if ev is not None:
                            events.append(ev)
                    except (json.JSONDecodeError, KeyError):
                        pass
        except Exception:
            pass

    # Supplement with cowrie SQLite DB
    if os.path.exists(COWRIE_DB):
        try:
            existing_keys = set()
            for e in events:
                if e.get("source") == "cowrie":
                    existing_keys.add((e.get("session", ""), e.get("eventid", "")))
            conn = sqlite3.connect(COWRIE_DB)
            conn.row_factory = sqlite3.Row
            for r in conn.execute(
                "SELECT a.session, a.success, a.username, a.password, a.timestamp, s.ip FROM auth a JOIN sessions s ON a.session = s.id WHERE a.timestamp > datetime('now',?) ORDER BY a.timestamp DESC LIMIT ?",
                (time_filter, per_source)
            ).fetchall():
                eid = "cowrie.login.success" if r["success"] else "cowrie.login.failed"
                key = (r["session"], eid)
                if key not in existing_keys:
                    existing_keys.add(key)
                    events.append({
                        "type": "cowrie", "source": "cowrie",
                        "eventid": eid, "timestamp": r["timestamp"],
                        "src_ip": r["ip"] or "0.0.0.0", "src_port": 0,
                        "dst_port": 22, "session": r["session"],
                        "protocol": "ssh", "username": r["username"] or "",
                        "password": r["password"] or "",
                        "auth_event": "success" if r["success"] else "failed",
                    })
            for r in conn.execute(
                "SELECT i.session, i.timestamp, i.input, s.ip FROM input i JOIN sessions s ON i.session = s.id WHERE i.timestamp > datetime('now',?) ORDER BY i.timestamp DESC LIMIT ?",
                (time_filter, per_source)
            ).fetchall():
                key = (r["session"], "cowrie.command.input")
                if key not in existing_keys:
                    existing_keys.add(key)
                    events.append({
                        "type": "cowrie", "source": "cowrie",
                        "eventid": "cowrie.command.input", "timestamp": r["timestamp"],
                        "src_ip": r["ip"] or "0.0.0.0", "src_port": 0,
                        "dst_port": 22, "session": r["session"],
                        "protocol": "ssh", "command": (r["input"] or ""),
                    })
            conn.close()
        except Exception:
            pass


    if os.path.exists(DIONAEA_DB):
        try:
            conn = sqlite3.connect(DIONAEA_DB)
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                f"SELECT id, timestamp, protocol, src_ip, src_port, dst_port, payload_hex, payload_size FROM connections WHERE timestamp > datetime('now','{time_filter}') ORDER BY id DESC LIMIT ?",
                (per_source,)
            )
            for r in cur.fetchall():
                proto = r[2]
                dst = normalize_dionaea_port(proto, r[5])
                psize = r[7] or 0
                phex = r[6] or ""
                src_ip = r[3]
                internal_dst = r[5]
                # ── High-signal CTI filter: skip empty-payload connections ──
                if psize == 0 or len(phex) < 4:
                    continue
                # ── Cross-protocol filter: drop HTTP/TLS on DB ports ──
                if internal_dst in (33306, 14433):
                    plow = phex[:6].lower()
                    if plow.startswith("474554") or plow.startswith("160301"):
                        continue
                # ── MSSQL handshake dedup ──
                if proto == "MSSQL" and psize < 128:
                    dedup_key = (src_ip, phex[:24])
                    if dedup_key in _MSSQL_DEDUP:
                        continue
                    _MSSQL_DEDUP.add(dedup_key)
                    if len(_MSSQL_DEDUP) > 2000:
                        _MSSQL_DEDUP.clear()
                events.append({
                    "type": "dionaea",
                    "source": "dionaea",
                    "id": r[0],
                    "timestamp": r[1],
                    "protocol": proto,
                    "src_ip": r[3],
                    "src_port": r[4],
                    "dst_port": dst,
                    "payload_hex": phex[:128],
                    "payload_size": psize,
                })
            conn.close()
        except Exception:
            pass

    if os.path.exists(WEB_TRAP_LOG):
        try:
            with open(WEB_TRAP_LOG) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    ev = parse_web_trap_line(line)
                    if ev is not None:
                        events.append(ev)
        except Exception:
            pass

    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    # Per-source fairness: proportional for small limits, cap each source at 1000 for bulk
    per = max(limit // 3, 100) if limit <= 500 else min(limit, 1000)
    cowrie_events = [e for e in events if e.get("source") == "cowrie"][:per]
    dionaea_events = [e for e in events if e.get("source") == "dionaea"][:per]
    nginx_events = [e for e in events if e.get("source") == "nginx"][:per]
    merged = cowrie_events + dionaea_events + nginx_events
    merged.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return web.json_response(merged[:limit])


async def api_event_details(request):
    source = request.query.get("source", "")
    ev_id = request.query.get("id", "")
    session = request.query.get("session", "")
    ip = request.query.get("ip", "")
    ts = request.query.get("ts", "")

    result = {"source": source, "details": {}}

    if source == "dionaea" and ev_id:
        if os.path.exists(DIONAEA_DB):
            try:
                conn = sqlite3.connect(DIONAEA_DB)
                conn.row_factory = sqlite3.Row
                cur = conn.execute("SELECT * FROM connections WHERE id = ?", (int(ev_id),))
                row = cur.fetchone()
                if row:
                    d = dict(row)
                    result["details"] = {
                        "id": d["id"],
                        "timestamp": d["timestamp"],
                        "protocol": d["protocol"],
                        "src_ip": d["src_ip"],
                        "src_port": d["src_port"],
                        "dst_port": d["dst_port"],
                        "payload_hex": d["payload_hex"] or "",
                        "payload_size": d["payload_size"],
                    }
                conn.close()
            except Exception:
                pass

    elif source == "cowrie" and session:
        result["details"]["session"] = session
        result["details"]["auth_attempts"] = []
        result["details"]["commands"] = []
        result["details"]["connection"] = {}

        if os.path.exists(COWRIE_JSON):
            try:
                with open(COWRIE_JSON) as f:
                    for line in f:
                        line = line.strip()
                        if not line or not line.startswith("{"):
                            continue
                        try:
                            obj = json.loads(line)
                            if obj.get("session") != session:
                                continue
                            eid = obj.get("eventid", "")
                            if eid == "cowrie.session.connect":
                                result["details"]["connection"] = {
                                    "src_ip": obj.get("src_ip", ""),
                                    "dst_port": obj.get("dst_port", 0),
                                    "protocol": obj.get("protocol", ""),
                                    "timestamp": obj.get("timestamp", ""),
                                    "message": obj.get("message", ""),
                                }
                            elif eid == "cowrie.login.failed":
                                result["details"]["auth_attempts"].append({
                                    "username": obj.get("username", ""),
                                    "password": obj.get("password", ""),
                                    "result": "failed",
                                    "timestamp": obj.get("timestamp", ""),
                                })
                            elif eid == "cowrie.login.success":
                                result["details"]["auth_attempts"].append({
                                    "username": obj.get("username", ""),
                                    "password": obj.get("password", ""),
                                    "result": "success",
                                    "timestamp": obj.get("timestamp", ""),
                                })
                            elif eid == "cowrie.command.input":
                                result["details"]["commands"].append({
                                    "input": obj.get("input", ""),
                                    "timestamp": obj.get("timestamp", ""),
                                })
                            elif eid == "cowrie.client.version":
                                result["details"]["client_version"] = obj.get("version", "")
                            elif eid == "cowrie.client.kex":
                                result["details"]["hassh"] = obj.get("hassh", "")
                            elif eid == "cowrie.session.closed":
                                result["details"]["duration"] = obj.get("duration", "")
                        except (json.JSONDecodeError, KeyError):
                            pass
            except Exception:
                pass

    elif source == "nginx" and ip and ts:
        result["details"]["src_ip"] = ip
        result["details"]["headers"] = {}
        result["details"]["raw"] = ""
        if os.path.exists(WEB_TRAP_LOG):
            try:
                found_line = None
                ts_clean = ts.replace("-", "/").replace("T", ":").replace(" ", ":")
                with open(WEB_TRAP_LOG) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        if ip in line and ts_clean[:13] in line:
                            found_line = line
                            break
                if not found_line:
                    with open(WEB_TRAP_LOG) as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            if ip in line:
                                found_line = line
                                break
                if found_line:
                    result["details"]["raw"] = found_line
                    m = WEB_TRAP_RE.match(found_line)
                    if m:
                        result["details"]["src_ip"] = m.group(1)
                        result["details"]["timestamp"] = m.group(2)
                        result["details"]["method"] = m.group(3)
                        result["details"]["path"] = m.group(4)
                        result["details"]["referer"] = m.group(5)
                        result["details"]["user_agent"] = m.group(6)
                        result["details"]["headers"] = {
                            "Method": m.group(3),
                            "Path": m.group(4),
                            "Referer": m.group(5),
                            "User-Agent": m.group(6),
                        }
            except Exception:
                pass

    return web.json_response(result)


async def api_system(request):
    result = {"cpu": 0.0, "mem_pct": 0.0, "mem_used": 0, "mem_total": 0, "load": [0,0,0]}
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().strip().split()
            result["load"] = [float(parts[0]), float(parts[1]), float(parts[2])]
            result["cpu"] = round(result["load"][0] * 100 / os.cpu_count(), 1) if os.cpu_count() else round(result["load"][0], 1)
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    meminfo[k.strip()] = int(v.strip().split()[0])
            total = meminfo.get("MemTotal", 0)
            available = meminfo.get("MemAvailable", 0)
            if total:
                result["mem_total"] = total
                result["mem_used"] = total - available
                result["mem_pct"] = round((total - available) / total * 100, 1)
    except Exception:
        pass
    return web.json_response(result)


async def api_asn_details(request):
    asn = request.query.get("asn", "")
    if not asn:
        return web.json_response({"error": "missing asn param"}, status=400)

    result = {"asn": asn, "ips": set(), "countries": {}, "protocols": {}, "total_hits": 0}

    asn_clean = asn.lstrip("AS").strip()

    if os.path.exists(DIONAEA_DB):
        try:
            conn = sqlite3.connect(DIONAEA_DB)
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT src_ip, protocol, COUNT(*) as cnt FROM connections WHERE src_ip IS NOT NULL AND src_ip != '' GROUP BY src_ip, protocol"
            )
            for r in cur.fetchall():
                ip_name = r["src_ip"]
                try:
                    import urllib.request
                    url = f"http://ip-api.com/json/{ip_name}?fields=as,countryCode"
                    req = urllib.request.Request(url, headers={"User-Agent": "honeypot/1.0"})
                    with urllib.request.urlopen(req, timeout=2) as resp:
                        data = json.loads(resp.read().decode())
                        if asn_clean in (data.get("as") or ""):
                            result["ips"].add(ip_name)
                            cc = data.get("countryCode", "??")
                            result["countries"][cc] = result["countries"].get(cc, 0) + r["cnt"]
                            result["protocols"][r["protocol"]] = result["protocols"].get(r["protocol"], 0) + r["cnt"]
                            result["total_hits"] += r["cnt"]
                except Exception:
                    continue
            conn.close()
        except Exception:
            pass

    if os.path.exists(COWRIE_DB):
        try:
            conn = sqlite3.connect(COWRIE_DB)
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT DISTINCT ip, COUNT(*) as cnt FROM auth WHERE ip IS NOT NULL AND ip != '' GROUP BY ip"
            )
            for r in cur.fetchall():
                ip_name = r["ip"]
                try:
                    import urllib.request
                    url = f"http://ip-api.com/json/{ip_name}?fields=as,countryCode"
                    req = urllib.request.Request(url, headers={"User-Agent": "honeypot/1.0"})
                    with urllib.request.urlopen(req, timeout=2) as resp:
                        data = json.loads(resp.read().decode())
                        if asn_clean in (data.get("as") or ""):
                            result["ips"].add(ip_name)
                            cc = data.get("countryCode", "??")
                            result["countries"][cc] = result["countries"].get(cc, 0) + r["cnt"]
                            result["protocols"]["SSH/TELNET"] = result["protocols"].get("SSH/TELNET", 0) + r["cnt"]
                            result["total_hits"] += r["cnt"]
                except Exception:
                    continue
            conn.close()
        except Exception:
            pass

    result["ips"] = sorted(list(result["ips"]))
    return web.json_response(result)


async def api_historical(request):
    range_param = request.query.get("range", "7d")
    time_filter = get_time_filter(range_param)
    ips = set()

    if os.path.exists(COWRIE_DB):
        try:
            conn = sqlite3.connect(COWRIE_DB)
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                f"SELECT DISTINCT ip, COUNT(*) as cnt FROM auth WHERE timestamp > datetime('now','{time_filter}') AND ip IS NOT NULL AND ip != '' GROUP BY ip"
            )
            for r in cur.fetchall():
                ips.add((r["ip"], "SSH", r["cnt"]))
            conn.close()
        except Exception:
            pass

    # Supplement with JSON SSH/TELNET IPs (more complete than DB)
    if os.path.exists(COWRIE_JSON):
        try:
            with open(COWRIE_JSON) as jf:
                for line in jf:
                    line = line.strip()
                    if not line or not line.startswith("{"):
                        continue
                    if '"eventid":"cowrie.login.success"' in line or '"eventid":"cowrie.login.failed"' in line:
                        try:
                            obj = json.loads(line)
                            ip = obj.get("src_ip", "")
                            proto = obj.get("protocol", "ssh").upper()
                            if ip:
                                ips.add((ip, proto, 1))
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass

    if os.path.exists(DIONAEA_DB):
        try:
            conn = sqlite3.connect(DIONAEA_DB)
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                f"SELECT DISTINCT src_ip, protocol, COUNT(*) as cnt FROM connections WHERE timestamp > datetime('now','{time_filter}') AND src_ip IS NOT NULL AND src_ip != '' GROUP BY src_ip, protocol"
            )
            for r in cur.fetchall():
                ips.add((r["src_ip"], r["protocol"], r["cnt"]))
            conn.close()
        except Exception:
            pass

    if os.path.exists(WEB_TRAP_LOG):
        try:
            with open(WEB_TRAP_LOG) as f:
                for line in f:
                    m = WEB_TRAP_RE.match(line.strip())
                    if m:
                        ips.add((m.group(1), "HTTP", 1))
        except Exception:
            pass

    result = []
    for ip, proto, cnt in ips:
        result.append({"ip": ip, "protocol": proto, "count": cnt})
    result.sort(key=lambda x: x["count"], reverse=True)
    return web.json_response(result[:1000])


# ─── LIVE MODE ─────────────────────────────────────────────────────

async def tail_cowrie_json():
    if not os.path.exists(COWRIE_JSON):
        return
    f = open(COWRIE_JSON, "r")
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            await asyncio.sleep(0.5)
            continue
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            event = parse_cowrie_event(obj)
            if event is not None:
                await EVENT_QUEUE.put(event)
        except (json.JSONDecodeError, KeyError):
            pass


async def poll_dionaea():
    if not os.path.exists(DIONAEA_DB):
        return
    conn = sqlite3.connect(DIONAEA_DB)
    last_id = get_dionaea_last_id(conn)
    while True:
        await asyncio.sleep(5)
        try:
            new_events, last_id = query_dionaea_new(conn, last_id)
            for ev in new_events:
                await EVENT_QUEUE.put(ev)
        except Exception:
            try:
                conn = sqlite3.connect(DIONAEA_DB)
                last_id = get_dionaea_last_id(conn)
            except Exception:
                pass


async def tail_web_trap():
    if not os.path.exists(WEB_TRAP_LOG):
        return
    f = open(WEB_TRAP_LOG, "r")
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            await asyncio.sleep(0.5)
            continue
        line = line.strip()
        if not line:
            continue
        event = parse_web_trap_line(line)
        if event is not None:
            await EVENT_QUEUE.put(event)


async def broadcast_worker():
    while True:
        event = await EVENT_QUEUE.get()
        await broadcast_event(event)
        EVENT_QUEUE.task_done()


async def live_mode():
    tasks = [
        asyncio.create_task(tail_cowrie_json()),
        asyncio.create_task(poll_dionaea()),
        asyncio.create_task(tail_web_trap()),
        asyncio.create_task(broadcast_worker()),
    ]
    await asyncio.gather(*tasks)


# ─── SIMULATION MODE ────────────────────────────────────────────────

def load_all_events():
    events = []

    if os.path.exists(COWRIE_DB):
        try:
            conn = sqlite3.connect(COWRIE_DB)
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT * FROM auth ORDER BY timestamp ASC")
            for r in cur.fetchall():
                d = dict(r)
                events.append({
                    "type": "cowrie",
                    "source": "cowrie",
                    "timestamp": d.get("timestamp", ""),
                    "eventid": d.get("event", "cowrie.login.failed"),
                    "src_ip": d.get("ip", "0.0.0.0"),
                    "protocol": "ssh",
                    "dst_port": 22,
                    "username": d.get("username", ""),
                    "password": d.get("password", ""),
                    "auth_event": "failed",
                })
            cur = conn.execute("SELECT * FROM sessions ORDER BY starttime ASC")
            for r in cur.fetchall():
                d = dict(r)
                events.append({
                    "type": "cowrie",
                    "source": "cowrie",
                    "timestamp": d.get("starttime", ""),
                    "eventid": "cowrie.session.connect",
                    "src_ip": d.get("ip", "0.0.0.0"),
                    "protocol": "ssh",
                    "dst_port": 22,
                    "session": d.get("id", ""),
                })
            conn.close()
        except Exception:
            pass

    if os.path.exists(DIONAEA_DB):
        try:
            conn = sqlite3.connect(DIONAEA_DB)
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT * FROM connections ORDER BY timestamp ASC")
            for r in cur.fetchall():
                d = dict(r)
                proto = d.get("protocol", "")
                psize = d.get("payload_size", 0)
                phex = d.get("payload_hex", "")
                if psize == 0 or len(phex) < 4:
                    continue
                src_ip = d.get("src_ip", "")
                internal_dst = d.get("dst_port", 0)
                if internal_dst in (33306, 14433):
                    plow = phex[:6].lower()
                    if plow.startswith("474554") or plow.startswith("160301"):
                        continue
                if proto == "MSSQL" and psize < 128:
                    dedup_key = (src_ip, phex[:24])
                    if dedup_key in _MSSQL_DEDUP:
                        continue
                    _MSSQL_DEDUP.add(dedup_key)
                    if len(_MSSQL_DEDUP) > 2000:
                        _MSSQL_DEDUP.clear()
                events.append({
                    "type": "dionaea",
                    "source": "dionaea",
                    "timestamp": d.get("timestamp", ""),
                    "protocol": proto,
                    "src_ip": d.get("src_ip", "0.0.0.0"),
                    "src_port": d.get("src_port", 0),
                    "dst_port": PUBLIC_PORT_MAP.get(proto, d.get("dst_port", 0)),
                    "payload_size": psize,
                })
            conn.close()
        except Exception:
            pass

    if os.path.exists(WEB_TRAP_LOG):
        try:
            with open(WEB_TRAP_LOG) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    ev = parse_web_trap_line(line)
                    if ev is not None:
                        events.append(ev)
        except Exception:
            pass

    events.sort(key=lambda e: e.get("timestamp", ""))
    return events


async def simulation_mode():
    while True:
        events = load_all_events()
        if not events:
            await asyncio.sleep(10)
            continue

        prev_ts = None
        for i, ev in enumerate(events):
            ev_ts_str = ev.get("timestamp", "")
            try:
                ev_ts = datetime.fromisoformat(ev_ts_str)
                if ev_ts.tzinfo is None:
                    ev_ts = ev_ts.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                ev_ts = datetime.now(timezone.utc)

            if i == 0:
                delta = 0
            else:
                try:
                    prev_dt = datetime.fromisoformat(prev_ts)
                    if prev_dt.tzinfo is None:
                        prev_dt = prev_dt.replace(tzinfo=timezone.utc)
                    delta = (ev_ts - prev_dt).total_seconds()
                except (ValueError, TypeError):
                    delta = 0

            delta = max(0, min(delta, 3600))
            if delta > 0:
                await asyncio.sleep(delta)

            ev["playback_ts"] = datetime.now(timezone.utc).isoformat()
            await broadcast_event(ev)
            prev_ts = ev_ts_str


# ─── Main ───────────────────────────────────────────────────────────

async def api_credential_details(request):
    username = request.query.get("username", "")
    password = request.query.get("password", "")
    if not username:
        return web.json_response({"error": "missing username"}, status=400)

    result = {"username": username, "password": password, "sessions": [], "ips": {}, "total_attempts": 0, "first_seen": None, "last_seen": None}
    sessions = {}

    if os.path.exists(COWRIE_JSON):
        try:
            with open(COWRIE_JSON) as f:
                for line in f:
                    line = line.strip()
                    if not line or not line.startswith("{"):
                        continue
                    try:
                        obj = json.loads(line)
                        u = obj.get("username", "")
                        p = obj.get("password", "")
                        if u == username and (not password or p == password):
                            ip = obj.get("src_ip", "")
                            ts = obj.get("timestamp", "")
                            sid = obj.get("session", "")
                            result["total_attempts"] += 1
                            result["ips"][ip] = result["ips"].get(ip, 0) + 1
                            if not result["first_seen"] or ts < result["first_seen"]:
                                result["first_seen"] = ts
                            if not result["last_seen"] or ts > result["last_seen"]:
                                result["last_seen"] = ts
                            if sid and sid not in sessions:
                                sessions[sid] = {"session": sid, "ip": ip, "timestamp": ts, "commands": []}
                            eid = obj.get("eventid", "")
                            if eid == "cowrie.command.input" and sid in sessions:
                                sessions[sid]["commands"].append({"input": obj.get("input", ""), "timestamp": ts})
                    except (json.JSONDecodeError, KeyError):
                        continue
        except Exception:
            pass

    # Supplement with DB data (richer than JSON alone)
    if os.path.exists(COWRIE_DB):
        try:
            conn = sqlite3.connect(COWRIE_DB)
            conn.row_factory = sqlite3.Row
            for r in conn.execute(
                "SELECT a.session, a.timestamp, a.username, a.password, s.ip FROM auth a JOIN sessions s ON a.session = s.id WHERE a.username = ? AND (? = '' OR a.password = ?) ORDER BY a.timestamp DESC LIMIT 1000",
                (username, password, password)
            ).fetchall():
                ip = r["ip"] or ""
                ts = r["timestamp"]
                sid = r["session"]
                result["total_attempts"] += 1
                result["ips"][ip] = result["ips"].get(ip, 0) + 1
                if not result["first_seen"] or ts < result["first_seen"]:
                    result["first_seen"] = ts
                if not result["last_seen"] or ts > result["last_seen"]:
                    result["last_seen"] = ts
                if sid and sid not in sessions:
                    sessions[sid] = {"session": sid, "ip": ip, "timestamp": ts, "commands": []}
            if sessions:
                sids = list(sessions.keys())
                placeholders = ",".join("?" * len(sids))
                for r in conn.execute(
                    f"SELECT session, timestamp, input FROM input WHERE session IN ({placeholders}) ORDER BY timestamp DESC LIMIT 1000",
                    sids
                ).fetchall():
                    sid = r["session"]
                    if sid in sessions:
                        sessions[sid]["commands"].append({"input": r["input"] or "", "timestamp": r["timestamp"]})
            conn.close()
        except Exception:
            pass

    result["sessions"] = list(sessions.values())
    result["top_ips"] = sorted([{"ip": k, "count": v} for k, v in result["ips"].items()], key=lambda x: x["count"], reverse=True)[:10]
    return web.json_response(result)


async def api_geo(request):
    ip = request.query.get("ip", "")
    if not ip:
        return web.json_response({}, status=400)
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,region,city,lat,lon,isp,as,org"
        req = urllib.request.Request(url, headers={"User-Agent": "honeypot/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        return web.json_response(data)
    except Exception:
        return web.json_response({})


async def run():
    load_config()
    mode = CONFIG.get("mode", "live")

    app = web.Application()
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/api/stats", api_stats)
    app.router.add_get("/api/events", api_events)
    app.router.add_get("/api/historical", api_historical)
    app.router.add_get("/api/recent", api_recent)
    app.router.add_get("/api/event-details", api_event_details)
    app.router.add_get("/api/system", api_system)
    app.router.add_get("/api/asn-details", api_asn_details)
    app.router.add_get("/api/credential-details", api_credential_details)
    app.router.add_get("/api/geo", api_geo)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 8765)
    await site.start()

    if mode == "simulation":
        await simulation_mode()
    else:
        await live_mode()


if __name__ == "__main__":
    asyncio.run(run())
