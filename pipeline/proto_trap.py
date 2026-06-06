import asyncio
import sqlite3
import json
import time
import os
from datetime import datetime, timezone

DB_PATH = "/opt/honeypot/database/dionaea_history.db"
BIND_PORTS = {
    4545:  "SMB",
    14433: "MSSQL",
    33306: "MySQL",
}

def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            protocol TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL,
            payload_hex TEXT DEFAULT '',
            payload_size INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS malware_captures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            protocol TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            md5 TEXT DEFAULT '',
            sha256 TEXT DEFAULT '',
            file_size INTEGER DEFAULT 0,
            payload_path TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()

def log_connection(protocol, src_ip, src_port, dst_port, payload=b""):
    now = datetime.now(timezone.utc).isoformat()
    for attempt in range(3):
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            conn.execute(
                "INSERT INTO connections (timestamp, protocol, src_ip, src_port, dst_port, payload_hex, payload_size) VALUES (?,?,?,?,?,?,?)",
                (now, protocol, src_ip, src_port, dst_port, payload.hex()[:512] if payload else "", len(payload))
            )
            conn.commit()
            conn.close()
            break
        except sqlite3.OperationalError:
            if attempt < 2:
                import time as _time
                _time.sleep(0.5)
                continue
            try:
                conn.close()
            except Exception:
                pass
    return {
        "type": "connection",
        "source": "dionaea",
        "timestamp": now,
        "protocol": protocol,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "payload_size": len(payload)
    }

class ProtocolHoneypot:
    def __init__(self, port, proto_name, banner=None, response_handler=None):
        self.port = port
        self.proto_name = proto_name
        self.banner = banner
        self.response_handler = response_handler
        self.event_queue = None

    async def handle_client(self, reader, writer):
        peername = writer.get_extra_info('peername')
        src_ip = peername[0] if peername else "0.0.0.0"
        src_port = peername[1] if peername else 0

        payload_all = b""

        if self.banner:
            try:
                writer.write(self.banner)
                await writer.drain()
            except Exception:
                pass

        try:
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=15.0)
                if not data:
                    break
                payload_all += data
                if self.response_handler:
                    resp = self.response_handler(data)
                    if resp:
                        writer.write(resp)
                        await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        out_event = log_connection(self.proto_name, src_ip, src_port, self.port, payload_all)

        try:
            os.makedirs("/opt/honeypot/dionaea/payloads", exist_ok=True)
            if len(payload_all) > 0:
                ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                fname = f"/opt/honeypot/dionaea/payloads/{self.proto_name}_{src_ip}_{ts}.bin"
                with open(fname, "wb") as f:
                    f.write(payload_all)
        except Exception:
            pass

        if self.event_queue:
            await self.event_queue.put(out_event)

    async def start(self, event_queue=None):
        self.event_queue = event_queue
        server = await asyncio.start_server(
            self.handle_client, '0.0.0.0', self.port,
            backlog=50
        )
        print(f"  [{self.proto_name}] listening on port {self.port}")
        async with server:
            await server.serve_forever()

async def run_dionaea_trap(event_queue=None):
    init_db()

    smb = ProtocolHoneypot(4545, "SMB",
        banner=b'\x00\x00\x00\xa4\xffSMBr\x00\x00\x00\x00\x88\x01@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    )

    mssql = ProtocolHoneypot(14433, "MSSQL")

    mysql = ProtocolHoneypot(33306, "MySQL",
        banner=b'J\x00\x00\x00\n8.0.36\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    )

    tasks = [
        smb.start(event_queue),
        mssql.start(event_queue),
        mysql.start(event_queue),
    ]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(run_dionaea_trap())
