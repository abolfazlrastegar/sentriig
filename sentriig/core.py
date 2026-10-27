"""Sentriig core: local state, Telegram polling and bounded monitoring."""
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path

HOME = Path(os.environ.get("SENTRIIG_HOME", "/var/lib/sentriig"))
CONFIG = HOME / "config.json"
PAIR = HOME / "pair.json"
DB = HOME / "state.db"
KNOWN = ("nginx", "apache2", "httpd", "supervisor", "supervisord", "docker", "redis", "redis-server", "mysql", "mariadb", "postgresql")
SENSITIVE = re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+|authorization\s*[:=]\s*|bearer\s+|(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*)[^\s,;]+")

def redact(s):
    s = SENSITIVE.sub(lambda m: m.group(1) + "[REDACTED]", str(s))
    return re.sub(r"\b\d{7,}:[A-Za-z0-9_-]{20,}\b", "[REDACTED]", s)[:1300]

def save(c):
    HOME.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f: json.dump(c, f)
    os.replace(tmp, CONFIG)
    CONFIG.chmod(0o600)

def load():
    if not CONFIG.exists(): raise RuntimeError("Run sentriig setup first")
    return json.loads(CONFIG.read_text())

def store():
    HOME.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB)
    db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts INTEGER, severity TEXT, domain TEXT, service TEXT, message TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS domains (name TEXT PRIMARY KEY, enabled INTEGER DEFAULT 1)")
    db.commit()
    DB.chmod(0o600)
    return db

def telegram(c, action, payload=None, timeout=20):
    req = urllib.request.Request("https://api.telegram.org/bot" + c["token"] + "/" + action,
        data=urllib.parse.urlencode(payload or {}).encode(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        raise RuntimeError("Telegram connection failed") from None
    if not data.get("ok"): raise RuntimeError("Telegram API rejected request")
    return data.get("result")

def send(c, text, keyboard=None):
    if not c.get("chat_id"): return
    body = {"chat_id": str(c["chat_id"]), "text": text[:3900]}
    if keyboard: body["reply_markup"] = json.dumps({"inline_keyboard": keyboard})
    telegram(c, "sendMessage", body)

def service_status(s):
    try:
        r = subprocess.run(["systemctl", "is-active", s], capture_output=True, text=True, timeout=4)
        return r.stdout.strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"

def discover_services():
    result = []
    for name in KNOWN:
        try:
            r = subprocess.run(["systemctl", "list-unit-files", name + ".service", "--no-legend", "--no-pager"],
                capture_output=True, text=True, timeout=4)
            if any(x.startswith(name + ".service ") for x in r.stdout.splitlines()): result.append(name)
        except (OSError, subprocess.TimeoutExpired): pass
    return result

def discover_domains():
    result = set()
    for directory in (Path("/etc/nginx/sites-enabled"), Path("/etc/nginx/conf.d")):
        if not directory.is_dir(): continue
        for file in directory.iterdir():
            if not file.is_file() or file.suffix not in ("", ".conf"): continue
            try: content = file.read_text(errors="replace")[:200000]
            except OSError: continue
            for names in re.findall(r"(?m)^\s*server_name\s+([^;]+);", content):
                for name in names.split():
                    if not name.startswith(("~", "$", "_", "#")) and "*" not in name and re.fullmatch(r"[A-Za-z0-9.-]{1,253}", name):
                        result.add(name.lower())
    return sorted(result)

def record(db, c, severity, domain, service, message):
    message = redact(message)
    db.execute("INSERT INTO events(ts,severity,domain,service,message) VALUES(?,?,?,?,?)",
        (int(time.time()), severity, domain, service, message))
    db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 2000)")
    db.commit()
    if c.get("notifications", {}).get(severity, False) and domain not in c.get("muted_domains", []):
        try: send(c, f"[{severity}] Sentriig\nServer: {c['server_name']}\nDomain: {domain or 'server-wide'}\nService: {service}\nError: {message}")
        except RuntimeError: pass

def poll_services(db, c):
    for name in c.get("services", []):
        status = service_status(name)
        key = "svc:" + name
        row = db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        old = row[0] if row else None
        if status != old:
            if status != "active": record(db, c, "CRITICAL" if old == "active" else "ERROR", "", name, "Service state: " + status)
            elif old is not None: record(db, c, "RECOVERY", "", name, "Service active again")
            db.execute("INSERT OR REPLACE INTO kv VALUES(?,?)", (key, status))
            db.commit()

def poll_domains(db, c):
    for (name,) in db.execute("SELECT name FROM domains WHERE enabled=1").fetchall():
        ok, detail = False, ""
        req = urllib.request.Request("http://127.0.0.1/", headers={"Host": name, "User-Agent": "Sentriig/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                ok, detail = resp.status < 500, "HTTP " + str(resp.status)
        except urllib.error.HTTPError as exc:
            ok, detail = exc.code < 500, "HTTP " + str(exc.code)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            detail = type(exc).__name__
        key = "web:" + name
        row = db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        old = row[0] if row else None
        new = "up" if ok else "down"
        if new != old:
            if not ok: record(db, c, "ERROR", name, "HTTP / Nginx upstream", "Health check failed: " + detail)
            elif old == "down": record(db, c, "RECOVERY", name, "HTTP", "Domain recovered")
            db.execute("INSERT OR REPLACE INTO kv VALUES(?,?)", (key, new))
            db.commit()

def poll_nginx_errors(db, c):
    file = Path("/var/log/nginx/error.log")
    try:
        stat = file.stat()
        key = "nginx:cursor"
        row = db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        old = json.loads(row[0]) if row else {}
        offset = old.get("offset", 0) if old.get("inode") == stat.st_ino else 0
        if not row: offset = stat.st_size
        if offset > stat.st_size: offset = 0
        with file.open("rb") as stream:
            stream.seek(offset)
            chunk = stream.read(64000)
        if len(chunk) == 64000:
            chunk = chunk[:chunk.rfind(b"\n") + 1] if b"\n" in chunk else b""
        for line in chunk.decode("utf-8", "replace").splitlines()[:100]:
            m = re.search(r"\[(emerg|alert|crit|error|warn|notice|info)\]", line)
            if not m: continue
            sev = {"emerg":"CRITICAL", "alert":"CRITICAL", "crit":"CRITICAL", "error":"ERROR", "warn":"WARNING", "notice":"INFO", "info":"INFO"}[m.group(1)]
            host = re.search(r"(?:server|host):\s*\"?([A-Za-z0-9.-]+)", line)
            record(db, c, sev, host.group(1) if host else "", "nginx", line)
        db.execute("INSERT OR REPLACE INTO kv VALUES(?,?)",
                   (key, json.dumps({"inode": stat.st_ino, "offset": offset + len(chunk)})))
        db.commit()
    except (OSError, ValueError): pass

def keyboard(rows):
    return [[{"text": label, "callback_data": value} for label, value in row] for row in rows]

def home():
    return keyboard([[("🌐 Domains", "domains"), ("⚙️ Services", "services")],
                     [("🚨 Events", "events"), ("🔔 Alerts", "alerts")],
                     [("🔎 Scan domains", "scan"), ("📊 Status", "status")]])

def authorized(c, msg):
    return bool(c.get("chat_id") and int(msg.get("chat", {}).get("id", 0)) == int(c["chat_id"]) and
                int(msg.get("from", {}).get("id", 0)) == int(c.get("user_id", 0)))

def handle(db, c, upd):
    cb = upd.get("callback_query")
    msg = cb.get("message", {}) if cb else upd.get("message", {})
    if not cb and not c.get("chat_id") and msg.get("chat", {}).get("type") == "private":
        text = msg.get("text", "")
        if text.startswith("/start ") and PAIR.is_file():
            try: pending = json.loads(PAIR.read_text())
            except (OSError, ValueError): pending = {}
            if time.time() < pending.get("expires", 0) and secrets.compare_digest(text[7:].strip(), pending.get("code", "")):
                c["chat_id"], c["user_id"] = int(msg["chat"]["id"]), int(msg["from"]["id"])
                save(c)
                PAIR.unlink(missing_ok=True)
                send(c, "✅ Sentriig paired. Monitoring active.", home())
                return
    check = {**msg, "from": cb.get("from", {})} if cb else msg
    if not authorized(c, check):
        if cb:
            try: telegram(c, "answerCallbackQuery", {"callback_query_id": cb["id"]})
            except RuntimeError: pass
        return
    if cb:
        try: telegram(c, "answerCallbackQuery", {"callback_query_id": cb["id"]})
        except RuntimeError: pass
    command = cb.get("data", "") if cb else msg.get("text", "")
    if command in ("/start", "/menu", "menu"):
        send(c, "Sentriig • " + c["server_name"] + "\nChoose an option:", home())
    elif command == "status":
        send(c, "Server: " + c["server_name"] + "\n" +
             ("\n".join(f"{s}: {service_status(s)}" for s in c.get("services", [])) or "No services"), home())
    elif command == "services":
        send(c, "Services:\n" + ("\n".join(f"• {s}: {service_status(s)}" for s in c.get("services", [])) or "No services"), home())
    elif command == "domains":
        rows = db.execute("SELECT name,enabled FROM domains ORDER BY name LIMIT 80").fetchall()
        send(c, "Domains:\n" + ("\n".join(f"• {n} {'✅' if en else '⏸'}" for n, en in rows) or "None. Scan first."), home())
    elif command == "events":
        rows = db.execute("SELECT severity,domain,service,message FROM events ORDER BY id DESC LIMIT 8").fetchall()
        send(c, "Recent events:\n" + ("\n\n".join(f"[{s}] {d or 'server'}/{unit}: {msg[:220]}" for s,d,unit,msg in rows) or "None"), home())
    elif command == "scan":
        names = discover_domains()
        for name in names:
            db.execute("INSERT OR IGNORE INTO domains(name) VALUES(?)", (name,))
        db.commit()
        send(c, f"Scan finished. Found {len(names)} domains; new domains registered.", home())
    elif command == "alerts":
        flags = c.get("notifications", {})
        rows = [[(f"{x}: {'ON' if flags.get(x) else 'OFF'}", "toggle:" + x)] for x in ("CRITICAL","ERROR","WARNING","INFO","RECOVERY")]
        send(c, "Notification preferences:", keyboard(rows + [[("⬅ Menu", "menu")]]))
    elif command.startswith("toggle:"):
        level = command[7:]
        if level in ("CRITICAL","ERROR","WARNING","INFO","RECOVERY"):
            c.setdefault("notifications", {})[level] = not c["notifications"].get(level, False)
            save(c)
            send(c, f"{level} updated.", home())

def run():
    c = load()
    db = store()
    offset, last = 0, 0.0
    while True:
        if time.monotonic() - last >= 30:
            poll_services(db, c)
            poll_domains(db, c)
            poll_nginx_errors(db, c)
            last = time.monotonic()
        try:
            updates = telegram(c, "getUpdates", {"offset": offset, "timeout": 15,
                        "allowed_updates": json.dumps(["message","callback_query"])}, timeout=23)
            for update in updates:
                offset = max(offset, update["update_id"] + 1)
                handle(db, c, update)
        except RuntimeError:
            time.sleep(5)
