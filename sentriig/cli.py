"""Sentriig command-line setup and service controls."""
import argparse
import getpass
import json
import os
import secrets
import socket
import subprocess
import time
from . import core

def main():
    parser = argparse.ArgumentParser(description="Sentriig self-hosted Telegram monitor")
    parser.add_argument("command", choices=("setup","start","stop","restart","status","pair","test","logs","discover","run"))
    cmd = parser.parse_args().command
    if cmd == "setup":
        token = getpass.getpass("Telegram bot token (hidden): ").strip()
        if ":" not in token: parser.error("Invalid token format")
        try: bot = core.telegram({"token":token}, "getMe")
        except RuntimeError as exc: parser.error(str(exc))
        name = input(f"Server name [{socket.gethostname()}]: ").strip() or socket.gethostname()
        c = {"token":token,"server_name":name[:80],"chat_id":None,"user_id":None,
             "services":core.discover_services(),
             "notifications":{"CRITICAL":True,"ERROR":True,"WARNING":False,"INFO":False,"RECOVERY":True},
             "muted_domains":[]}
        core.save(c)
        core.store().close()
        print(f"Configured @{bot['username']}. Run: sudo sentriig start; sudo -u sentriig -H sentriig pair")
    elif cmd == "pair":
        c = core.load()
        if c.get("chat_id"):
            print("Already paired. Changing owner requires local administrator intervention.")
            return
        code = secrets.token_urlsafe(18)
        core.HOME.mkdir(parents=True, exist_ok=True)
        fd = os.open(core.PAIR, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f: json.dump({"code":code,"expires":time.time()+180}, f)
        bot = core.telegram(c,"getMe")["username"]
        print(f"Open https://t.me/{bot}?start={code} in private Telegram chat, and tap Start. Expires in 3 minutes.")
    elif cmd == "run":
        core.run()
    elif cmd == "test":
        c = core.load()
        core.telegram(c, "getMe")
        print("Bot token OK")
        if c.get("chat_id"):
            core.send(c, "✅ Sentriig test from " + c["server_name"])
            print("Message sent")
        else: print("Not paired")
    elif cmd == "discover":
        print("\n".join(core.discover_domains()) or "No domains found")
    elif cmd == "logs":
        raise SystemExit(subprocess.call(["journalctl","-u","sentriig.service","-n","60","--no-pager"]))
    else:
        command = ["systemctl",cmd,"sentriig.service"]
        if cmd == "status": command.append("--no-pager")
        raise SystemExit(subprocess.call(command))

if __name__ == "__main__":
    main()
