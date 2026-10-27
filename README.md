# Sentriig 🛡️

**Self-hosted Linux monitoring with Telegram alerts.** One server, one bot, no central backend.

> **v0.1.0 BETA — staging-only until installation, network and security checks have been performed on your OS.**

## Quick installation

```bash
git clone https://github.com/abolfazlrastegar/sentriig.git
cd sentriig
sudo bash scripts/install.sh
sudo -u sentriig -H sentriig setup
sudo sentriig start
sudo -u sentriig -H sentriig pair
sudo -u sentriig -H sentriig test
```

Create a bot with [BotFather](https://t.me/BotFather). Setup asks for the token in a hidden prompt; pair prints a one-time `/start CODE` deep link to connect your private chat. Keep it secret.

## CLI

- `setup`: bot token and server label
- `start`, `stop`, `restart`, `status`: systemd service control
- `pair`: receive Chat ID and Telegram user ID through a short-lived pairing code
- `test`: verify Telegram connection and send a test alert
- `logs`: recent monitor service journal
- `discover`: preview Nginx hosts from the terminal

Use `sudo sentriig <command>` for systemd operations. Use `sudo -u sentriig -H sentriig setup|pair|test` for private state.

## Telegram

/start opens a menu for **Scan domains**, **Domains**, **Services**, **Events**, **Alerts**, and **Status**.

Scanning configurations happens **only when requested via Telegram**; runtime health checks remain periodic. Nginx domain mapping is best effort based on static `server_name` directives. It records recent errors by severity and domain where identifiable; service-wide failures are not misattributed to a single website. ERROR and CRITICAL alerts are on by default, RECOVERY on; INFO and WARNING notification delivery are initially off (events may still be saved). No arbitrary server commands can be run from Telegram.

## Monitoring and limitations

- Detects presence and up/down transitions of common systemd services such as Nginx, Apache, Docker, MySQL, PostgreSQL, Redis and Supervisor.
- Checks monitored domains via **local HTTP** Host header. HTTPS-only applications, non-standard ports and redirects may give false readings.
- Tails a bounded amount of `/var/log/nginx/error.log`, subject to access permissions, and stores sanitized events in local SQLite. Event display is recent-items, not yet detailed per-domain filtering.
- Does **not** guarantee prediction of future outages. Cannot alert if the entire server, network or bot process is down; independent external checking is required.
- No generic deep Laravel/Node/WordPress validation-event instrumentation yet; reading Nginx alone cannot expose all application-level errors.
- Credentials are redacted using common patterns, but arbitrary log content may still contain personal data. Do not use with sensitive production logs until reviewed.
- Domain discovery currently targets conventional Nginx directories. Other web-server configs and custom setups may need additional adapters.
- There is no automatic restart/repair of monitored services.

## Security

The bot only accepts a paired private Telegram user and chat. Pair codes expire. Runtime uses a dedicated unprivileged service account with systemd sandboxing and local mode-0600 credentials. No exposed HTTP endpoint or remote shell. Never commit `config.json`, `pair.json` or bot tokens. Rotate any exposed token with BotFather.

## Local tests

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q sentriig
bash -n scripts/install.sh
```

## License

MIT. See LICENSE.
