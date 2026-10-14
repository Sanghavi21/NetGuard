# NetGuard

NetGuard is a local network-security operations dashboard built with Flask, SQLite, and psutil. It combines live host visibility with an event-review workflow and a clearly separated Attack Lab for synthetic exercises.

> **Scope:** NetGuard is a learning and local-operations project, not a production IDS or firewall. Its live connection inventory reads the host socket table; it does not capture packet payloads, inspect every blocked packet, or enforce firewall rules.

## Features

- **Live connections:** reads current TCP/UDP sockets from the computer running NetGuard; shows protocol, state, local/remote endpoints, PID, process name (when available), and a five-second refresh.
- **Listener review flags:** identifies sockets bound to all network interfaces and selected sensitive service ports. These are review hints, not proof that the service is reachable from the internet.
- **Network usage monitor:** samples per-adapter byte counters while the monitor page is open, calculates upload/download rates, saves collected totals, supports a monthly limit, and exports CSV.
- **Security event review:** dashboard summaries, severity trends, source correlation, alert triage, investigation notes, and CSV/PDF exports for records in the local database.
- **Event provenance:** events created by the Attack Lab are marked `ATTACK LAB`; older rows without a known origin are marked `UNCLASSIFIED`.
- **IP list:** maintains NetGuard’s local application blacklist. Adding an address here does not add a Windows Firewall rule.
- **Operator profile:** stores operator contact/team details, shows account activity, and supports password changes.
- **Attack Lab:** creates synthetic records in the local database for safe demonstrations. It does not generate attack traffic or test a real network.

## Requirements

- Windows 10/11 (the host connection inventory is designed for Windows)
- Python 3.10 or newer
- PowerShell, or another terminal that can run Python

## Run locally

Open PowerShell in the project directory:

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

On first run, NetGuard creates `database/netguard.db` and initializes the local schema. The default local account is:

| Username | Password |
| --- | --- |
| `admin` | `admin123` |

Change this password from **My profile** before using the app with any non-demo data. If Windows prevents the connection inventory from reading the socket table, run the local Flask process from an elevated terminal; the page will report when this is needed.

## Network monitor notes

- Counters are collected from Windows network adapters while the monitor page is open. NetGuard cannot recover usage from before monitoring began.
- Adapter byte counters are system-wide and do not identify which application used the data.
- VPN and virtual adapters can mirror traffic from another adapter. Select one adapter when reviewing totals.
- Connection inventory and traffic counters describe the machine running Flask, not a remote client or the whole LAN.

## GitHub preparation

The local database contains account hashes, audit records, event data, and usage history. Keep it out of commits. `.gitignore` now excludes local database files and virtual environments.

`database/netguard.db` was already tracked by the repository, so `.gitignore` alone will not untrack it. Before committing the README and code, run:

```powershell
git rm --cached database/netguard.db
git add .gitignore README.md
git add app.py config.py database\db_handler.py requirements.txt static templates
git status
```

The `git rm --cached` command removes the database from Git’s index but keeps your local file. The database is present in earlier repository history and on the configured remote; removing it from a new commit does not erase those older copies. If the repository is or will be public, treat those older copies as exposed and rotate credentials. Purging repository history requires a deliberate history rewrite and force push.

After reviewing `git status`:

```powershell
git commit -m "Document NetGuard and add live host visibility"
git push origin main
```

## Security notes

- Flask is started with its development server and debug mode in `app.py`; keep it bound to localhost and do not expose it to the internet.
- `config.py` contains a development session secret. Replace it before using the project with real or shared data.
- The default admin password must be changed before storing non-demo information.
- The application blacklist is only a NetGuard database list; it does not block traffic at the operating-system level.

## Project layout

```text
NetGuard/
├── app.py                    # Flask routes and application logic
├── config.py                 # Local app configuration
├── database/
│   └── db_handler.py         # SQLite schema and initialization
├── requirements.txt          # Python dependencies
├── static/
│   ├── css/style.css         # NetGuard interface styles
│   └── images/               # Local UI artwork
└── templates/                # Flask/Jinja pages
```
