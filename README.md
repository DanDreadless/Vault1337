![Vault1337 logo](/vault/static/images/logos/png/logo-no-background.png "Vault1337 Logo")

---

[![License](https://img.shields.io/badge/AGPL-3.0--Clause-blue.svg)](https://github.com/DanDreadless/Vault1337/blob/main/LICENSE) [![Website](https://img.shields.io/website?url=https%3A%2F%2Fwww.vault1337.com%2F&label=Vault1337&link=https%3A%2F%2Fwww.vault1337.com%2F)](https://www.vault1337.com/)
 [![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/DanDreadless?link=https%3A%2F%2Fx.com%2FDanDreadless)](https://x.com/DanDreadless)

---

Vault1337 is an open-source static malware analysis platform and repository. It provides a secure, self-hosted environment for storing, organising, and analysing malware samples — built for security researchers, educators, and enthusiasts.

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3 / Django 5.2 / Django REST Framework |
| Authentication | JWT (djangorestframework-simplejwt) |
| Frontend | React 19 / TypeScript / Vite 6 / Tailwind CSS 4 |
| Database | PostgreSQL (production) / SQLite (development) |
| Production | Gunicorn + NGINX (runs on Raspberry Pi 5) |
| Container | Docker — `vault1337/vault1337:latest` |

## Features

- Upload samples by file or URL, or download directly from **VirusTotal** or **MalwareBazaar** by SHA256 hash
- **15+ static analysis tools** grouped by file type (PE, ELF, Mach-O, document, archive, email):
  - **Universal**: Strings (UTF-8/ASCII/Wide/Latin-1), Hex Viewer, IOC Extractor, YARA, ExifTool
  - **Windows PE**: LIEF Parser (headers, imports, exports, entropy, signature), PE File (suspicious imports, packer detection, compile timestamp anomaly, anti-VM string scan), Disassembler (Capstone x86/x64/ARM)
  - **Linux ELF**: LIEF Parser (ELF header, sections, symbols, suspicious symbols, packer detection, segments, binary info), Disassembler
  - **macOS Mach-O**: Mach-O Tool (header, load commands, imported libraries, exports, symbols, sections, code signature, entitlements, encrypted segments)
  - **Documents**: PDF Parser (metadata, content, URLs, JavaScript, embedded files), OLETools (OLEID, OLEMETA, OLEDUMP, OLEVBA, RTFOBJ, OLEOBJ)
  - **Archives**: Zip Extractor (ZIP / 7z with optional password)
  - **Email**: Email Parser (headers, body, attachments, URLs)
- **YARA rules** — create, edit, and run rules via a built-in editor; no rules included by default
- **IOC tracking** — extract and manage 13 IOC types including persistence artefacts (Win Run keys, scheduled tasks, Linux cron, systemd units, macOS LaunchAgents)
- **IP reputation** — query AbuseIPDB, Spur, and Shodan from a single interface
- **Sample report** — structured JSON aggregating hashes, VT data, IOCs, and tags (`GET /api/v1/files/{id}/report/`)
- **VirusTotal enrichment** — automatic on upload; refresh any time via the VT Enrich action
- Tag-based organisation with full-text search
- JWT-authenticated REST API with OpenAPI/Swagger docs at `/api/v1/docs/`
- API key management for all third-party integrations

## Quick Start (Docker — single container)

For a quick demo using SQLite. Data is not persisted when the container stops.

```bash
docker run -p 8000:8000 \
  -e SECRET_KEY=change-me-to-something-random \
  -e DEBUG=True \
  vault1337/vault1337:latest
```

Open `http://localhost:8000` and log in with the default credentials:

```
Username: admin
Password: changeme123
```

> **Change your password immediately** via the Django admin at `/admin/`

---

## Production (Docker Compose + PostgreSQL)

Docker Compose sets up Vault1337 with a PostgreSQL database and persistent volumes for samples and YARA rules.

**1. Clone the repository**

```bash
git clone https://github.com/DanDreadless/Vault1337.git
cd Vault1337/Docker
```

**2. Configure environment**

The `Docker/.env` file is the single source of configuration. Open it and set at minimum:

| Variable | Description |
|---|---|
| `SECRET_KEY` | Long random string — generate with `openssl rand -hex 50` |
| `POSTGRES_PASSWORD` | Password for the database |
| `DJANGO_SUPERUSER_PASSWORD` | Initial admin password |
| `ALLOWED_HOSTS` | Your server hostname or IP |

API keys are optional but unlock VirusTotal, MalwareBazaar, AbuseIPDB, Spur, and Shodan integrations.

**3. Start the stack**

```bash
docker compose up -d
```

Open `http://localhost:8000` (or your configured `HOST_PORT`).

To stop:

```bash
docker compose down
```

To stop and wipe all data including the database:

```bash
docker compose down -v
```

---

## Local Development

Requires Python 3.12+, Node.js 22+, and (optionally) PostgreSQL.

**1. Clone and set up Python environment**

```bash
git clone https://github.com/DanDreadless/Vault1337.git
cd Vault1337
python3 -m venv env
source env/bin/activate        # Windows: env\Scripts\activate
pip install -r requirements.txt
```

**2. Configure environment**

Copy the Docker env template and edit it for local use:

```bash
cp Docker/.env .env
```

Set `SECRET_KEY` and `DEBUG=True`. Leave `DATABASE_URL` empty to use SQLite, or point it at a local PostgreSQL instance.

**3. Run migrations and create a superuser**

```bash
python manage.py migrate
python manage.py createsuperuser
```

**4. Start the Django API**

```bash
python manage.py runserver
```

**5. Start the React frontend** (in a second terminal)

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The Vite dev server proxies `/api/` requests to Django on port 8000.

---

## API keys

Add API keys via the web UI at `/admin/keys/` (staff login required):

- [VT_KEY](https://www.virustotal.com/) — VirusTotal
- [MALWARE_BAZAAR_KEY](https://bazaar.abuse.ch/api/) — Malware Bazaar
- [ABUSEIPDB_KEY](https://www.abuseipdb.com/api.html) — AbuseIPDB
- [SPUR_KEY](https://spur.us/context-api/) — Spur
- [SHODAN_KEY](https://account.shodan.io/) — Shodan

---

## Documentation

Full installation instructions are available at [vault1337.com](https://www.vault1337.com).

---

## License

This project is licensed under the **GNU Affero General Public License (AGPL-3.0)**. This ensures that:
- You are free to use, modify, and share this software as long as you comply with the terms of the AGPL-3.0.
- If you deploy this software on a server, you must make the source code, including any modifications, available to your users under the same license.

The full text of the AGPL-3.0 license is available in the [LICENSE](LICENSE) file.

## Commercial Use

Vault1337 is open-source software, but we recognize that businesses may want to use it without adhering to the AGPL's strict copyleft requirements. To accommodate such use cases, a **commercial license** is available.

### Benefits of the Commercial License
1. Use Vault1337 in proprietary environments without the need to open-source your modifications.
2. Support the continued development and maintenance of the project.

### How to Purchase
Contact me via **LinkedIn**: [www.linkedin.com/in/dan-pickering](https://www.linkedin.com/in/dan-pickering)

## Supporting the Project

Even if you don't require a commercial license, consider supporting the project through donations or sponsorship. Your contributions help keep Vault1337 free for the open-source community.

Thank you for using Vault1337!
