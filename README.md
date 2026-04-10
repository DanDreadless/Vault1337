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
| Production | Gunicorn + NGINX (cloud-hosted or containerised) |
| Container | Docker — `vault1337/vault1337:latest` |

## Features

- Upload samples by file or URL, or download directly from **VirusTotal** or **MalwareBazaar** by SHA256 hash
- **20+ static analysis tools** grouped by file type (PE, ELF, Mach-O, APK, .NET, document, archive, email, image):
  - **Universal**: Strings (UTF-8/ASCII/Wide/Latin-1), Hex Viewer, IOC Extractor, YARA, ExifTool
  - **Windows PE**: LIEF Parser (headers, imports, exports, entropy, signature), PE File (suspicious imports, packer detection, compile timestamp anomaly, anti-VM string scan), Disassembler (Capstone x86/x64/ARM)
  - **Linux ELF**: LIEF Parser (ELF header, sections, symbols, suspicious symbols, packer detection, segments, binary info), Disassembler
  - **macOS Mach-O**: Mach-O Tool (header, load commands, imported libraries, exports, symbols, sections, code signature, entitlements, encrypted segments)
  - **Android APK**: APK Tool via androguard (manifest, components, intents, signing certificate, DEX strings, embedded URLs, suspicious permissions and API usage)
  - **Scripts & .NET**: .NET Analysis via dnfile (assembly info, type/method definitions, strings, imports, resources)
  - **Documents**: PDF Parser (metadata, content, URLs, JavaScript, embedded files, page rendering), OLETools (OLEID, OLEMETA, OLEDUMP, OLEVBA, RTFOBJ, OLEOBJ)
  - **Archives**: Zip Extractor (ZIP / 7z with optional password)
  - **Email**: Email Parser (headers, body, attachments, URLs)
  - **Images**: Image Viewer (inline render via data URI)
- **MITRE ATT&CK mapping** — scan analysis results and IOC types for technique indicators; results displayed as tactic-coloured badges with links to MITRE, persisted per sample
- **STIX 2.1 export** — export any sample (with all IOCs) or a bulk selection of IOCs from the IOC page as a STIX 2.1 bundle via the [stix2](https://github.com/oasis-open/cti-python-stix2) library
- **YARA rules** — create, edit, and run rules via a built-in editor; no rules included by default
- **IOC tracking** — extract and manage 13 IOC types including persistence artefacts (Win Run keys, scheduled tasks, Linux cron, systemd units, macOS LaunchAgents); bulk export to STIX or bulk delete from the IOC page
- **IOC auto-enrichment** — newly extracted IPs and domains are automatically queried against VirusTotal and AbuseIPDB in a background thread; true/false positive status set automatically with manual override support
- **IP & domain intelligence** — structured report cards with verdict banners for [IP Check](https://www.vault1337.com/docs.html#ip) (AbuseIPDB, Spur, Shodan, VirusTotal) and [Domain Check](https://www.vault1337.com/docs.html#ip) (VirusTotal, WHOIS, passive DNS)
- **Decoder** — Base64, hex, URL, ROT13, and XOR decoding in-browser without uploading a sample
- **Sample report** — structured JSON aggregating hashes, VT data, IOCs, and tags (`GET /api/v1/files/{id}/report/`)
- **PDF report export** — one-click A4 PDF from the sample detail page covering hashes, VT intelligence, confirmed IOCs, and analyst notes; generated entirely in-browser with no extra API calls
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

> **Change your password immediately** after first login via the Management page or the Django admin at `/admin/`

---

## Production (Docker Compose + PostgreSQL)

Docker Compose sets up Vault1337 with a PostgreSQL database and persistent named volumes for samples and YARA rules.

**1. Clone the repository and enter the Docker directory**

```bash
git clone https://github.com/DanDreadless/Vault1337.git
cd Vault1337/Docker
```

**2. Create and configure the environment file**

Create a `Docker/.env` file and set at minimum:

| Variable | Description |
|---|---|
| `SECRET_KEY` | Long random string — `openssl rand -hex 50` |
| `POSTGRES_USER` | Database username |
| `POSTGRES_PASSWORD` | Database password |
| `POSTGRES_DB` | Database name |
| `DATABASE_URL` | `postgres://<user>:<pass>@db:5432/<db>` |
| `DJANGO_SUPERUSER_USERNAME` | Initial admin username (default: `admin`) |
| `DJANGO_SUPERUSER_PASSWORD` | Initial admin password (default: `changeme123`) |
| `DJANGO_SUPERUSER_EMAIL` | Initial admin email |
| `ALLOWED_HOSTS` | Your server hostname or IP |

API keys are optional but unlock VirusTotal, MalwareBazaar, AbuseIPDB, Spur, Shodan, and OTX integrations.

**3. Pull the image and start the stack**

```bash
docker compose up -d
```

On first start the entrypoint automatically runs migrations and creates the superuser from the `DJANGO_SUPERUSER_*` env vars.

Open `http://localhost:8000` (or your configured `HOST_PORT`).

**Useful commands**

```bash
# View live logs
docker compose logs -f web

# Stop without losing data
docker compose down

# Stop and wipe all data including the database (destructive)
docker compose down -v
```

**Persistent volumes**

| Volume | Contents |
|---|---|
| `sample_storage` | Malware samples (stored by SHA256 hash) |
| `yara_rules` | YARA `.yar` rule files |
| `backups` | Database backup dumps |
| `postgres_data` | PostgreSQL data directory |

Named volumes persist across restarts and rebuilds. They are only destroyed by `docker compose down -v`.

---

## Docker Development (build from source)

Use this when developing locally. Builds the image from source and mounts your existing SQLite database and sample storage so your data is immediately available.

```bash
cd Docker
docker compose \
  -f docker-compose.yml \
  -f docker-compose.build.yml \
  -f docker-compose.localdev.yml \
  up --build
```

What the `localdev` overlay does:
- Bind-mounts `../db.sqlite3` → `/app/db.sqlite3`
- Bind-mounts `../sample_storage/` → `/app/sample_storage`
- Sets `DATABASE_URL=""` so Django uses SQLite (PostgreSQL never starts)

> **Linux / WSL users:** the container runs as UID 1001. If your files are owned by your host user (UID 1000), make them writable so the container can write to them:
> ```bash
> chmod 666 db.sqlite3 && chmod -R 777 sample_storage/
> ```

To develop against a fresh PostgreSQL database instead (useful for testing migrations):

```bash
cd Docker
docker compose -f docker-compose.yml -f docker-compose.build.yml up --build
```

---

## Local Development (Python + Node)

Requires Python 3.12+, Node.js 22+.

**1. Clone and set up Python environment**

```bash
git clone https://github.com/DanDreadless/Vault1337.git
cd Vault1337
python3 -m venv env
source env/bin/activate        # Windows: env\Scripts\activate
pip install -r requirements.txt
```

**2. Configure environment**

Create a `.env` file in the project root:

```bash
SECRET_KEY=$(openssl rand -hex 50)
DEBUG=True
```

Leave `DATABASE_URL` unset to use SQLite, or point it at a local PostgreSQL instance.

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

Add API keys via the **Management page** (`/management` → API Keys tab). Staff login required.

| Key | Service |
|---|---|
| `VT_KEY` | [VirusTotal](https://www.virustotal.com/) |
| `MALWARE_BAZAAR_KEY` | [MalwareBazaar](https://bazaar.abuse.ch/api/) |
| `ABUSEIPDB_KEY` | [AbuseIPDB](https://www.abuseipdb.com/api.html) |
| `SPUR_KEY` | [Spur](https://spur.us/context-api/) |
| `SHODAN_KEY` | [Shodan](https://account.shodan.io/) |
| `OTX_KEY` | [AlienVault OTX](https://otx.alienvault.com/api) |

Keys can also be set directly in your `.env` file.

---

## Documentation

Full installation and usage documentation is available at [vault1337.com](https://www.vault1337.com).

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
