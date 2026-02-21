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

- Upload samples by file or URL, or download directly from **VirusTotal** or **Malware Bazaar** by SHA256 hash
- **10+ static analysis tools**: Strings, LIEF Parser, Hex Viewer, PDF Parser, OLE Tools, ExifTool, IOC Extractor, YARA, Email Parser, Zip Extractor, QR Decode
- **YARA rules** — create, edit and run rules against samples via a built-in editor
- **IOC tracking** — extract and manage indicators of compromise linked to samples
- **IP reputation** — query AbuseIPDB, Spur, and Shodan from a single interface
- Tag-based organisation with full-text search
- JWT-authenticated REST API with staff/user role separation
- API key management for all third-party integrations

## Quick Start (Docker)

```bash
docker pull vault1337/vault1337:latest
docker run -p 8000:8000 vault1337/vault1337:latest
```

Open `http://localhost:8000` and log in with the default credentials:

```
Username: admin
Password: changeme123
```

> **Change your password immediately** at `http://localhost:8000/admin`

Add your API keys at `http://localhost:8000/admin/keys` (staff only) for the full feature set:
- [VT_KEY](https://www.virustotal.com/) — VirusTotal
- [MALWARE_BAZAAR_KEY](https://bazaar.abuse.ch/api/) — Malware Bazaar
- [ABUSEIPDB_KEY](https://www.abuseipdb.com/api.html) — AbuseIPDB
- [SPUR_KEY](https://spur.us/context-api/) — Spur
- [SHODAN_KEY](https://account.shodan.io/) — Shodan

## Documentation

Full installation instructions (Docker and manual Ubuntu 24.04) are available at [vault1337.com](https://www.vault1337.com).

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
