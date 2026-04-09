# ── Stage 1: Build React frontend ─────────────────────────────────────────────
FROM node:22-alpine AS frontend-builder

WORKDIR /app/frontend

# Install dependencies first for better layer caching.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ .
RUN npm run build


# ── Stage 2: Production image ──────────────────────────────────────────────────
FROM ubuntu:25.10

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
# Put the venv on PATH so no explicit activation is needed.
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies — upgrade first to pull in OS-level security patches
# (fixes CVE-2025-14831 and CVE-2025-9820 in gnutls28).
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        exiftool \
        libmpc-dev \
        libgl1 \
        libglib2.0-0 \
        ca-certificates \
        postgresql-client \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create virtualenv and pin pip + wheel to patched versions to fix
# CVE-2025-47273, CVE-2024-6345 (setuptools), CVE-2026-24049 (wheel>=0.46.2),
# CVE-2025-8869, CVE-2026-1703 (pip>=26.0).
RUN python3 -m venv /opt/venv \
    && pip install --no-cache-dir "pip>=26.0" setuptools "wheel>=0.46.2"

# Install Python dependencies before copying source for better caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    # androguard pulls in frida (dynamic instrumentation) as a hard dependency,
    # but vault1337 only uses androguard's static analysis features. frida bundles
    # a Go 1.24.x runtime (CVE-2025-68121 critical + 22 others). Remove it so the
    # pentest submodule remains importable by name but the Go binary is not present.
    && pip uninstall -y frida

# Copy application source (build context is the project root).
COPY . .

# Copy the built React frontend from stage 1.
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Create a non-root user for runtime. UID/GID 1001 avoids conflicts with common
# system users. Using a fixed UID makes it straightforward to pre-create the
# same user on the host when bind-mounting volumes.
RUN groupadd --gid 1001 vault \
    && useradd --uid 1001 --gid vault --create-home --shell /bin/sh vault

# Create runtime directories that are mounted as Docker volumes.
RUN mkdir -p sample_storage vault/yara-rules backups

# Collect Django static files (admin CSS etc.) into staticfiles/.
# SECRET_KEY must be set; DATABASE_URL is not needed for collectstatic.
RUN SECRET_KEY=dummy-build-key python manage.py collectstatic --noinput

# Transfer ownership of the application tree to the vault user.
# /opt/venv is deliberately excluded — pip installs as root make it
# world-readable, so the vault user can use it without a slow recursive chown
# across thousands of package files.
RUN chown -R vault:vault /app

EXPOSE 8000

COPY Docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Drop privileges — run as non-root from here on.
USER vault

ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "vault1337.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--preload", \
     "--worker-tmp-dir", "/dev/shm", \
     "--timeout", "120"]
