# ── Stage 1: Build React frontend ─────────────────────────────────────────────
FROM node:22-slim AS frontend-builder

WORKDIR /app/frontend

# Install dependencies first for better layer caching.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ .
RUN npm run build


# ── Stage 2: Production image ──────────────────────────────────────────────────
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
# Put the venv on PATH so no explicit activation is needed.
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-pip \
    exiftool \
    libmpc-dev \
    libgl1 \
    libglib2.0-0 \
    ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create virtualenv and upgrade pip.
RUN python3 -m venv /opt/venv && pip install --no-cache-dir --upgrade pip

# Install Python dependencies before copying source for better caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source (build context is the project root).
COPY . .

# Copy the built React frontend from stage 1.
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Create runtime directories that are mounted as Docker volumes.
RUN mkdir -p sample_storage vault/yara-rules

# Collect Django static files (admin CSS etc.) into staticfiles/.
# SECRET_KEY must be set; DATABASE_URL is not needed for collectstatic.
RUN SECRET_KEY=dummy-build-key python manage.py collectstatic --noinput

EXPOSE 8000

COPY Docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "vault1337.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "4"]
