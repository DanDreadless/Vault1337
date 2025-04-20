# Dockerfile for Vault1337
# Based on Ubuntu 22.04 LTS
FROM ubuntu:22.04

# Set environment variables early
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Install system dependencies (grouped to reduce layers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    exiftool \
    python3-venv \
    python3-pip \
    yara \
    libmpc-dev \
    libgl1 \
    libglib2.0-0 \
    ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Clone the project
WORKDIR /opt
RUN git clone https://github.com/DanDreadless/Vault1337

# Set working directory
WORKDIR /opt/Vault1337

# Create necessary directories
RUN mkdir -p \
    vault/samples \
    vault/yara-rules \
    vault/static/images/media

# Set up virtual environment and install requirements
RUN python3 -m venv /opt/Vault1337/venv && \
    /opt/Vault1337/venv/bin/pip install --upgrade pip && \
    /opt/Vault1337/venv/bin/pip install -r requirements.txt

# Modify Django settings for allowed hosts
RUN sed -i "s/ALLOWED_HOSTS = \['127.0.0.1', '192.168.68.126'\]/ALLOWED_HOSTS = ['localhost']/g" vault1337/settings.py

# Copy entrypoint script to handle venv activation
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Run Django migrations (ignore errors like in shell script)
RUN /opt/Vault1337/venv/bin/python3 manage.py makemigrations || true && \
    /opt/Vault1337/venv/bin/python3 manage.py migrate || true

# Expose default Django port
EXPOSE 8000

# Default entrypoint
ENTRYPOINT ["/entrypoint.sh"]
