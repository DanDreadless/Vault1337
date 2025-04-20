# Use the latest Ubuntu image
FROM ubuntu:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    exiftool \
    python3-venv \
    python3-pip \
    yara \
    libmpc-dev \
    libgl1 \
    libglib2.0-0

# Clone the repository
RUN git clone https://github.com/DanDreadless/Vault1337 /Vault1337

# Set working directory
WORKDIR /Vault1337

# Run install script (assumes it handles venv creation & activation)
RUN chmod +x install.sh && ./install.sh
RUN sed -i "s/ALLOWED_HOSTS = ['127.0.0.1', '192.168.68.126']/ALLOWED_HOSTS = ['localhost']/g" vault1337/settings.py
# Copy entrypoint to activate env before running commands
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose port used by your app
EXPOSE 8000

# Entrypoint ensures virtualenv is activated before running anything
ENTRYPOINT ["/entrypoint.sh"]