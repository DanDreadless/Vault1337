#!/bin/bash

source /opt/Vault1337/venv/bin/activate
# Generate and store Django secret key in .env file
secret_key=$(python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')

# Ensure the .env file exists
touch .env

# Prepend SECRET_KEY to .env
{ echo "SECRET_KEY='$secret_key'"; cat /opt/Vault1337/.env; } > /opt/Vault1337/.env

# Add dummy keys to .env file
cat <<EOF >> .env
VT_KEY='paste_your_virustotal_api_key_here'
MALWARE_BAZAAR_KEY='paste_your_malware_bazaar_api_key_here'
ABUSEIPDB_KEY='paste_your_abuseipdb_api_key_here'
SPUR_KEY='paste_your_spur_api_key_here'
EOF
# Run migrations
python3 manage.py makemigrations --noinput
python3 manage.py migrate --noinput

# Create superuser if it doesn't exist
echo "from django.contrib.auth import get_user_model; \
User = get_user_model(); \
User.objects.filter(username='$DJANGO_SUPERUSER_USERNAME').exists() or \
User.objects.create_superuser('$DJANGO_SUPERUSER_USERNAME', '$DJANGO_SUPERUSER_EMAIL', '$DJANGO_SUPERUSER_PASSWORD')" \
| python3 manage.py shell

# Run the server or passed command
exec "$@"