#!/bin/bash
set -e

# Apply database migrations.
python manage.py migrate --noinput

# Create superuser on first startup if it doesn't exist.
python manage.py shell <<PYEOF
from django.contrib.auth import get_user_model
User = get_user_model()
username = '${DJANGO_SUPERUSER_USERNAME:-admin}'
if not User.objects.filter(username=username).exists():
    User.objects.create_superuser(
        username,
        '${DJANGO_SUPERUSER_EMAIL:-admin@localhost}',
        '${DJANGO_SUPERUSER_PASSWORD:-changeme123}',
    )
    print(f'Superuser "{username}" created.')
else:
    print(f'Superuser "{username}" already exists — skipping.')
PYEOF

exec "$@"
