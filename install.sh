#!/bin/bash

# Create necessary directories
mkdir -p vault/samples
mkdir -p vault/yara-rules
mkdir -p vault/static/images/media
mv .env.sample .env

# Set up Python virtual environment
python3 -m venv env
source env/bin/activate

# Install required Python packages with error handling
if pip install -r requirements.txt; then
    echo "Python packages installed successfully."
else
    echo "Failed to install Python packages. Please check the requirements.txt file."
    exit 1
fi

# Apply database migrations
if python3 manage.py makemigrations && python3 manage.py migrate; then
    echo "Database migrations applied successfully."
else
    echo "Failed to apply database migrations."
    exit 1
fi

# Prompt user to create a superuser
if python3 manage.py createsuperuser; then
    echo "Superuser created successfully."
else
    echo "Failed to create superuser."
    exit 1
fi

# Generate and store Django secret key in .env file
secret_key=$(python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')

# Ensure the .env file exists
if [ ! -f .env ]; then
    touch .env
fi

# Remove existing SECRET_KEY if present
sed -i '/^SECRET_KEY=/d' .env

# Insert the new SECRET_KEY at the beginning of the file
echo -e "SECRET_KEY='$secret_key'\n$(cat .env)" > .env

echo "Django secret key has been updated as the first line in .env."