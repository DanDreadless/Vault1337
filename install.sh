#!/bin/bash

# Create necessary directories
mkdir -p vault/samples
mkdir -p vault/yara-rules
mkdir -p vault/static/images/media


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

# Insert the new SECRET_KEY at the beginning of the file
echo -e "SECRET_KEY='$secret_key'$(cat .env)" > .env

echo "Django secret key has been generated and stored in .env file."
echo "Adding dummy keys to .env file. Please update them with your own keys."
# Add dummy keys to .env file
cat <<EOF >> .env
VT_KEY='paste_your_virustotal_api_key_here'
MALWARE_BAZAAR_KEY='paste_your_malware_bazaar_api_key_here'
ABUSEIPDB_KEY='paste_your_abuseipdb_api_key_here'
SPUR_KEY='paste_your_spur_api_key_here'
EOF

deactivate

echo "install.sh completed successfully."
echo "You can now run the application using 'source env/bin/activate' and 'python3 manage.py runserver'."