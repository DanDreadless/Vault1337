#!/bin/bash

# Update and upgrade system packages
sudo apt update && sudo apt upgrade -y

# Install necessary packages
sudo apt install exiftool libmpc-dev git-all -y

# Prompt user for installation directory
read -p "Enter the directory where you want to clone Vault1337: " install_dir
cd "$install_dir" || { echo "Directory not found. Exiting."; exit 1; }

# Clone the repository
git clone https://github.com/DanDreadless/Vault1337/
cd Vault1337/ || { echo "Cloning failed. Exiting."; exit 1; }

# Change ownership of the repository
read -p "Enter your Linux username: " username
sudo chown -R "$username":"$username" .

# Set up Python virtual environment
python3 -m venv env
source env/bin/activate

# Install required Python packages
pip install -r requirements.txt

# Generate and display Django secret key
secret_key=$(python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')
echo "Your Django secret key is: $secret_key"
echo "Please add this key to your .env file."

# Apply database migrations
python3 manage.py makemigrations
python3 manage.py migrate

# Prompt user to create a superuser
python3 manage.py createsuperuser

# Create necessary directories
mkdir -p vault/samples
mkdir -p vault/yara-rules

# Run the Django development server
python3 manage.py runserver
