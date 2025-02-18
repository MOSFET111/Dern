#!/bin/bash
# Exit on error
set -o errexit

# Create and activate a virtual environment
python -m venv dernenv
source dernenv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Collect static files
python manage.py collectstatic --noinput