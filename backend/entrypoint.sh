#!/usr/bin/env sh
set -eu

export HOMEGLUE_DEBUG="${HOMEGLUE_DEBUG:-0}"

python manage.py migrate_with_lock

# Create admin user if env vars are present and user doesn't exist.
python - <<'PY'
import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "homeglue.settings")
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()
username = os.getenv("DJANGO_SUPERUSER_USERNAME")
email = os.getenv("DJANGO_SUPERUSER_EMAIL") or ""
password = os.getenv("DJANGO_SUPERUSER_PASSWORD")

if username and password:
    if not User.objects.filter(username=username).exists():
        User.objects.create_superuser(username=username, email=email, password=password)
PY

python manage.py collectstatic --noinput

exec gunicorn homeglue.wsgi:application \
  --bind 0.0.0.0:8080 \
  --workers 2 \
  --access-logfile - \
  --error-logfile -
