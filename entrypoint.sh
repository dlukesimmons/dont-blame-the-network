#!/bin/bash
set -e

# Add split-tunnel route through ftd-vpn container if available
FTD_IP=$(getent hosts ftd-vpn 2>/dev/null | awk '{print $1}')
if [ -n "$FTD_IP" ]; then
    ip route add 10.0.69.0/24 via "$FTD_IP" 2>/dev/null && \
        echo "VPN route: 10.0.69.0/24 via ftd-vpn ($FTD_IP)" || \
        echo "VPN route already set or failed — continuing"
fi

echo "Waiting for MySQL to be ready..."
until python -c "
import pymysql, os, sys
try:
    pymysql.connect(
        host=os.environ.get('DB_HOST', 'db'),
        user=os.environ.get('DB_USER', 'dbtn'),
        password=os.environ.get('DB_PASSWORD', 'dbtn-password'),
        database=os.environ.get('DB_NAME', 'dbtn'),
    ).close()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; do
    echo "  MySQL not ready, retrying in 3s..."
    sleep 3
done
echo "MySQL ready."

echo "Running migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Creating superuser if not exists..."
python manage.py shell -c "
from accounts.models import User
if not User.objects.filter(username='${DJANGO_SUPERUSER_USERNAME:-admin}').exists():
    User.objects.create_superuser(
        username='${DJANGO_SUPERUSER_USERNAME:-admin}',
        email='${DJANGO_SUPERUSER_EMAIL:-admin@local.lan}',
        password='${DJANGO_SUPERUSER_PASSWORD:-admin}'
    )
    print('Superuser created.')
else:
    print('Superuser already exists.')
"

echo "Starting gunicorn..."
exec gunicorn dbtn_project.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 3 \
    --timeout 3600 \
    --access-logfile - \
    --error-logfile -
