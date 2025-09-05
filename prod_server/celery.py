import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "reachlink.settings")
app = Celery("reachlink")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
# Add this if using local time instead of UTC
app.conf.enable_utc = False
app.conf.timezone = 'Asia/Riyadh'
