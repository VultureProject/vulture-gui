import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulture_os.settings")
app = Celery("vulture_os")
app.config_from_object("django.conf:settings", namespace="CELERY")

app.conf.beat_schedule = {
    'monitor-vulture': {
        'task': 'daemons.tasks.daemon_task',
        'schedule': 10.0,
        'args': ()
    },
}

app.autodiscover_tasks()