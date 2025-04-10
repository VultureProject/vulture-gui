# Generated by Django 2.1.3 on 2020-12-01 15:24

from django.db import migrations, models
from datetime import datetime

cybereason_mallops = {}

def before_timestamp_rename(apps, schema_editor):
    frontend_model = apps.get_model("services", "Frontend")
    db_alias = schema_editor.connection.alias
    frontend_objects = frontend_model.objects.using(db_alias)

    for frontend in frontend_objects.all():
        if isinstance(frontend.cybereason_malops_timestamp, datetime):
            cybereason_mallops[frontend.id] = float(frontend.cybereason_malops_timestamp.timestamp())


def after_timestamp_rename(apps, schema_editor):
    frontend_model = apps.get_model("services", "Frontend")
    db_alias = schema_editor.connection.alias
    frontend_objects = frontend_model.objects.using(db_alias)

    for frontend in frontend_objects.all():
        frontend.cybereason_malops_timestamp = cybereason_mallops.get(frontend.id, 0.0)
        frontend.save()


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0022_auto_20201123_1617'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='frontend',
            name='cybereason_malware_timestamp',
        ),
        migrations.AddField(
            model_name='frontend',
            name='cybereason_malwares_timestamp',
            field=models.FloatField(default=0.0),
        ),
        migrations.RunPython(before_timestamp_rename, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name='frontend',
            name='cybereason_malops_timestamp',
        ),
        migrations.AddField(
            model_name='frontend',
            name='cybereason_malops_timestamp',
            field=models.FloatField(default=0.0),
        ),
        migrations.RunPython(after_timestamp_rename, migrations.RunPython.noop),
    ]
