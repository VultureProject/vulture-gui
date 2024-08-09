# Generated by Django 4.2.9 on 2024-07-03 20:40

from django.db import migrations
import djongo.models.fields


def add_default_last_collected_timestamps(apps, schema_editor):
    frontend_model = apps.get_model("services", "frontend")
    db_alias = schema_editor.connection.alias
    frontends = frontend_model.objects.using(db_alias)

    for frontend in frontends:
        if not frontend.last_collected_timestamps:
            frontend.last_collected_timestamps = dict()
            frontend.save()

class Migration(migrations.Migration):

    dependencies = [
        ('services', '0069_frontend_cisco_umbrella_access_token_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='frontend',
            name='last_collected_timestamps',
            field=djongo.models.fields.JSONField(default=dict),
        ),
        migrations.RunPython(add_default_last_collected_timestamps, migrations.RunPython.noop),
    ]
