# Generated by Django 4.2.9 on 2024-04-02 15:01

from django.db import migrations
import djongo.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0066_frontend_redis_stream_acknowledge_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='frontend',
            name='apex_page_token',
            field=djongo.models.fields.JSONField(default=dict),
        ),
    ]
