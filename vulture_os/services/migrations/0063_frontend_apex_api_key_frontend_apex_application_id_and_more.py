# Generated by Django 4.2.6 on 2023-11-23 14:33

import django.core.validators
from django.db import migrations, models
import djongo.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0062_remove_frontend_timeout_connect_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='frontend',
            name='apex_api_key',
            field=models.TextField(default='', help_text='Apex api key', verbose_name='Apex api key'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='apex_application_id',
            field=models.TextField(default='', help_text='Apex application id', verbose_name='Apex application id'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='apex_server_host',
            field=models.TextField(default='', help_text='Apex server host', verbose_name='Apex server host'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='apex_timestamp',
            field=djongo.models.fields.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='frontend',
            name='custom_tl_frame_delimiter',
            field=models.IntegerField(default=-1, blank=True, help_text='Additional frame delimiter', validators=[django.core.validators.MinValueValidator(-1), django.core.validators.MaxValueValidator(255)], verbose_name='Additional frame delimiter'),
        ),
    ]
