# Generated by Django 4.2.9 on 2024-07-10 16:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0074_frontend_lockself_host_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='frontend',
            name='cisco_meraki_get_security_logs',
            field=models.BooleanField(default=False, help_text='Get security logs', verbose_name='Get security logs'),
        ),
    ]
