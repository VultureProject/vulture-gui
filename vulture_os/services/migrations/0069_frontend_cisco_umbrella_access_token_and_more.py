# Generated by Django 4.2.7 on 2024-06-28 09:48

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0068_alter_frontend_filebeat_module_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='frontend',
            name='cisco_umbrella_access_token',
            field=models.TextField(default='', verbose_name='Cisco-Umbrella access token'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='cisco_umbrella_client_id',
            field=models.TextField(default='', help_text='Cisco-Umbrella client id', verbose_name='Cisco-Umbrella client id'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='cisco_umbrella_expires_at',
            field=models.DateTimeField(default=django.utils.timezone.now, verbose_name='Cisco-Umbrella token expiration time'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='cisco_umbrella_secret_key',
            field=models.TextField(default='', help_text='Cisco-Umbrella secret key', verbose_name='Cisco-Umbrella secret key'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='gatewatcher_alerts_api_key',
            field=models.TextField(default='', help_text='Gatewatcher alerts api key', verbose_name='Gatewatcher alerts api key'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='gatewatcher_alerts_host',
            field=models.TextField(default='', help_text='Gatewatcher alerts host', verbose_name='Gatewatcher alerts host'),
        ),
    ]
