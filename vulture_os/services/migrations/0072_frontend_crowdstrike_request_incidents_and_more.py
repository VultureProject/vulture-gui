# Generated by Django 4.2.9 on 2024-07-19 08:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0071_frontend_waf_barracuda_token'),
    ]

    operations = [
        migrations.AddField(
            model_name='frontend',
            name='crowdstrike_request_incidents',
            field=models.BooleanField(default=True, help_text='Request Crowdstrike incident api', verbose_name='Get incident logs'),
        ),
    ]