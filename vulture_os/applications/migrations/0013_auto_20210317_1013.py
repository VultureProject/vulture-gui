# Generated by Django 3.0.5 on 2021-03-17 10:13

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0012_auto_20210126_0546'),
    ]

    operations = [
        migrations.AddField(
            model_name='reputationcontext',
            name='enable_hour_download',
            field=models.BooleanField(default=True),
        ),
        migrations.AlterField(
            model_name='reputationcontext',
            name='content',
            field=models.BinaryField(default=b''),
        ),
        migrations.AlterField(
            model_name='reputationcontext',
            name='db_type',
            field=models.TextField(choices=[('ipv4', 'IPv4 MMDB'), ('ipv6', 'IPv6 MMDB'), ('ipv4_netset', 'IPv4 Netset'), ('ipv6_netset', 'IPv6 Netset'), ('domain', 'Host/Domain names'), ('lookup', 'Rsyslog lookup database'), ('GeoIP', 'GeoIP')], default='ipv4', help_text='Type of database', verbose_name='Database type'),
        ),
    ]
