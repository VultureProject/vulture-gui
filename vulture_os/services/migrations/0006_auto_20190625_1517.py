# Generated by Django 2.1.3 on 2019-06-25 15:17

import django.core.validators
from django.db import migrations, models
import djongo.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0007_auto_20190617_1458'),
        ('services', '0005_openvpn'),
    ]

    operations = [
        migrations.AddField(
            model_name='frontend',
            name='https_redirect',
            field=models.BooleanField(default=False, help_text='Redirect http requests to https, if available', verbose_name='Force HTTP to HTTPS redirection'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='log_forwarders_parse_failure',
            field=djongo.models.fields.ArrayReferenceField(help_text='Log forwarders used in log_condition', null=True, on_delete=djongo.models.fields.ArrayReferenceField._on_delete, related_name='frontend_failure_set', to='applications.LogOM'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='parser_tag',
            field=models.TextField(help_text='Tag used in rsyslog template', null=True),
        ),
        migrations.AlterField(
            model_name='frontend',
            name='log_forwarders',
            field=djongo.models.fields.ArrayReferenceField(help_text='Log forwarders used in log_condition', null=True, on_delete=djongo.models.fields.ArrayReferenceField._on_delete, related_name='frontend_set', to='applications.LogOM'),
        ),
        migrations.AlterField(
            model_name='frontend',
            name='timeout_client',
            field=models.PositiveIntegerField(default=60, help_text='HTTP request Timeout', validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(3600)], verbose_name='Timeout'),
        ),
        migrations.AlterField(
            model_name='frontend',
            name='timeout_connect',
            field=models.PositiveIntegerField(default=5000, help_text='HTTP request Timeout', validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(20000)], verbose_name='Timeout'),
        ),
        migrations.AlterField(
            model_name='frontend',
            name='impcap_intf',
            field=models.ForeignKey(to="system.NetworkInterfaceCard", verbose_name='Listening interface', help_text='Interface used by impcap for trafic listening', null=True, on_delete=models.PROTECT),
        ),
    ]
