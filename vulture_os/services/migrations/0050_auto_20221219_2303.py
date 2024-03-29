# Generated by Django 3.0.5 on 2022-12-19 23:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0049_auto_20221205_1522'),
    ]

    operations = [
        migrations.AddField(
            model_name='frontend',
            name='proofpoint_trap_apikey',
            field=models.TextField(default='', help_text='ProofPoint TRAP API key', verbose_name='ProofPoint TRAP API key'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='proofpoint_trap_host',
            field=models.TextField(default='', help_text='ProofPoint API root url', verbose_name='ProofPoint TRAP host'),
        ),
    ]
