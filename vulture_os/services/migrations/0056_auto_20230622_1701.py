# Generated by Django 3.2.19 on 2023-06-22 17:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0055_auto_20230606_1831'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='frontend',
            name='elasticsearch_auth',
        ),
        migrations.RemoveField(
            model_name='frontend',
            name='elasticsearch_host',
        ),
        migrations.RemoveField(
            model_name='frontend',
            name='elasticsearch_index',
        ),
        migrations.RemoveField(
            model_name='frontend',
            name='elasticsearch_password',
        ),
        migrations.RemoveField(
            model_name='frontend',
            name='elasticsearch_username',
        ),
        migrations.RemoveField(
            model_name='frontend',
            name='elasticsearch_verify_ssl',
        ),
        migrations.AddField(
            model_name='frontend',
            name='mmdb_cache_size',
            field=models.PositiveIntegerField(default=0, help_text='Number of entries of the LFU cache for mmdblookup.', verbose_name='mmdblookup LFU cache size'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='nb_workers',
            field=models.PositiveIntegerField(default=8, help_text='Maximum number of workers for rsyslog ruleset', verbose_name='Maximum parser workers'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='redis_batch_size',
            field=models.PositiveIntegerField(default=10, help_text='Size of debatch queue for redis pipeline during *POP operations.', verbose_name='imhiredis debatch queue size'),
        ),
    ]