# Generated by Django 3.2.20 on 2023-08-22 09:26

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('system', '0021_auto_20230810_1349'),
        ('applications', '0019_auto_20230719_2137'),
    ]

    operations = [
        migrations.CreateModel(
            name='LogOMKAFKA',
            fields=[
                ('logom_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='applications.logom')),
                ('broker', models.TextField(blank=True, default='["1.2.3.4:9092"]')),
                ('enabled', models.BooleanField(default=True)),
                ('topic', models.TextField()),
                ('key', models.TextField(blank=True)),
                ('dynaKey', models.BooleanField(default=False)),
                ('dynaTopic', models.BooleanField(default=False)),
                ('topicConfParam', models.TextField(blank=True)),
                ('confParam', models.TextField(blank=True)),
                ('partitions_useFixed', models.IntegerField(blank=True)),
                ('partitions_auto', models.BooleanField(default=False)),
            ],
            bases=('applications.logom',),
        ),
        migrations.RemoveField(
            model_name='logomfile',
            name='stock_as_raw',
        ),
        migrations.RemoveField(
            model_name='logomfwd',
            name='send_as_raw',
        ),
        migrations.AddField(
            model_name='backend',
            name='enable_tcp_health_check',
            field=models.BooleanField(default=False, help_text='Enable TCP protocol health checker', verbose_name='TCP health check'),
        ),
        migrations.AddField(
            model_name='backend',
            name='enable_tcp_keep_alive',
            field=models.BooleanField(default=True, help_text='Enable TCP keep-alive', verbose_name='TCP Keep alive'),
        ),
        migrations.AddField(
            model_name='backend',
            name='http_health_check_interval',
            field=models.PositiveIntegerField(default=5, help_text='HTTP Health Check interval', validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(3600)], verbose_name='HTTP Health Check interval'),
        ),
        migrations.AddField(
            model_name='backend',
            name='http_health_check_linger',
            field=models.BooleanField(default=True, help_text='Enable linger to close cleanly the TCP tunnel', verbose_name='Close the connection cleanly'),
        ),
        migrations.AddField(
            model_name='backend',
            name='tcp_health_check_expect_match',
            field=models.TextField(choices=[('', 'None'), ('string', 'Response content contains'), ('rstring', 'Response content match regex'), ('binary', 'Response binary contains'), ('rbinary', 'Response binary match regex'), ('! string', 'Response content does not contain'), ('! rstring', 'Response content does not match regex'), ('! binary', 'Response binary does not contains'), ('! rbinary', 'Response binary does not match regex')], default='', help_text='Type of match to expect', null=True, verbose_name='TCP Health Check expected'),
        ),
        migrations.AddField(
            model_name='backend',
            name='tcp_health_check_expect_pattern',
            field=models.TextField(default='', help_text='Type of pattern to match to expect', verbose_name='TCP Health Check expected pattern'),
        ),
        migrations.AddField(
            model_name='backend',
            name='tcp_health_check_interval',
            field=models.PositiveIntegerField(default=5, help_text='TCP Health Check interval', validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(3600)], verbose_name='TCP Health Check interval'),
        ),
        migrations.AddField(
            model_name='backend',
            name='tcp_health_check_linger',
            field=models.BooleanField(default=True, help_text='Enable linger to close cleanly the TCP tunnel', verbose_name='Close the connection cleanly'),
        ),
        migrations.AddField(
            model_name='backend',
            name='tcp_health_check_send',
            field=models.TextField(default='', help_text='Message sent after connection established', null=True, verbose_name='Message to send'),
        ),
        migrations.AddField(
            model_name='backend',
            name='tcp_keep_alive_timeout',
            field=models.PositiveIntegerField(default=60, help_text='TCP request Timeout', validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(20000)], verbose_name='Timeout'),
        ),
        migrations.AddField(
            model_name='logom',
            name='send_as_raw',
            field=models.BooleanField(default=False, help_text='Send logs without any modification', verbose_name='Send as raw'),
        ),
        migrations.AddField(
            model_name='logomelasticsearch',
            name='data_stream_mode',
            field=models.BooleanField(default=False, help_text='Enable Elasticsearch datastreams support', verbose_name='Enable Elasticsearch datastreams support'),
        ),
        migrations.AddField(
            model_name='logomhiredis',
            name='dynamic_key',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='backend',
            name='http_health_check_version',
            field=models.TextField(choices=[('HTTP/1.0', 'HTTP/1.0'), ('HTTP/1.1', 'HTTP/1.1'), ('HTTP/2', 'HTTP/2')], default='HTTP/1.0', help_text='HTTP version', verbose_name='Version'),
        ),
    ]
