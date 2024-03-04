# Generated by Django 4.2.7 on 2024-02-21 14:23

import django.core.validators
from django.db import migrations, models
import djongo.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0022_alter_logomkafka_confparam_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='logomhiredis',
            name='expire_key',
            field=models.PositiveIntegerField(blank=True, default=0, help_text='Use SETEX instead of SET in key mode with an expiration in seconds', verbose_name='Expiration of the key (s)'),
        ),
        migrations.AddField(
            model_name='logomhiredis',
            name='mode',
            field=models.TextField(choices=[('queue', 'Queue/list mode, using lpush/rpush'), ('set', 'Set/keys mode, using set/setex'), ('publish', 'Channel mode, using publish'), ('stream', 'Stream mode, using xadd')], default='queue', help_text='Specify how Rsyslog insert logs in Redis', verbose_name='Redis insertion mode'),
        ),
        migrations.AddField(
            model_name='logomhiredis',
            name='stream_capacitylimit',
            field=models.PositiveIntegerField(blank=True, default=0, help_text='Set a stream capacity limit, if set to more than 0 (zero), oldest values in the stream will be evicted to stay under the max value', verbose_name='Maximum stream size'),
        ),
        migrations.AddField(
            model_name='logomhiredis',
            name='stream_outfield',
            field=models.TextField(blank=True, default='msg', help_text='Set the name of the index field to use when inserting log, in stream mode', validators=[django.core.validators.RegexValidator(message="Value shouldn't have any spaces", regex='^\\S+$')], verbose_name='Index name of the log'),
        ),
        migrations.AddField(
            model_name='logomhiredis',
            name='use_rpush',
            field=models.BooleanField(blank=True, default=False, help_text='Use RPUSH instead of LPUSH in list mode', verbose_name='Use RPUSH'),
        ),
    ]
