# Generated by Django 2.1.3 on 2020-11-18 13:01

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import djongo.models.fields
from toolkit.mongodb.mongo_base import MongoBase


def set_enrichment_tags(apps, schema_editor):
    mongo = MongoBase()
    if not mongo.connect():
        print("[ERROR] could not connect to mongo to update data !!")
        return
    if not mongo.connect_primary():
        print("[ERROR] could not connect to mongo primary, please reload migration")
        return

    mongo.update_many('vulture', 'darwin_filterpolicy', {}, {"$set": {"enrichment_tags": []}})



class Migration(migrations.Migration):

    dependencies = [
        ('darwin', '0009_darwinfilter_alter_fields'),
    ]

    operations = [
        migrations.CreateModel(
            name='DarwinBuffering',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('interval', models.PositiveIntegerField(default=300, help_text='Number of seconds to cache data before analysing the batch')),
                ('required_log_lines', models.PositiveIntegerField(default=10, help_text='Minimal number of entries to require before launching analysis')),
            ],
        ),
        migrations.RemoveField(
            model_name='darwinpolicy',
            name='filters',
        ),
        migrations.RemoveField(
            model_name='filterpolicy',
            name='conf_path',
        ),
        migrations.AddField(
            model_name='darwinfilter',
            name='can_be_buffered',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='darwinfilter',
            name='longname',
            field=models.TextField(default=''),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='darwinpolicy',
            name='is_internal',
            field=models.BooleanField(default=False, help_text='Whether this policy is a system one'),
        ),
        migrations.AddField(
            model_name='filterpolicy',
            name='enrichment_tags',
            field=djongo.models.fields.JSONField(blank=True, default=list(), help_text='The tag to use as enrichment value for this filter, if none is set the filter type is used'),
        ),
        migrations.AddField(
            model_name='filterpolicy',
            name='weight',
            field=models.FloatField(default=1.0, help_text='The weight of this filter when calculating mean certitude during multiple calls to different filters with the same data', validators=[django.core.validators.MinValueValidator(0.0)]),
        ),
        migrations.AlterField(
            model_name='darwinpolicy',
            name='description',
            field=models.TextField(blank=True, help_text='A description for your policy'),
        ),
        migrations.AlterField(
            model_name='darwinpolicy',
            name='name',
            field=models.TextField(default='Custom Policy', help_text='The friendly name of your policy (should be unique)', unique=True),
        ),
        migrations.AlterField(
            model_name='filterpolicy',
            name='cache_size',
            field=models.PositiveIntegerField(default=0, help_text='The number of cache entries the filter can have to keep previous results', verbose_name='Cache size'),
        ),
        migrations.RemoveField(
            model_name="filterpolicy",
            name="config",
        ),
        migrations.AddField(
            model_name='filterpolicy',
            name='config',
            field=djongo.models.fields.JSONField(blank=True, default={}, help_text='A dictionary containing all specific parameters of this filter'),
        ),
        migrations.AlterField(
            model_name='filterpolicy',
            name='filter',
            field=models.ForeignKey(help_text='The type of darwin filter this instance is', on_delete=django.db.models.deletion.CASCADE, to='darwin.DarwinFilter')
        ),
        migrations.AlterField(
            model_name='filterpolicy',
            name='enabled',
            field=models.BooleanField(default=False, help_text='Wheter this filter should be started'),
        ),
        migrations.AlterField(
            model_name='filterpolicy',
            name='log_level',
            field=models.TextField(choices=[('CRITICAL', 'Critical'), ('ERROR', 'Error'), ('WARNING', 'Warning'), ('INFO', 'Informational'), ('DEBUG', 'Debug')], default='WARNING', help_text='The logging level for this particular instance (closer to DEBUG means more info, but also more disk space taken and less performances overall)'),
        ),
        migrations.AlterField(
            model_name='filterpolicy',
            name='mmdarwin_enabled',
            field=models.BooleanField(default=False, help_text='!!! ADVANCED FEATURE !!! Activates a custom call to Darwin from Rsyslog'),
        ),
        migrations.RemoveField(
            model_name="filterpolicy",
            name="mmdarwin_parameters",
        ),
        migrations.AddField(
            model_name='filterpolicy',
            name='mmdarwin_parameters',
            field=djongo.models.fields.JSONField(blank=True, default=[], help_text='!!! ADVANCED FEATURE !!! the list of rsyslog fields to take when executing the custom call to Darwin (syntax is Rsyslog ', validators=[]),
        ),
        migrations.AlterField(
            model_name='filterpolicy',
            name='nb_thread',
            field=models.PositiveIntegerField(default=5, help_text='The number of concurrent threads to run for this instance (going above 10 is rarely a good idea)'),
        ),
        migrations.AlterField(
            model_name='filterpolicy',
            name='next_filter',
            field=models.ForeignKey(blank=True, default=None, help_text='A potential filter to send results and/or data to continue analysis', null=True, on_delete=django.db.models.deletion.SET_NULL, to='darwin.FilterPolicy'),
        ),
        migrations.AlterField(
            model_name='filterpolicy',
            name='output',
            field=models.TextField(choices=[('NONE', 'Do not send any data to next filter'), ('LOG', 'Send filters alerts to next filter'), ('RAW', 'Send initial body to next filter'), ('PARSED', 'Send parsed body to next filter')], default='NONE', help_text="The type of output this filter should send to the next one (when defined, see 'next_filter'). This should be 'NONE', unless you know what you're doing"),
        ),
        migrations.AlterField(
            model_name='filterpolicy',
            name='policy',
            field=models.ForeignKey(help_text='The policy associated with this filter instance', on_delete=django.db.models.deletion.CASCADE, to='darwin.DarwinPolicy'),
        ),
        migrations.RemoveField(
            model_name="filterpolicy",
            name="status",
        ),
        migrations.AddField(
            model_name='filterpolicy',
            name='status',
            field=djongo.models.fields.JSONField(default={}, help_text="The statuses of the filter on each cluster's node"),
        ),
        migrations.AlterField(
            model_name='filterpolicy',
            name='threshold',
            field=models.PositiveIntegerField(default=80, help_text='The threshold above which the filter should trigger an alert: filters return a certitude between 0 and 100 (inclusive), this tells the filter to raise an alert if the certitude for the data analysed is above or equal to this threshold'),
        ),
        migrations.AlterField(
            model_name='inspectionpolicy',
            name='rules',
            field=djongo.models.fields.ArrayReferenceField(help_text='rules in policy', null=True, on_delete=django.db.models.deletion.PROTECT, to='darwin.InspectionRule'),
        ),
        migrations.AddField(
            model_name='darwinbuffering',
            name='buffer_filter',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='buffers', to='darwin.FilterPolicy'),
        ),
        migrations.AddField(
            model_name='darwinbuffering',
            name='destination_filter',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='buffering', to='darwin.FilterPolicy'),
        ),
        migrations.RenameField(
            model_name='filterpolicy',
            old_name='filter',
            new_name='filter_type',
        ),
        migrations.RunPython(set_enrichment_tags, migrations.RunPython.noop),
    ]
