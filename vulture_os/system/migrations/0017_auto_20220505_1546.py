# Generated by Django 3.0.5 on 2022-05-05 15:46

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('system', '0016_auto_20210317_1013'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='zfs',
            name='node',
        ),
        migrations.RemoveField(
            model_name='tenants',
            name='predator_apikey',
        ),
        migrations.RemoveField(
            model_name='tenants',
            name='shodan_apikey',
        ),
        migrations.DeleteModel(
            name='VM',
        ),
        migrations.DeleteModel(
            name='ZFS',
        ),
    ]