# Generated by Django 3.0.5 on 2022-06-14 13:36

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('workflow', '0006_auto_20210701_0205'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='workflow',
            name='defender_policy',
        ),
    ]