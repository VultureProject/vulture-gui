# Generated by Django 2.1.3 on 2019-11-19 03:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('darwin', '0007_auto_20190923_1425'),
    ]

    operations = [
        migrations.AlterField(
            model_name='darwinpolicy',
            name='name',
            field=models.TextField(default='Custom Policy', unique=True),
        ),
    ]
