# Generated by Django 3.0.5 on 2021-04-14 02:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0013_auto_20210317_1013'),
    ]

    operations = [
        migrations.AlterField(
            model_name='logomelasticsearch',
            name='index_pattern',
            field=models.TextField(default='MyLog-%$!timestamp:1:10%', unique=True),
        )
    ]
