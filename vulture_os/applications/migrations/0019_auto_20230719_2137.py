# Generated by Django 3.2.20 on 2023-07-19 21:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('system', '0020_auto_20230602_2327'),
        ('applications', '0018_auto_20230627_1606'),
    ]

    operations = [
        migrations.AddField(
            model_name='logomelasticsearch',
            name='es8_compatibility',
            field=models.BooleanField(default=False, help_text='Enable Elasticsearch/OpenSearch 8 compatibility', verbose_name='Elasticsearch/OpenSearch 8 compatibility'),
        ),
        migrations.AlterField(
            model_name='logomelasticsearch',
            name='index_pattern',
            field=models.TextField(default='mylog-%$!timestamp:1:10%', unique=True),
        ),
    ]
