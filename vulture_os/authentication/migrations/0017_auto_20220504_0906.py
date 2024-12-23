# Generated by Django 3.0.5 on 2022-05-04 09:06

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0016_auto_20211206_1240'),
    ]

    operations = [

        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_timeout',
            field=models.PositiveIntegerField(default=10, help_text='Timeout in seconds before dropping SSO', validators=[django.core.validators.MinValueValidator(1)]),
        ),
    ]
