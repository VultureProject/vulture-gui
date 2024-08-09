# Generated by Django 2.1.3 on 2020-06-02 15:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0009_auto_20191119_0339'),
    ]

    operations = [
        migrations.AddField(
            model_name='server',
            name='mode',
            field=models.TextField(choices=[('net', 'network'), ('unix', 'unix sockets')], default='net', help_text='Server mode (IP, unix socket)'),
        ),
        migrations.AlterField(
            model_name='server',
            name='target',
            field=models.TextField(default='1.2.3.4', help_text='IP/hostname/socket of server'),
        ),
    ]
