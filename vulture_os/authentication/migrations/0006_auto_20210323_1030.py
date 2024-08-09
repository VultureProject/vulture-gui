# Generated by Django 3.0.5 on 2021-03-23 10:30

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0029_auto_20210317_0955'),
        ('authentication', '0005_auto_20210317_0955'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='templateimage',
            name='uid',
        ),
        migrations.AddField(
            model_name='templateimage',
            name='content',
            field=models.TextField(default='', help_text='Image you can use in the portal templates'),
        ),
        migrations.AddField(
            model_name='templateimage',
            name='image_type',
            field=models.TextField(default=''),
        ),
        migrations.AlterField(
            model_name='templateimage',
            name='name',
            field=models.TextField(default='', help_text='The name of the image'),
        ),
        migrations.AlterField(
            model_name='userauthentication',
            name='external_listener',
            field=models.ForeignKey(help_text='Listener used for external portal', null=True, on_delete=django.db.models.deletion.SET_NULL, to='services.Frontend', verbose_name='Listen on'),
        ),
    ]
