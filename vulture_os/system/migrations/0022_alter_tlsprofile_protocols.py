# Generated by Django 3.2.20 on 2023-07-19 21:39

from django.db import migrations, models
import djongo.models.fields


existing_profiles_protocols = {}

def save_tls_protocols(apps, schema_editor):
    tls_profile_model = apps.get_model("system", "tlsprofile")
    db_alias = schema_editor.connection.alias
    tls_profile = tls_profile_model.objects.using(db_alias)

    for profile in tls_profile.all():
        existing_profiles_protocols[profile.id] = profile.protocols


def update_tls_protocols(apps, schema_editor):
    tls_profile_model = apps.get_model("system", "tlsprofile")
    db_alias = schema_editor.connection.alias
    tls_profile = tls_profile_model.objects.using(db_alias)

    for profile in tls_profile.all():
        # put back configured protocols
        profile.protocols = existing_profiles_protocols[profile.id]

        # replace old default with new default
        if profile.protocols == ['tlsv12']:
            profile.protocols = ['tlsv13', 'tlsv12']

        profile.save()


class Migration(migrations.Migration):

    dependencies = [
        ('system', '0021_auto_20230810_1349'),
    ]

    operations = [
        migrations.RunPython(save_tls_protocols, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name="tlsprofile",
            name="protocols",
        ),
        migrations.AddField(
            model_name="tlsprofile",
            name="protocols",
            field=djongo.models.fields.JSONField(default=['tlsv13', 'tlsv12'], help_text='Allowed protocol ciphers.', verbose_name=models.TextField(choices=[('tlsv13', 'TLSv1.3'), ('tlsv12', 'TLSv1.2'), ('tlsv11', 'TLSv1.1'), ('tlsv10', 'TLSv1.0')])),
        ),
        migrations.RunPython(update_tls_protocols, migrations.RunPython.noop),
    ]