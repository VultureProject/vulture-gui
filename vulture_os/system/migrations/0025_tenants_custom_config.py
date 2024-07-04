# Generated by Django 4.2.7 on 2024-07-04 14:46

from django.db import migrations, models
import djongo.models.fields

def set_empty_additional_config(apps, schema_editor):
    tenant_model = apps.get_model("system", "tenants")
    db_alias = schema_editor.connection.alias
    tenant_models = tenant_model.objects.using(db_alias)

    for tenant in tenant_models.all():
        tenant.additional_config = dict()
        tenant.save()
        print(f"Tenant '{tenant.name}' updated")

class Migration(migrations.Migration):

    dependencies = [
        ('system', '0024_config_redis_password_alter_config_cluster_api_key_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenants',
            name='additional_config',
            field=djongo.models.fields.JSONField(blank=True, default=dict, help_text='Add a more flexible configuration for the tenant', verbose_name='Custom tenant configuration'),
        ),
        migrations.RunPython(set_empty_additional_config, migrations.RunPython.noop),
    ]
