# Generated by Django 4.2.9 on 2024-03-12 10:10

from django.db import migrations, models
import django.db.models.deletion
from django.forms.models import model_to_dict

existing_wacls = list()

def save_existing_wacls(apps, schema_editor):
    WACLModel = apps.get_model("workflow", "WorkflowACL")
    db_alias = schema_editor.connection.alias
    WACLs = WACLModel.objects.using(db_alias)

    for wacl in WACLs.all():
        existing_wacls.append(wacl)


def restore_existing_wacls(apps, schema_editor):
    for wacl in existing_wacls:
        wacl.save()

class Migration(migrations.Migration):

    dependencies = [
        ('security', '0001_initial'),
        ('workflow', '0008_workflow_cors_allowed_headers_and_more'),
    ]

    operations = [
        # Need to remove before recreating ForeignKeys because the ID type changes (from ObjectID to AutoField)
        migrations.RunPython(save_existing_wacls, migrations.RunPython.noop, elidable=True),
        migrations.RemoveField(
            model_name='workflowacl',
            name='access_control',
        ),
        migrations.AddField(
            model_name='workflowacl',
            name='access_control',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, to='security.accesscontrol'),
        ),
        migrations.RunPython(restore_existing_wacls, migrations.RunPython.noop, elidable=True),
    ]