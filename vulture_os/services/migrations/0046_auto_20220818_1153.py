# Generated by Django 3.0.5 on 2022-08-18 11:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0045_auto_20220713_1437'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='frontend',
            name='impcap_filter',
        ),
        migrations.RemoveField(
            model_name='frontend',
            name='impcap_filter_type',
        ),
        migrations.RemoveField(
            model_name='frontend',
            name='impcap_intf',
        ),
        migrations.AddField(
            model_name='frontend',
            name='trendmicro_worryfree_access_token',
            field=models.TextField(default='', help_text='Trendmicro Worryfree access token', verbose_name='Trendmicro Worryfree access token'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='trendmicro_worryfree_secret_key',
            field=models.TextField(default='', help_text='Trendmicro Worryfree secret key', verbose_name='Trendmicro Worryfree secret key'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='trendmicro_worryfree_server_name',
            field=models.TextField(default='cspi.trendmicro.com', help_text='Trendmicro Worryfree server name', verbose_name='Trendmicro Worryfree server name'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='trendmicro_worryfree_server_port',
            field=models.TextField(default='443', help_text='Trendmicro Worryfree server port', verbose_name='Trendmicro Worryfree server port'),
        ),
        migrations.AlterField(
            model_name='frontend',
            name='filebeat_module',
            field=models.TextField(choices=[('_custom', 'Custom Filebeat config'), ('activemq', 'Activemq'), ('aws', 'Aws'), ('awsfargate', 'Awsfargate'), ('azure', 'Azure'), ('barracuda', 'Barracuda'), ('bluecoat', 'Bluecoat'), ('cef', 'Cef'), ('checkpoint', 'Checkpoint'), ('cisco', 'Cisco'), ('coredns', 'Coredns'), ('crowdstrike', 'Crowdstrike'), ('cyberark', 'Cyberark'), ('cyberarkpas', 'Cyberarkpas'), ('cylance', 'Cylance'), ('envoyproxy', 'Envoyproxy'), ('f5', 'F5'), ('fortinet', 'Fortinet'), ('gcp', 'Gcp'), ('google_workspace', 'Google_workspace'), ('googlecloud', 'Googlecloud'), ('gsuite', 'Gsuite'), ('ibmmq', 'Ibmmq'), ('imperva', 'Imperva'), ('infoblox', 'Infoblox'), ('iptables', 'Iptables'), ('juniper', 'Juniper'), ('microsoft', 'Microsoft'), ('misp', 'Misp'), ('mssql', 'Mssql'), ('mysqlenterprise', 'Mysqlenterprise'), ('netflow', 'Netflow'), ('netscout', 'Netscout'), ('o365', 'O365'), ('okta', 'Okta'), ('oracle', 'Oracle'), ('panw', 'Panw'), ('proofpoint', 'Proofpoint'), ('rabbitmq', 'Rabbitmq'), ('radware', 'Radware'), ('snort', 'Snort'), ('snyk', 'Snyk'), ('sonicwall', 'Sonicwall'), ('sophos', 'Sophos'), ('squid', 'Squid'), ('suricata', 'Suricata'), ('threatintel', 'Threatintel'), ('tomcat', 'Tomcat'), ('zeek', 'Zeek'), ('zookeeper', 'Zookeeper'), ('zoom', 'Zoom'), ('zscaler', 'Zscaler')], default='tcp', help_text='Filebeat built-in module'),
        ),
        migrations.AlterField(
            model_name='frontend',
            name='mode',
            field=models.TextField(choices=[('tcp', 'TCP'), ('http', 'HTTP'), ('log', 'LOG (Rsyslog)'), ('filebeat', 'LOG (Filebeat)')], default='tcp', help_text='Listening mode'),
        ),
    ]
