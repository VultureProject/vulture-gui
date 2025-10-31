#!/home/vlt-os/env/bin/python
"""This file is part of Vulture OS.

Vulture OS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture OS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture OS.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Kevin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Frontends & Listeners dedicated form classes'

# Django system imports
import ast
from django.conf import settings
from django.core.validators import RegexValidator
from django.forms import (BooleanField, CharField, CheckboxInput, ChoiceField, ModelChoiceField, ModelMultipleChoiceField, Form,
                          ModelForm, NumberInput, Select, SelectMultiple, TextInput, Textarea, URLField, HiddenInput)
from django.utils.translation import gettext_lazy as _

# Django project imports
from applications.logfwd.models import LogOM
from applications.reputation_ctx.models import ReputationContext
from darwin.policy.models import DarwinPolicy
from gui.forms.form_utils import NoValidationField
from services.frontend.models import (Frontend, FrontendReputationContext, Listener, COMPRESSION_ALGO_CHOICES,
                                      LISTENING_MODE_CHOICES, LOG_LEVEL_CHOICES, MODE_CHOICES, DARWIN_MODE_CHOICES,
                                      REDIS_MODE_CHOICES, REDIS_STARTID_CHOICES,
                                      FILEBEAT_LISTENING_MODE, FILEBEAT_MODULE_LIST, SENTINEL_ONE_ACCOUNT_TYPE_CHOICES,
                                      get_available_timezones)

from services.rsyslogd.form import RsyslogQueueForm
from services.rsyslogd.rsyslog import JINJA_PATH as JINJA_RSYSLOG_PATH
from system.cluster.models import NetworkAddress
from system.error_templates.models import ErrorTemplate
from toolkit.api_parser.utils import get_available_api_parser
from toolkit.network.network import parse_proxy_url
from system.pki.models import TLSProfile, X509Certificate
from system.cluster.models import Node
from system.tenants.models import Tenants

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from django.forms import ValidationError

# Extern modules imports
from ast import literal_eval as ast_literal_eval
from ipaddress import ip_address
from json import loads as json_loads
from mimetypes import guess_extension as mime_guess_ext
from os import scandir
from os.path import exists as path_exists
from re import search as re_search, match as re_match

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class FrontendReputationContextForm(ModelForm):
    """ Form class for intermediary model between Frontend & ReputationContext """
    class Meta:
        model = FrontendReputationContext
        fields = ("enabled", "reputation_ctx", "arg_field", "dst_field")

        widgets = {
            'enabled': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'reputation_ctx': Select(attrs={'class': "form-control select2"}),
            'arg_field': TextInput(attrs={'class': "form-control", 'placeholder': "src_ip"}),
            'dst_field': TextInput(attrs={'class': "form-control", 'placeholder': "src_reputation"})
        }

    def __init__(self, *args, **kwargs):
        """ Initialisation of fields method """
        # Do not set id of html fields, that causes issues in JS/JQuery
        kwargs['auto_id'] = False
        super().__init__(*args, **kwargs)
        self.fields['reputation_ctx'].empty_label = None

    def as_table_headers(self):
        """ Format field names as table head """
        result = "<tr>\n"
        for field in self:
            result += "<th>{}</th>\n".format(field.label)
        result += "<th>Delete</th></tr>\n"
        return result

    def as_table_td(self):
        """ Format fields as a table with <td></td> """
        result = "<tr>"
        for field in self:
            result += "<td>{}</td>\n".format(field)
        result += "<td style='text-align:center'><a class='btnDelete'><i style='color:grey' " \
                  "class='fas fa-trash-alt'></i></a></td></tr>\n"
        return result


class FrontendForm(RsyslogQueueForm, ModelForm):
    listeners = NoValidationField()
    headers = NoValidationField()
    reputation_ctx = NoValidationField()
    keep_source_fields = NoValidationField()
    redis_use_local = BooleanField(
        widget=CheckboxInput(attrs={'class': 'js-switch'})
    )

    REDIS_DEFAULT_SERVER = '127.0.0.5'
    REDIS_DEFAULT_PORT = 6379

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        AVAILABLE_API_PARSER = [("", "--------")]
        AVAILABLE_API_PARSER.extend([(parser, parser.upper().replace('_', ' '))
                                     for parser in get_available_api_parser()])

        """ Darwin policy """
        self.fields['darwin_policies'] = ModelMultipleChoiceField(
            label=_("Darwin policies"),
            queryset=DarwinPolicy.objects.filter(is_internal=False),
            widget=SelectMultiple(attrs={'class': 'form-control select2'}),
            required=False
        )
        """ Log forwarders """
        self.fields['log_forwarders'] = ModelMultipleChoiceField(
            label=_("Log forwarders"),
            queryset=LogOM.objects.all().only(*LogOM.str_attrs()),
            widget=SelectMultiple(attrs={'class': 'form-control select2'}),
            required=False
        )
        """ Log forwarders """
        self.fields['log_forwarders_parse_failure'] = ModelMultipleChoiceField(
            label=_("Log forwarders - parse failure"),
            queryset=LogOM.objects.all().only(*LogOM.str_attrs()),
            widget=SelectMultiple(attrs={'class': 'form-control select2'}),
            required=False
        )
        """ MMDP Reputation database IPv4 """
        # Defined here AND in model, to use queryset
        self.fields['logging_reputation_database_v4'] = ModelChoiceField(
            label=_("Rsyslog IPv4 reputation database"),
            # queryset=[(f.get('id'), str(f)) for f in Feed.objects.mongo_find({"filename": {"$regex": r"\.mmdb$"},  # MMDB database
            #                                   "label": {"$regex": r"^((?![iI][Pp][Vv]6).)*$"}},  # Excude IPv6
            #                                  {"filename": 1, "label": 1})],  # .only( label, filename )
            # queryset=Feed.objects.filter(filename__iregex="^((?![iI][Pp][Vv]6).)*\.mmdb$"),
            # queryset=Feed.objects.exclude(filename__iregex="^((?![iI][Pp][Vv]6).)*$").filter(filename__endswith=".mmdb"),
            queryset=ReputationContext.objects.filter(db_type="ipv4", filename__endswith=".mmdb")
                                      .only(*(ReputationContext.str_attrs() + ['filename', 'db_type'])),
            widget=Select(attrs={'class': 'form-control select2'}),
            empty_label="No IPv4",
            required=False
        )
        """ MMDP Reputation database IPv6 """
        # Defined here AND in model, to use queryset
        self.fields['logging_reputation_database_v6'] = ModelChoiceField(
            label=_("Rsyslog IPv6 reputation database"),
            queryset=ReputationContext.objects.filter(db_type="ipv6",
                                                      filename__endswith=".mmdb")  # MMDP database & IPv6
            .only(*(ReputationContext.str_attrs() + ['filename', 'db_type'])),
            widget=Select(attrs={'class': 'form-control select2'}),
            empty_label="No IPv6",
            required=False
        )
        self.fields['logging_geoip_database'] = ModelChoiceField(
            label=_("Rsyslog GeoIP database"),
            queryset=ReputationContext.objects.filter(db_type="GeoIP")
                                      .only(*(ReputationContext.str_attrs() + ['filename', 'db_type'])),
            widget=Select(attrs={'class': 'form-control select2'}),
            empty_label="No GeoIP",
            required=False
        )

        self.fields['node'] = ModelChoiceField(
            label=_('Node'),
            queryset=Node.objects.all(),
            widget=Select(attrs={'class': 'form-control select2'})
        )

        self.fields['forcepoint_host'] = URLField(
            label=_('Forcepoint URL'),
            widget=TextInput(attrs={'class': 'form-control'})
        )

        self.fields['api_parser_type'] = ChoiceField(
            label=_('API Parser'),
            choices=AVAILABLE_API_PARSER,
            widget=Select(attrs={'class': 'form-control select2'})
        )

        # Remove the blank input generated by django
        for field_name in ['mode', 'ruleset', 'log_level', 'listening_mode', 'filebeat_listening_mode', 'filebeat_module',
                            'filebeat_config', 'compression_algos', 'log_forwarders', 'tenants_config']:
            self.fields[field_name].empty_label = None
        self.fields['error_template'].empty_label = "No template"
        # Set required in POST data to False
        for field_name in ['log_condition', 'keep_source_fields', 'ruleset', 'log_level', 'listening_mode',
                           'filebeat_listening_mode', 'filebeat_module', 'filebeat_config', 'headers', 'custom_actions', 'custom_haproxy_conf',
                           'cache_total_max_size', 'cache_max_age', 'compression_algos', 'compression_mime_types',
                           'error_template', 'tenants_config', 'enable_logging_reputation', 'tags', 'timeout_client', 'timeout_keep_alive',
                           'parser_tag', 'file_path', 'ratelimit_interval', 'ratelimit_burst', 'expected_timezone',
                           'kafka_brokers', 'kafka_topic', 'kafka_consumer_group', 'kafka_options',
                           'healthcheck_service', 'mmdb_cache_size','redis_batch_size', 'redis_use_local',
                           'redis_mode', 'redis_use_lpop', 'redis_server', 'redis_port', 'redis_key', 'redis_password',
                           'node', 'darwin_mode', 'api_parser_type', 'api_parser_use_proxy', 'api_parser_custom_proxy',
                           'api_parser_verify_ssl', 'api_parser_custom_certificate',
                           'forcepoint_host', 'forcepoint_username', 'forcepoint_password', "symantec_username", "symantec_password",
                           "aws_access_key_id", "aws_secret_access_key", "aws_bucket_name", "akamai_host",
                           "akamai_client_secret", "akamai_access_token", "akamai_client_token", 'akamai_config_id',
                           'office365_tenant_id', 'office365_client_id', 'office365_client_secret',
                           'imperva_base_url', 'imperva_api_key', 'imperva_api_id',
                           'imperva_private_key', 'reachfive_host', 'reachfive_client_id', 'reachfive_client_secret',
                           'mongodb_api_user', 'mongodb_api_password', 'mongodb_api_group_id',
                           "mdatp_api_tenant", "mdatp_api_appid", "mdatp_api_secret",
                           "cortex_xdr_host", "cortex_xdr_apikey_id", "cortex_xdr_apikey", "cortex_xdr_advanced_token",
                           "cybereason_host", "cybereason_username", "cybereason_password",
                           "cisco_meraki_apikey", "cisco_meraki_get_security_logs", "cisco_meraki_get_configuration_changes_logs",
                           'proofpoint_tap_host', 'proofpoint_tap_endpoint', 'proofpoint_tap_principal',
                           "carbon_black_host", 'carbon_black_orgkey', 'carbon_black_apikey',
                           "netskope_host", 'netskope_apikey', 'netskope_get_page_logs', 'netskope_get_network_logs', 'netskope_get_application_logs',
                           'rapid7_idr_host', 'rapid7_idr_apikey',
                           'harfanglab_host', 'harfanglab_apikey',
                           'nozomi_probe_host', 'nozomi_probe_login', 'nozomi_probe_password',
                           'vadesecure_host', 'vadesecure_login', 'vadesecure_password',
                           'defender_token_endpoint', 'defender_client_id', 'defender_client_secret',
                           'proofpoint_tap_secret', 'sentinel_one_host', 'sentinel_one_apikey', 'sentinel_one_account_type',
                           'crowdstrike_request_incidents','crowdstrike_host','crowdstrike_client_id','crowdstrike_client_secret','crowdstrike_client',
                           'vadesecure_o365_host','vadesecure_o365_tenant','vadesecure_o365_client_id',
                           'vadesecure_o365_client_secret',
                           'blackberry_cylance_host','blackberry_cylance_tenant','blackberry_cylance_app_id',
                           'blackberry_cylance_app_secret',
                           'ms_sentinel_tenant_id', 'ms_sentinel_appid', 'ms_sentinel_appsecret',
                           'sentinel_one_singularity_mobile_host', 'sentinel_one_singularity_mobile_client_id', 'sentinel_one_singularity_mobile_client_secret',
                           'ms_sentinel_subscription_id', 'ms_sentinel_resource_group', 'ms_sentinel_workspace',
                           'proofpoint_pod_uri', 'proofpoint_pod_cluster_id', 'proofpoint_pod_token',
                           'waf_cloudflare_apikey','waf_cloudflare_zoneid',
                           'gsuite_alertcenter_json_conf', 'gsuite_alertcenter_admin_mail',
                           'sophos_cloud_client_id', 'sophos_cloud_client_secret', 'sophos_cloud_tenant_id',
                           'trendmicro_worryfree_access_token', 'trendmicro_worryfree_secret_key', 'trendmicro_worryfree_server_name',
                           'trendmicro_worryfree_server_port',
                           'safenet_tenant_code', 'safenet_apikey',
                           'signalsciences_ngwaf_email', 'signalsciences_ngwaf_token', 'signalsciences_ngwaf_corp_name', 'signalsciences_ngwaf_site_name',
                           'proofpoint_casb_api_key','proofpoint_casb_client_id','proofpoint_casb_client_secret',
                           'proofpoint_trap_host', 'proofpoint_trap_apikey',
                           'waf_cloud_protector_host', 'waf_cloud_protector_api_key_pub', 'waf_cloud_protector_api_key_priv',
                           'waf_cloud_protector_provider', 'waf_cloud_protector_tenant', 'waf_cloud_protector_servers',
                           'trendmicro_visionone_token',
                           'cisco_duo_host', 'cisco_duo_ikey', 'cisco_duo_skey',
                           'sentinel_one_mobile_host', 'sentinel_one_mobile_apikey',
                           'csc_domainmanager_apikey', 'csc_domainmanager_authorization',
                           'retarus_token', 'retarus_channel', 'vectra_host', 'vectra_client_id', 'vectra_secret_key',
                           'apex_server_host', 'apex_application_id', 'apex_api_key',
                           'gatewatcher_alerts_host', 'gatewatcher_alerts_api_key',
                           'cisco_umbrella_client_id', 'cisco_umbrella_secret_key',
                           'waf_barracuda_token',
                           "beyondtrust_pra_client_id", "beyondtrust_pra_secret", "beyondtrust_pra_host",
                           "lockself_x_auth_token", "lockself_x_ls_token", "lockself_host", "lockself_organization_id",
                           "cisco_umbrella_managed_org_api_key", "cisco_umbrella_managed_org_secret_key", "cisco_umbrella_managed_org_customers_id",
                           "cisco_umbrella_managed_org_get_dns", "cisco_umbrella_managed_org_get_proxy",
                           "catonetworks_account_id", "catonetworks_api_key",
                           "infoblox_threat_defense_host", "infoblox_threat_defense_token",
                           "beyondtrust_reportings_client_id", "beyondtrust_reportings_secret", "beyondtrust_reportings_host",
                           "beyondtrust_reportings_get_team_logs", "beyondtrust_reportings_get_access_session_logs", "beyondtrust_reportings_get_vault_account_activity_logs", "beyondtrust_reportings_get_support_session_logs",
                           "varonis_host", "varonis_api_key",
                           "armis_centrix_host", "armis_centrix_secretkey", "armis_centrix_get_activity_logs",
                           "perception_point_x_ray_host", "perception_point_x_ray_token", "perception_point_x_ray_organization_id", "perception_point_x_ray_environment_id", "perception_point_x_ray_case_types",
                           "extrahop_host", "extrahop_id", "extrahop_secret",
                           "hornetsecurity_app_id", "hornetsecurity_token",
                           "ubika_base_refresh_token", "ubika_namespaces",
                            "sentinel_one_graph_token", "sentinel_one_graph_console_url",
                           'messagetrace_o365_tenant_id', 'messagetrace_o365_client_id', 'messagetrace_o365_client_secret',
                           'cnapp_wiz_client_id', 'cnapp_wiz_client_secret', 'cnapp_wiz_api_url',
                           ]:
            self.fields[field_name].required = False

        """ Build choices of "ruleset" field with rsyslog jinja templates names """
        # read the entries
        try:
            with scandir(JINJA_RSYSLOG_PATH) as listOfEntries:
                for entry in listOfEntries:
                    if entry.is_dir():
                        m = re_search("rsyslog_ruleset_([\w-]+)", entry.name)
                        if m:
                            # Do NOT process haproxy - it's an internal log type
                            if m.group(1) in ("haproxy", "haproxy_tcp"):
                                continue

                            self.fields['ruleset'].widget.choices.append((m.group(1), m.group(1)))
        except Exception as e:
            logger.error("Cannot build 'ruleset' choices. Seems that path '{}' is not found: ".format(
                JINJA_RSYSLOG_PATH
            ))
            logger.exception(e)

        # Set initial value of compression_algos field,
        #  convert space separated string into list
        if self.initial.get('compression_algos'):
            self.initial['compression_algos'] = self.initial.get('compression_algos').split(' ')

        # Convert list field from model to text input comma separated
        self.initial['tags'] = ','.join(self.initial.get('tags', []) or self.fields['tags'].initial)
        self.initial['kafka_brokers'] = ",".join(self.initial.get('kafka_brokers', []) or self.fields['kafka_brokers'].initial)
        self.initial['kafka_options'] = ",".join(self.initial.get('kafka_options', []) or self.fields['kafka_options'].initial)
        self.initial['cisco_umbrella_managed_org_customers_id'] = ",".join(self.initial.get('cisco_umbrella_managed_org_customers_id', []) or self.fields['cisco_umbrella_managed_org_customers_id'].initial)
        self.initial['ubika_namespaces'] = ",".join(self.initial.get('ubika_namespaces', []) or self.fields['ubika_namespaces'].initial)
        self.initial['perception_point_x_ray_case_types'] = ",".join([str(case_type) for case_type in (self.initial.get('perception_point_x_ray_case_types', []) or self.fields['perception_point_x_ray_case_types'].initial)])

        if not self.fields['keep_source_fields'].initial:
            self.fields['keep_source_fields'].initial = dict(self.initial.get('keep_source_fields') or {}) or "{}"

        if  not self.instance or \
            self.instance.redis_server == self.REDIS_DEFAULT_SERVER and \
            self.instance.redis_port == self.REDIS_DEFAULT_PORT:
            self.fields['redis_use_local'].initial = True

    class Meta:
        model = Frontend
        fields = ['enabled', 'tags', 'name', 'mode', 'enable_logging', 'log_level', 'log_condition', 'keep_source_fields', 'ruleset',
                  'listening_mode', 'filebeat_listening_mode', 'filebeat_module', 'filebeat_config',
                  'custom_actions', 'custom_haproxy_conf', 'enable_cache', 'cache_total_max_size', 'cache_max_age',
                  'enable_compression', 'compression_algos', 'compression_mime_types', 'error_template',
                  'log_forwarders', 'tenants_config', 'enable_logging_reputation', 'logging_reputation_database_v4',
                  'logging_reputation_database_v6', 'logging_geoip_database', 'timeout_client',
                  'timeout_keep_alive', 'disable_octet_counting_framing', 'custom_tl_frame_delimiter',
                  'https_redirect', 'log_forwarders_parse_failure', 'parser_tag',
                  'ratelimit_interval', 'ratelimit_burst', 'expected_timezone', 'file_path',
                  'kafka_brokers', 'kafka_topic', 'kafka_consumer_group', 'kafka_options',
                  'healthcheck_service', 'mmdb_cache_size','redis_batch_size', 'redis_mode', 'redis_use_lpop',
                  'redis_server', 'redis_port', 'redis_key', 'redis_password', 'redis_stream_consumerGroup',
                  'redis_stream_consumerName', 'redis_stream_startID', 'redis_stream_acknowledge', 'redis_stream_reclaim_timeout',
                  'node', 'darwin_policies', 'darwin_mode', 'api_parser_type', 'api_parser_use_proxy',
                  'api_parser_custom_proxy', 'api_parser_verify_ssl', 'api_parser_custom_certificate',
                  'forcepoint_host', 'forcepoint_username', 'forcepoint_password',
                  "symantec_username", "symantec_password",
                  "aws_access_key_id", "aws_secret_access_key", "aws_bucket_name",
                  "akamai_host", "akamai_client_secret", "akamai_access_token", "akamai_client_token", 'akamai_config_id',
                  'office365_tenant_id', 'office365_client_id', 'office365_client_secret',
                  'imperva_base_url', 'imperva_api_key', 'imperva_api_id', 'imperva_private_key',
                  'reachfive_host', 'reachfive_client_id', 'reachfive_client_secret',
                  'mongodb_api_user', 'mongodb_api_password', 'mongodb_api_group_id',
                  "mdatp_api_tenant", "mdatp_api_appid", "mdatp_api_secret",
                  "cortex_xdr_host", "cortex_xdr_apikey_id", "cortex_xdr_apikey", "cortex_xdr_advanced_token",
                  "cybereason_host", "cybereason_username", "cybereason_password",
                  "cisco_meraki_apikey", "cisco_meraki_get_security_logs", "cisco_meraki_get_configuration_changes_logs",
                  'proofpoint_tap_host', 'proofpoint_tap_endpoint', 'proofpoint_tap_principal',
                  "proofpoint_tap_secret",
                  "sentinel_one_host", "sentinel_one_apikey", "sentinel_one_account_type",
                  'netskope_host', 'netskope_apikey', 'netskope_get_page_logs', 'netskope_get_network_logs', 'netskope_get_application_logs',
                  'rapid7_idr_host', 'rapid7_idr_apikey',
                  'harfanglab_host', 'harfanglab_apikey',
                  'nozomi_probe_host', 'nozomi_probe_login', 'nozomi_probe_password',
                  'vadesecure_host', 'vadesecure_login', 'vadesecure_password',
                  "carbon_black_host", "carbon_black_orgkey", "carbon_black_apikey",
                  'defender_token_endpoint', 'defender_client_id', 'defender_client_secret',
                  'crowdstrike_request_incidents','crowdstrike_host','crowdstrike_client_id','crowdstrike_client_secret','crowdstrike_client',
                  'vadesecure_o365_host','vadesecure_o365_tenant','vadesecure_o365_client_id',
                  'vadesecure_o365_client_secret',
                  'blackberry_cylance_host','blackberry_cylance_tenant','blackberry_cylance_app_id',
                  'blackberry_cylance_app_secret',
                  'ms_sentinel_tenant_id', 'ms_sentinel_appid', 'ms_sentinel_appsecret', 'ms_sentinel_subscription_id',
                  'ms_sentinel_resource_group', 'ms_sentinel_workspace',
                  'sentinel_one_singularity_mobile_host', 'sentinel_one_singularity_mobile_client_id',
                  'sentinel_one_singularity_mobile_client_secret',
                  'proofpoint_pod_uri', 'proofpoint_pod_cluster_id', 'proofpoint_pod_token',
                  'waf_cloudflare_apikey', 'waf_cloudflare_zoneid',
                  'gsuite_alertcenter_json_conf', 'gsuite_alertcenter_admin_mail',
                  'sophos_cloud_client_id', 'sophos_cloud_client_secret', 'sophos_cloud_tenant_id',
                  'trendmicro_worryfree_access_token', 'trendmicro_worryfree_secret_key', 'trendmicro_worryfree_server_name',
                  'trendmicro_worryfree_server_port', 'safenet_tenant_code', 'safenet_apikey',
                  'signalsciences_ngwaf_email', 'signalsciences_ngwaf_token', 'signalsciences_ngwaf_corp_name', 'signalsciences_ngwaf_site_name',
                  'proofpoint_casb_api_key','proofpoint_casb_client_id','proofpoint_casb_client_secret',
                  'proofpoint_trap_host', 'proofpoint_trap_apikey',
                  'waf_cloud_protector_host', 'waf_cloud_protector_api_key_pub', 'waf_cloud_protector_api_key_priv',
                  'waf_cloud_protector_provider', 'waf_cloud_protector_tenant', 'waf_cloud_protector_servers',
                  'trendmicro_visionone_token',
                  'cisco_duo_host', 'cisco_duo_ikey', 'cisco_duo_skey',
                  'sentinel_one_mobile_host', 'sentinel_one_mobile_apikey',
                  'csc_domainmanager_apikey', 'csc_domainmanager_authorization',
                  'retarus_token', 'retarus_channel', 'vectra_host', 'vectra_secret_key', 'vectra_client_id',
                  'apex_server_host', 'apex_application_id', 'apex_api_key',
                  'gatewatcher_alerts_host', 'gatewatcher_alerts_api_key',
                  'cisco_umbrella_client_id', 'cisco_umbrella_secret_key',
                  'waf_barracuda_token',
                  "beyondtrust_pra_client_id", "beyondtrust_pra_secret", "beyondtrust_pra_host",
                  'lockself_x_auth_token', 'lockself_x_ls_token', 'lockself_host', 'lockself_organization_id',
                  'cisco_umbrella_managed_org_api_key', 'cisco_umbrella_managed_org_secret_key', 'cisco_umbrella_managed_org_customers_id',
                  'cisco_umbrella_managed_org_get_dns', 'cisco_umbrella_managed_org_get_proxy',
                  'catonetworks_api_key', 'catonetworks_account_id',
                  "infoblox_threat_defense_host", "infoblox_threat_defense_token",
                  "beyondtrust_reportings_client_id", "beyondtrust_reportings_secret", "beyondtrust_reportings_host",
                  "beyondtrust_reportings_get_team_logs", "beyondtrust_reportings_get_access_session_logs",
                  "beyondtrust_reportings_get_vault_account_activity_logs",
                  "beyondtrust_reportings_get_support_session_logs",
                  "varonis_host", "varonis_api_key",
                  "armis_centrix_host", "armis_centrix_secretkey", "armis_centrix_get_activity_logs",
                  "perception_point_x_ray_host", "perception_point_x_ray_token", "perception_point_x_ray_organization_id", "perception_point_x_ray_environment_id", "perception_point_x_ray_case_types",
                  "extrahop_host", "extrahop_id", "extrahop_secret",
                  "hornetsecurity_app_id", "hornetsecurity_token",
                  "ubika_base_refresh_token", "ubika_namespaces",
                  "sentinel_one_graph_token", "sentinel_one_graph_console_url",
                  'messagetrace_o365_tenant_id', 'messagetrace_o365_client_id', 'messagetrace_o365_client_secret',
                  'cnapp_wiz_client_id', 'cnapp_wiz_client_secret', 'cnapp_wiz_api_url',
        ] + RsyslogQueueForm.Meta.fields

        widgets = {
            'enabled': CheckboxInput(attrs={'class': "js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'tags': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'mode': Select(choices=MODE_CHOICES, attrs={'class': 'form-control select2'}),
            'enable_logging': CheckboxInput({'class': 'js-switch'}),  # do not set js-switch
            'tenants_config': Select(choices=Tenants.objects.all(), attrs={'class': "form-control select2"}),
            'enable_logging_reputation': CheckboxInput(attrs={'class': "js-switch"}),
            'log_level': Select(choices=LOG_LEVEL_CHOICES, attrs={'class': 'form-control select2'}),
            'darwin_mode': Select(choices=DARWIN_MODE_CHOICES, attrs={'class': 'form-control select2'}),
            'log_condition': Textarea(attrs={'class': 'form-control'}),
            'ruleset': Select(attrs={'class': 'form-control select2'}),
            'listening_mode': Select(choices=LISTENING_MODE_CHOICES, attrs={'class': 'form-control select2'}),
            'filebeat_listening_mode': Select(choices=FILEBEAT_LISTENING_MODE, attrs={'class': 'form-control select2'}),
            'filebeat_module': Select(choices=FILEBEAT_MODULE_LIST, attrs={'class': 'form-control select2'}),
            'filebeat_config': Textarea(attrs={'class': 'form-control'}),
            'disable_octet_counting_framing': CheckboxInput(attrs={'class': " js-switch"}),
            'custom_tl_frame_delimiter': NumberInput(attrs={'class': 'form-control'}),
            'custom_actions': HiddenInput(),
            'custom_haproxy_conf': Textarea(attrs={'class': 'form-control'}),
            'enable_cache': CheckboxInput(attrs={'class': " js-switch"}),
            'cache_total_max_size': NumberInput(attrs={'class': 'form-control'}),
            'cache_max_age': NumberInput(attrs={'class': 'form-control'}),
            'enable_compression': CheckboxInput(attrs={'class': " js-switch"}),
            'compression_algos': SelectMultiple(choices=COMPRESSION_ALGO_CHOICES,
                                                attrs={'class': "form-control select2"}),
            'compression_mime_types': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'error_template': Select(choices=ErrorTemplate.objects.all(), attrs={'class': 'form-control select2'}),
            'timeout_client': NumberInput(attrs={'class': 'form-control'}),
            'timeout_keep_alive': NumberInput(attrs={'class': 'form-control'}),
            'https_redirect': CheckboxInput(attrs={'class': 'js-switch'}),
            'parser_tag': TextInput(attrs={'class': 'form-control'}),
            'ratelimit_interval': NumberInput(attrs={'class': 'form-control'}),
            'ratelimit_burst': NumberInput(attrs={'class': 'form-control'}),
            'expected_timezone': Select(choices=get_available_timezones(), attrs={'class': 'form-control select2'}),
            'file_path': TextInput(attrs={'class': 'form-control'}),
            'kafka_brokers': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'kafka_topic': TextInput(attrs={'class': 'form-control'}),
            'kafka_consumer_group': TextInput(attrs={'class': 'form-control'}),
            'kafka_options': TextInput(attrs={'class': 'form-control'}),
            'redis_mode': Select(choices=REDIS_MODE_CHOICES, attrs={'class': 'form-control select2'}),
            'redis_use_lpop': CheckboxInput(attrs={'class': 'js-switch'}),
            'redis_server': TextInput(attrs={'class': 'form-control'}),
            'redis_port': TextInput(attrs={'class': 'form-control'}),
            'redis_key': TextInput(attrs={'class': 'form-control'}),
            'redis_password': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'redis_stream_consumerGroup': TextInput(attrs={'class': 'form-control'}),
            'redis_stream_consumerName': TextInput(attrs={'class': 'form-control'}),
            'redis_stream_startID': Select(choices=REDIS_STARTID_CHOICES, attrs={'class': 'form-control select2'}),
            'redis_stream_acknowledge': CheckboxInput(attrs={'class': 'js-switch'}),
            'redis_stream_reclaim_timeout': NumberInput(attrs={'class': 'form-control'}),
            'healthcheck_service': CheckboxInput(attrs={'class': 'js-switch'}),
            'mmdb_cache_size': NumberInput(attrs={'class': 'form-control'}),
            'redis_batch_size': NumberInput(attrs={'class': 'form-control'}),
            'api_parser_use_proxy': CheckboxInput(attrs={'class': 'js-switch'}),
            'api_parser_custom_proxy': TextInput(attrs={'class': 'form-control'}),
            'api_parser_verify_ssl': CheckboxInput(attrs={'class': 'js-switch'}),
            'api_parser_custom_certificate': Select(choices=X509Certificate.objects.all(), attrs={'class': "form-control select2"}),
            'forcepoint_username': TextInput(attrs={'class': 'form-control'}),
            'forcepoint_password': TextInput(attrs={'class': 'form-control'}),
            'symantec_username': TextInput(attrs={'class': 'form-control'}),
            'symantec_password': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'aws_access_key_id': TextInput(attrs={'class': 'form-control'}),
            'aws_secret_access_key': TextInput(attrs={'class': 'form-control'}),
            'aws_bucket_name': Select(attrs={'class': 'form-control select2'}),
            'akamai_host': TextInput(attrs={'class': 'form-control'}),
            'akamai_client_secret': TextInput(attrs={'class': 'form-control'}),
            'akamai_access_token': TextInput(attrs={'class': 'form-control'}),
            'akamai_client_token': TextInput(attrs={'class': 'form-control'}),
            'akamai_config_id': TextInput(attrs={'class': 'form-control'}),
            'office365_tenant_id': TextInput(attrs={'class': 'form-control'}),
            'office365_client_id': TextInput(attrs={'class': 'form-control'}),
            'office365_client_secret': TextInput(attrs={'class': 'form-control'}),
            'imperva_base_url': TextInput(attrs={'class': 'form-control'}),
            'imperva_api_key': TextInput(attrs={'class': 'form-control'}),
            'imperva_api_id': TextInput(attrs={'class': 'form-control'}),
            'imperva_private_key': Textarea(attrs={'class': 'form-control'}),
            'reachfive_host': TextInput(attrs={'class': 'form-control'}),
            'reachfive_client_id': TextInput(attrs={'class': 'form-control'}),
            'reachfive_client_secret': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'mongodb_api_user': TextInput(attrs={'class': 'form-control'}),
            'mongodb_api_password': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'mongodb_api_group_id': TextInput(attrs={'class': 'form-control'}),
            'mdatp_api_tenant': TextInput(attrs={'class': 'form-control'}),
            'mdatp_api_appid': TextInput(attrs={'class': 'form-control'}),
            'mdatp_api_secret': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'cortex_xdr_host': TextInput(attrs={'class': 'form-control'}),
            'cortex_xdr_apikey_id': TextInput(attrs={'class': 'form-control'}),
            'cortex_xdr_apikey': TextInput(attrs={'class': 'form-control'}),
            'cortex_xdr_advanced_token': CheckboxInput(attrs={'class': "js-switch"}),
            'cybereason_host': TextInput(attrs={'class': 'form-control'}),
            'cybereason_username': TextInput(attrs={'class': 'form-control'}),
            'cybereason_password': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'cisco_meraki_apikey': TextInput(attrs={'class': 'form-control'}),
            'cisco_meraki_get_security_logs': CheckboxInput(attrs={'class': 'js-switch'}),
            'cisco_meraki_get_configuration_changes_logs': CheckboxInput(attrs={'class': 'js-switch'}),
            'proofpoint_tap_host': TextInput(attrs={'class': 'form-control'}),
            'proofpoint_tap_endpoint': Select(attrs={'class': 'form-control select2'}),
            'proofpoint_tap_principal': TextInput(attrs={'class': 'form-control'}),
            'proofpoint_tap_secret': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'sentinel_one_host': TextInput(attrs={'class': 'form-control'}),
            'sentinel_one_apikey': TextInput(attrs={'class': 'form-control'}),
            'sentinel_one_account_type': Select(choices=SENTINEL_ONE_ACCOUNT_TYPE_CHOICES, attrs={'class': 'form-control select2'}),
            'netskope_host': TextInput(attrs={'class': 'form-control'}),
            'netskope_apikey': TextInput(attrs={'class': 'form-control'}),
            'netskope_get_page_logs': CheckboxInput(attrs={'class': "js-switch"}),
            'netskope_get_network_logs': CheckboxInput(attrs={'class': "js-switch"}),
            'netskope_get_application_logs': CheckboxInput(attrs={'class': "js-switch"}),
            'carbon_black_host': TextInput(attrs={'class': 'form-control'}),
            'carbon_black_orgkey': TextInput(attrs={'class': 'form-control'}),
            'carbon_black_apikey': TextInput(attrs={'class': 'form-control'}),
            'rapid7_idr_host': TextInput(attrs={'class': 'form-control'}),
            'rapid7_idr_apikey': TextInput(attrs={'class': 'form-control'}),
            'harfanglab_host': TextInput(attrs={'class': 'form-control'}),
            'harfanglab_apikey': TextInput(attrs={'class': 'form-control'}),
            'nozomi_probe_host': TextInput(attrs={'class': 'form-control'}),
            'nozomi_probe_login': TextInput(attrs={'class': 'form-control'}),
            'nozomi_probe_password': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'vadesecure_host': TextInput(attrs={'class': 'form-control'}),
            'vadesecure_login': TextInput(attrs={'class': 'form-control'}),
            'vadesecure_password': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'defender_token_endpoint': TextInput(attrs={'class': 'form-control'}),
            'defender_client_id': TextInput(attrs={'class': 'form-control'}),
            'defender_client_secret': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'crowdstrike_request_incidents': CheckboxInput(attrs={'class': "js-switch"}),
            'crowdstrike_host': TextInput(attrs={'class': 'form-control'}),
            'crowdstrike_client_id': TextInput(attrs={'class': 'form-control'}),
            'crowdstrike_client_secret': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'crowdstrike_client': TextInput(attrs={'class': 'form-control'}),
            'vadesecure_o365_host': TextInput(attrs={'class': 'form-control'}),
            'vadesecure_o365_tenant': TextInput(attrs={'class': 'form-control'}),
            'vadesecure_o365_client_id': TextInput(attrs={'class': 'form-control'}),
            'vadesecure_o365_client_secret': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'blackberry_cylance_host': TextInput(attrs={'class': 'form-control'}),
            'blackberry_cylance_tenant': TextInput(attrs={'class': 'form-control'}),
            'blackberry_cylance_app_id': TextInput(attrs={'class': 'form-control'}),
            'blackberry_cylance_app_secret': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'ms_sentinel_tenant_id': TextInput(attrs={'class': 'form-control'}),
            'ms_sentinel_appid': TextInput(attrs={'class': 'form-control'}),
            'ms_sentinel_appsecret': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'ms_sentinel_subscription_id': TextInput(attrs={'class': 'form-control'}),
            'ms_sentinel_resource_group': TextInput(attrs={'class': 'form-control'}),
            'ms_sentinel_workspace': TextInput(attrs={'class': 'form-control'}),
            'sentinel_one_singularity_mobile_host': TextInput(attrs={'class': 'form-control'}),
            'sentinel_one_singularity_mobile_client_id': TextInput(attrs={'class': 'form-control'}),
            'sentinel_one_singularity_mobile_client_secret': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'proofpoint_pod_uri': TextInput(attrs={'class': 'form-control'}),
            'proofpoint_pod_cluster_id': TextInput(attrs={'class': 'form-control'}),
            'proofpoint_pod_token': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'waf_cloudflare_apikey': TextInput(attrs={'class': 'form-control'}),
            'waf_cloudflare_zoneid': TextInput(attrs={'class': 'form-control'}),
            'gsuite_alertcenter_json_conf': Textarea(attrs={'class': 'form-control'}),
            'gsuite_alertcenter_admin_mail': TextInput(attrs={'class': 'form-control'}),
            'sophos_cloud_client_id': TextInput(attrs={'class': 'form-control'}),
            'sophos_cloud_client_secret': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'sophos_cloud_tenant_id': TextInput(attrs={'class': 'form-control'}),
            'trendmicro_worryfree_access_token': TextInput(attrs={'class': 'form-control'}),
            'trendmicro_worryfree_secret_key': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'trendmicro_worryfree_server_name': TextInput(attrs={'class': 'form-control'}),
            'trendmicro_worryfree_server_port': TextInput(attrs={'class': 'form-control'}),
            'safenet_tenant_code': TextInput(attrs={'class': 'form-control'}),
            'safenet_apikey': TextInput(attrs={'class': 'form-control'}),
            'signalsciences_ngwaf_email': TextInput(attrs={'class': 'form-control'}),
            'signalsciences_ngwaf_token': TextInput(attrs={'type': "password", 'class': 'form-control'}),
            'signalsciences_ngwaf_corp_name': TextInput(attrs={'class': 'form-control'}),
            'signalsciences_ngwaf_site_name': TextInput(attrs={'class': 'form-control'}),
            'proofpoint_casb_api_key': TextInput(attrs={'class': 'form-control'}),
            'proofpoint_casb_client_id': TextInput(attrs={'class': 'form-control'}),
            'proofpoint_casb_client_secret': TextInput(attrs={'type': 'password','class': 'form-control'}),
            'proofpoint_trap_host': TextInput(attrs={'class': 'form-control'}),
            'proofpoint_trap_apikey': TextInput(attrs={'class': 'form-control'}),
            'waf_cloud_protector_host': TextInput(attrs={'class': 'form-control'}),
            'waf_cloud_protector_api_key_pub': Textarea(attrs={'class': 'form-control'}),
            'waf_cloud_protector_api_key_priv': Textarea(attrs={'class': 'form-control'}),
            'waf_cloud_protector_provider': TextInput(attrs={'class': 'form-control'}),
            'waf_cloud_protector_tenant': TextInput(attrs={'class': 'form-control'}),
            'waf_cloud_protector_servers': TextInput(attrs={'class': 'form-control'}),
            'trendmicro_visionone_token': TextInput(attrs={'class': 'form-control'}),
            'cisco_duo_host': TextInput(attrs={'class': 'form-control'}),
            'cisco_duo_ikey': Textarea(attrs={'class': 'form-control'}),
            'cisco_duo_skey': Textarea(attrs={'class': 'form-control'}),
            'sentinel_one_mobile_host': TextInput(attrs={'class': 'form-control'}),
            'sentinel_one_mobile_apikey': TextInput(attrs={'type': 'password','class': 'form-control'}),
            'csc_domainmanager_apikey':TextInput(attrs={'class': 'form-control'}),
            'csc_domainmanager_authorization':TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'retarus_token': TextInput(attrs={'class': 'form-control'}),
            'retarus_channel': TextInput(attrs={'class': 'form-control'}),
            'vectra_host': TextInput(attrs={'class': 'form-control'}),
            'vectra_secret_key': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'vectra_client_id': TextInput(attrs={'class': 'form-control'}),
            'apex_server_host': TextInput(attrs={'class': 'form-control'}),
            'apex_api_key': TextInput(attrs={'class': 'form-control'}),
            'apex_application_id': TextInput(attrs={'class': 'form-control'}),
            'gatewatcher_alerts_host': TextInput(attrs={'class': 'form-control'}),
            'gatewatcher_alerts_api_key': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'cisco_umbrella_client_id': TextInput(attrs={'class': 'form-control'}),
            'cisco_umbrella_secret_key': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'waf_barracuda_token': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'beyondtrust_pra_client_id': TextInput(attrs={'class': 'form-control'}),
            'beyondtrust_pra_secret': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'beyondtrust_pra_host': TextInput(attrs={'class': 'form-control'}),
            'lockself_x_auth_token': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'lockself_x_ls_token': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'lockself_host': TextInput(attrs={'class': 'form-control'}),
            'lockself_organization_id': TextInput(attrs={'class': 'form-control'}),
            'cisco_umbrella_managed_org_api_key': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'cisco_umbrella_managed_org_secret_key': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'cisco_umbrella_managed_org_customers_id': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'cisco_umbrella_managed_org_get_dns': CheckboxInput(attrs={'class': 'js-switch'}),
            'cisco_umbrella_managed_org_get_proxy': CheckboxInput(attrs={'class': 'js-switch'}),
            'catonetworks_api_key': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'catonetworks_account_id': TextInput(attrs={'class': 'form-control'}),
            'infoblox_threat_defense_host': TextInput(attrs={'class': 'form-control'}),
            'infoblox_threat_defense_token': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'beyondtrust_reportings_client_id': TextInput(attrs={'class': 'form-control'}),
            'beyondtrust_reportings_secret': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'beyondtrust_reportings_host': TextInput(attrs={'class': 'form-control'}),
            'beyondtrust_reportings_get_team_logs': CheckboxInput(attrs={'class': 'js-switch'}),
            'beyondtrust_reportings_get_access_session_logs': CheckboxInput(attrs={'class': 'js-switch'}),
            'beyondtrust_reportings_get_vault_account_activity_logs': CheckboxInput(attrs={'class': 'js-switch'}),
            'beyondtrust_reportings_get_support_session_logs': CheckboxInput(attrs={'class': 'js-switch'}),
            'varonis_host': TextInput(attrs={'class': 'form-control'}),
            'varonis_api_key': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'armis_centrix_host': TextInput(attrs={'class': 'form-control'}),
            'armis_centrix_secretkey': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'armis_centrix_get_activity_logs': CheckboxInput(attrs={'class': 'js-switch'}),
            'perception_point_x_ray_host': TextInput(attrs={'class': 'form-control'}),
            'perception_point_x_ray_token': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'perception_point_x_ray_organization_id': TextInput(attrs={'class': 'form-control'}),
            'perception_point_x_ray_environment_id': TextInput(attrs={'class': 'form-control'}),
            'perception_point_x_ray_case_types': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'extrahop_host': TextInput(attrs={'class': 'form-control'}),
            'extrahop_id': TextInput(attrs={'class': 'form-control'}),
            'extrahop_secret': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'hornetsecurity_app_id': TextInput(attrs={'class': 'form-control'}),
            'hornetsecurity_token': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'ubika_base_refresh_token': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'ubika_namespaces': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'sentinel_one_graph_token': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'sentinel_one_graph_console_url': TextInput(attrs={'class': 'form-control'}),
            'messagetrace_o365_tenant_id': TextInput(attrs={'class': 'form-control'}),
            'messagetrace_o365_client_id': TextInput(attrs={'class': 'form-control'}),
            'messagetrace_o365_client_secret': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'cnapp_wiz_client_id': TextInput(attrs={'class': 'form-control'}),
            'cnapp_wiz_client_secret': TextInput(attrs={'type': 'password', 'class': 'form-control'}),
            'cnapp_wiz_api_url': TextInput(attrs={'class': 'form-control'}),
        } | RsyslogQueueForm.Meta.widgets

    def clean_name(self):
        """ HAProxy does not support space in frontend/listen name directive, replace them by _ """
        value = self.cleaned_data['name'].replace(' ', '_')
        try:
            RegexValidator('^[A-Za-z0-9-.:_]+$')(value)
        except Exception:
            raise ValidationError("Only letters, digits, '-' (dash), '_' (underscore) , '.' (dot) and ':' (colon) are allowed.")
        return value

    def clean_tags(self):
        tags = self.cleaned_data.get('tags')
        if tags:
            return [i.replace(" ", "") for i in self.cleaned_data['tags'].split(',')]
        return []

    def clean_log_condition(self):
        """ Verify if log_condition contains valids LogOM name into {{}} """
        regex = "{{([^}]+)}}"
        log_condition = self.cleaned_data.get('log_condition', "").replace("\r\n", "\n")
        for line in log_condition.split('\n'):
            match = re_search(regex, line)
            if match:
                try:
                    LogOM().select_log_om_by_name(match.group(1))
                except ObjectDoesNotExist:
                    raise ValidationError("Log Forwarder named '{}' not found.".format(match.group(1)))
        return log_condition

    def clean_ruleset(self):
        """ Check if the file associate to the ruleset exists """
        ruleset = self.cleaned_data.get('ruleset')
        if not ruleset:
            return ruleset

        ruleset_filename = "{}rsyslog_ruleset_{}".format(JINJA_RSYSLOG_PATH, ruleset)
        if not path_exists(ruleset_filename):
            raise ValidationError("Invalid ruleset chosen, corresponding configuration directory '{}' does not exists."
                                  .format(ruleset_filename))
        return ruleset

    def clean_compression_algos(self):
        """ Convert SelectMultiple selected choices
        into a TextField with space separator """
        compression_algos = self.cleaned_data.get('compression_algos')
        if not compression_algos:
            return ""
        try:
            """ Transform text formatted list into list"""
            algos_list = ast_literal_eval(compression_algos)
        except Exception:
            raise ValidationError("Invalid field.")
        else:
            """ And return select choices with space separator """
            return ' '.join(algos_list)

    def clean_compression_mime_types(self):
        """ Validate chosen MIME types with MIME library """
        mime_types = self.cleaned_data.get('compression_mime_types')
        if not mime_types:
            return mime_types
        for mime_type in mime_types.split(','):
            if not mime_guess_ext(mime_type):
                raise ValidationError("This MIME type is unknown : {}".format(mime_type))
        return mime_types

    def clean_keep_source_fields(self):
        try:
            if self.cleaned_data.get('keep_source_fields'):
                field_val = json_loads(self.cleaned_data.get('keep_source_fields'))
            else:
                return {}
        except Exception:
            raise ValidationError("This field seems to be corrupted")
        else:
            invalid_fields = []
            for key, val in field_val.items():
                if not re_match("^[a-zA-Z0-9\-\._\!]+$", key):
                    invalid_fields.append(key)
                if not re_match("^[a-zA-Z0-9\-\._\!]+$", val.get('field_name')):
                    invalid_fields.append(val.get('field_name'))
            if invalid_fields:
                raise ValidationError("Field '{}' is not valid")
            return field_val

    def clean_kafka_brokers(self):
        data = self.cleaned_data.get('kafka_brokers')
        if not data:
            return []
        if "[" in data and "]" in data:
            return ast.literal_eval(data)
        return data.split(',')

    def clean_kafka_options(self):
        data = self.cleaned_data.get('kafka_options')
        if not data:
            return []
        if "[" in data and "]" in data:
            return ast.literal_eval(data)
        return data.split(',')

    def clean_mmdb_cache_size(self):
        data = self.cleaned_data.get('mmdb_cache_size')
        if data and data !=0 and data % 2 != 0:
            self.add_error('mmdb_cache_size', "MMDB Cache size needs to be zero or a multiple of 2 (recommended value is 10000)")
        return data

    def clean_redis_batch_size(self):
        data = self.cleaned_data.get('redis_batch_size')
        if data and data < 10:
            self.add_error('redis_batch_size', "Redis dequeue size should be greater than 10")
        return data

    def clean_custom_actions(self):
        # Bypass validation and avoid database error
        return list()

    def clean_cisco_umbrella_managed_org_customers_id(self):
        data = self.cleaned_data.get('cisco_umbrella_managed_org_customers_id')
        if not data:
            return []
        if "[" in data and "]" in data:
            return ast.literal_eval(data)
        return data.split(',')

    def clean_ubika_namespaces(self):
        data = self.cleaned_data.get('ubika_namespaces')
        if not data:
            return []
        if "[" in data and "]" in data:
            return ast.literal_eval(data)
        return data.split(',')

    def clean_perception_point_x_ray_case_types(self):
        data = self.cleaned_data.get('perception_point_x_ray_case_types')
        if not data:
            return []
        if "[" in data and "]" in data:
            return ast.literal_eval(data)
        return data.split(',')

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()
        """ If mode != log or enable_logging => log_level required """
        mode = cleaned_data.get('mode')

        if cleaned_data.get('enable_logging'):
            if not cleaned_data.get('tenants_config'):
                raise ValidationError("Tenants config is required if logging is enabled")
            if not cleaned_data.get('log_condition'):
                raise ValidationError(
                    "Logging is enabled. Please check \"Archive logs on system\" or configure a log forwarder.")
            if mode == "http":
                if not cleaned_data.get('log_level'):
                    """ Log_level is required if mode is not log and logging enabled """
                    # If the error is associated with a particular field, use add_error
                    self.add_error('log_level', "This field is required if logging is enabled.")
        if mode == "log":
            # if cleaned_data.get('listening_mode') == "api":
            #     cleaned_data['ruleset'] = "generic_json"
            if not cleaned_data.get('ruleset'):
                self.add_error('ruleset', "This field is required.")
            if not cleaned_data.get('listening_mode'):
                self.add_error('listening_mode', "This field is required.")
        if mode == "filebeat":
            # Filebeat always send JSON logs on internal redis
            #  cleaned_data['ruleset'] = "generic_json"
            cleaned_data['listening_mode'] = "redis"
            if not cleaned_data.get('filebeat_listening_mode'):
                self.add_error('filebeat_listening_mode', "This field is required.")
        if mode == "http":
            if not cleaned_data.get('timeout_keep_alive'):
                self.add_error('timeout_keep_alive', "This field is required.")

        # If HAProxy conf - for TCP Rsyslog
        if (mode == "log" and "tcp" in cleaned_data.get('listening_mode')) or mode in ("tcp", "http"):
            if not cleaned_data.get('timeout_client'):
                self.add_error('timeout_client', "This field is required.")

        # If HAProxy conf - for TCP Filebeat
        if mode == "filebeat":
            if not cleaned_data.get('filebeat_config'):
                self.add_error('filebeat_config', "This field is required.")
            else:
                for line in cleaned_data.get('filebeat_config', '').split('\n'):
                    if re_match(r"^type:", line) or re_match(r"^\s*-\s*type:", line):
                        print("Filebeat config cannot contains 'type', this is managed by Vulture")
                    if re_match(r"^output:", line):
                        print("Filebeat config cannot contains 'output', this is managed by Vulture")

        if mode == "filebeat" and cleaned_data.get('filebeat_listening_mode') == "tcp":
            if not cleaned_data.get('timeout_client'):
                self.add_error('timeout_client', "This field is required.")

        if mode == "log" and cleaned_data.get('listening_mode') == "file":
            if not cleaned_data.get('tags'):
                self.add_error('tags', "This field is required.")

        if mode == "filebeat" and "%ip%" not in cleaned_data.get('filebeat_config'):
            if not cleaned_data.get('node'):
                self.add_error('node', "This field is required.")
            if cleaned_data.get('filebeat_listening_mode') == "file" and not cleaned_data.get('tags'):
                self.add_error('tags', "This field is required.")

        if mode == "log" and cleaned_data.get('listening_mode') == "api":
            if cleaned_data.get('api_parser_use_proxy', True) and cleaned_data.get('api_parser_custom_proxy', None):
                # parse_proxy_url will validate and return a correct url
                custom_proxy = parse_proxy_url(cleaned_data.get('api_parser_custom_proxy', None))
                if not custom_proxy:
                    self.add_error('api_parser_custom_proxy', "Wrong proxy format")
                cleaned_data['api_parser_custom_proxy'] = custom_proxy

            # Cisco Umbrella Managed Org specific validations
            if cleaned_data.get("api_parser_type") == "cisco_umbrella_managed_org":
                logger.warning("hello")
                if not (cleaned_data.get("cisco_umbrella_managed_org_get_dns", False) or cleaned_data.get("cisco_umbrella_managed_org_get_proxy", False)):
                        self.add_error("cisco_umbrella_managed_org_get_dns", "At least one type should be enabled")
                        self.add_error("cisco_umbrella_managed_org_get_proxy", "At least one type should be enabled")

            # Beyondtrust Reportings specific validations
            if cleaned_data.get("api_parser_type") == "beyondtrust_reportings":
                options = list()
                options.append(cleaned_data.get("beyondtrust_reportings_get_team_logs", False))
                options.append(cleaned_data.get("beyondtrust_reportings_get_access_session_logs", False))
                options.append(cleaned_data.get("beyondtrust_reportings_get_vault_account_activity_logs", False))
                options.append(cleaned_data.get("beyondtrust_reportings_get_support_session_logs", False))
                if not any(options):
                    self.add_error("beyondtrust_reportings_get_team_logs", "At least one of these fields is required.")
                    self.add_error("beyondtrust_reportings_get_access_session_logs", "At least one of these fields is required.")
                    self.add_error("beyondtrust_reportings_get_vault_account_activity_logs", "At least one of these fields is required.")
                    self.add_error("beyondtrust_reportings_get_support_session_logs", "At least one of these fields is required.")

        if mode == "log" and cleaned_data.get('listening_mode') == "kafka":
            if not cleaned_data.get('kafka_brokers'):
                self.add_error('kafka_brokers', "This field is required.")
            if not cleaned_data.get('kafka_topic'):
                self.add_error('kafka_topic', "This field is required.")
            if not cleaned_data.get('kafka_consumer_group'):
                self.add_error('kafka_consumer_group', "This field is required.")

        if mode == "log" and cleaned_data.get('listening_mode') == "redis":
            if not cleaned_data.get('redis_server'):
                self.add_error('redis_server', "This field is required.")
            if not cleaned_data.get('redis_port'):
                self.add_error('redis_port', "This field is required.")
            if not cleaned_data.get('redis_key'):
                self.add_error('redis_key', "This field is required.")
            if not cleaned_data.get('redis_mode'):
                self.add_error('redis_mode', "This field is required.")
            elif cleaned_data.get('redis_mode') == "stream":
                if cleaned_data.get('redis_stream_consumerGroup'):
                    if not cleaned_data.get('redis_stream_consumerName'):
                        self.add_error('redis_stream_consumerName', "This field is required if Consumer Group is set.")
                elif cleaned_data.get('redis_stream_startID') == ">":
                    self.add_error('redis_stream_startID', "Undelivered entries can only be set when a consumer group is declared.")

        """ If cache is enabled, cache_total_max_size and cache_max_age required """
        if cleaned_data.get('enable_cache'):
            if not cleaned_data.get('cache_total_max_size'):
                self.add_error('cache_total_max_size', "This field is required.")
            if not cleaned_data.get('cache_max_age'):
                self.add_error('cache_max_age', "This field is required.")

        """ If cache is enabled, cache_total_max_size and cache_max_age required """
        if cleaned_data.get('enable_compression'):
            if not cleaned_data.get('compression_algos'):
                self.add_error('compression_algos', "This field is required.")
            if not cleaned_data.get('compression_mime_types'):
                self.add_error('compression_mime_types', "This field is required.")

        """ If enable_logging_reputation is enabled, logging_reputation_database v4 or v6 or both required """
        if cleaned_data.get('enable_logging_reputation'):
            if not cleaned_data.get('logging_reputation_database_v4') and \
                    not cleaned_data.get('logging_reputation_database_v6'):
                self.add_error('logging_reputation_database_v4', "One of those fields is required.")
                self.add_error('logging_reputation_database_v6', "One of those fields is required.")

        """ If Darwin policy is enabled, darwin_mode is required """
        if cleaned_data.get('darwin_policies'):
            if not cleaned_data.get("darwin_mode"):
                self.add_error("darwin_mode", "This field is required when a darwin policy is set")

        """ if ratelimit_interval or ratelimit_burst is specified, the other cannot be left blank """
        if cleaned_data.get('ratelimit_interval') and not cleaned_data.get('ratelimit_burst'):
            self.add_error("ratelimit_burst", "This field cannot be left blank if rate-limiting interval is set")
        if cleaned_data.get('ratelimit_burst') and not cleaned_data.get('ratelimit_interval'):
            self.add_error("ratelimit_interval", "This field cannot be left blank if rate-limiting burst is set")

        return cleaned_data


class ListenerForm(ModelForm):

    tls_profiles = ModelMultipleChoiceField(
        queryset=TLSProfile.objects.filter(x509_certificate__isnull=False),
        widget=SelectMultiple(attrs={'class': 'form-control select2'}),
    )

    class Meta:
        model = Listener
        fields = ('network_address', 'port', 'tls_profiles', 'whitelist_ips', 'max_src', 'max_rate',)

        widgets = {
            'port': NumberInput(attrs={'class': 'form-control'}),
            'whitelist_ips': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'max_src': NumberInput(attrs={'class': 'form-control'}),
            'max_rate': NumberInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        """ Initialisation of fields method """
        # Do not set id of html fields, that causes issues in JS/JQuery
        kwargs['auto_id'] = False
        super().__init__(*args, **kwargs)
        self.fields['network_address'] = ModelChoiceField(
            label=_("Network address"),
            queryset=NetworkAddress.objects.all(),
            widget=Select(attrs={'class': 'form-control select2'}),
            required=True
        )
        # Remove the blank input generated by django
        self.fields['network_address'].empty_label = None
        self.fields['tls_profiles'].empty_label = "Plain text"
        self.fields['tls_profiles'].required = False

    def clean_whitelist_ips(self):
        """ Verify 'whitelist_ips' field """
        value = self.cleaned_data.get('whitelist_ips')
        any_field = False
        for v in value.split(','):
            if v == 'any':
                any_field = True
            elif any_field:
                raise ValidationError("Can't set field to 'any' if ip addresses are provided.")
            else:
                try:
                    v_splitted = v.split('/')
                    if len(v_splitted) > 2:
                        raise ValidationError("'{}' is not a valid ip address or cidr.".format(v))
                    elif len(v_splitted) == 2:
                        netmask = int(v_splitted[1])  # raise ValueError if failure
                        if netmask > 32 or netmask < 1:
                            raise ValidationError("'{}' is not a valid ip address or cidr.".format(v))
                    assert ip_address(v_splitted[0])
                except (ValueError, AssertionError) as e:
                    logger.exception(e)
                    raise ValidationError("'{}' is not a valid ip address or cidr.".format(v))
        return value

    def clean_tls_profiles(self):
        """ Verify that profile has a x509_certificate selected """
        tls_profiles = self.cleaned_data.get('tls_profiles')
        for tls_profile in tls_profiles:
            if tls_profile.x509_certificate is None:
                raise ValidationError("This TLS Profile does not have any certificate.")
        return tls_profiles

    def as_table_headers(self):
        """ Format field names as table head """
        result = "<tr><th style=\"visibility:hidden;\">{}</th>\n"
        for field in self:
            result += "<th>{}</th>\n".format(field.label)
        result += "<th>Delete</th></tr>\n"
        return result

    def as_table_td(self):
        """ Format fields as a table with <td></td> """
        result = "<tr><td style=\"visibility:hidden;\">{}</td>".format(self.instance.id or "")
        for field in self:
            result += "<td>{}</td>".format(field)
        result += "<td style='text-align:center'><a class='btnDelete'><i style='color:grey' " \
                  "class='fas fa-trash-alt'></i></a></td></tr>\n"
        return result


CONDITION_CHOICES = (
    ('if', 'If'),
    ('if not', 'If not')
)

FIELD_CHOICES = (
    ('$msg', 'Message'),
    ('$rawmsg', 'Raw message'),
    ('$hostname', 'Hostname'),
    ('$fromhost', 'Hostname msg from'),
    ('$fromhost-ip', 'IP msg from'),
    ('$syslogtag', 'Tag'),
    ('$programname', 'Program name'),
    ('$pri', 'PRI msg part'),
    ('$pri-text', 'PRI as text'),
    ('$iut', 'InfoUnitType'),
    ('$syslogfacility', 'Facility - as num'),
    ('$syslogfacility-text', 'Facility - as text'),
    ('$syslogseverity', 'Severity - as num'),
    ('$syslogseverity-text', 'Severity - as text'),
    ('$timegenerated', 'Received time'),
    ('$timestamp', 'Msg timestamp'),
    ('$inputname', 'Input module name')
)

OPERATOR_CHOICES = (
    ('contains', 'Contains'),
    ('startswith', 'Starts with'),
    ('regex', 'Matches regex'),
    ('==', 'Is equal to'),
    ('!=', 'Is different than'),
    ('<', 'Is less than'),
    ('>', 'Is upper than'),
    ('<=', 'Is less or equal to'),
    ('>=', 'Is upper or equal to'),
)


class LogOMTableForm(Form):
    """ Form used to generate table for log_forwarders """
    """ First condition word """
    condition = ChoiceField(
        label=_("Condition"),
        choices=CONDITION_CHOICES,
        widget=Select(attrs={'class': 'form-control select2'})
    )
    """ Comparison field name """
    field_name = ChoiceField(
        label=_("Field"),
        choices=FIELD_CHOICES,
        widget=Select(attrs={'class': 'form-control select2'})
    )
    """ Comparison operator """
    operator = ChoiceField(
        label=_("Operator"),
        choices=OPERATOR_CHOICES,
        widget=Select(attrs={'class': 'form-control select2'})
    )
    """ Comparison value """
    value = CharField(
        label=_("Value"),
        initial='"plop"',
        widget=TextInput(attrs={'class': 'form-control'})
    )
    """ Action - log forwarder """
    action = ModelMultipleChoiceField(
        label=_("Action"),
        queryset=LogOM.objects.all().only(*LogOM.str_attrs()),
        widget=SelectMultiple(attrs={'class': 'form-control select2'})
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['action'].empty_label = None

    def as_table_headers(self):
        """ Format field names as table head """
        result = "<tr>\n"
        for field in self:
            result += "<th>{}</th>\n".format(field.label)
        result += "<th>Delete</th></tr>\n"
        return result

    def as_table_td(self):
        """ Format fields as a table with <td></td> """
        result = "<tr>"
        for field in self:
            result += "<td>{}</td>".format(field)
        result += "<td style='text-align:center'><a class='btnDelete'><i style='color:grey' " \
                  "class='fas fa-trash-alt'></i></a></td></tr>\n"
        return result
