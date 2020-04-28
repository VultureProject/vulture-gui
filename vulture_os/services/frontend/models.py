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
__doc__ = 'Frontends & Listeners model classes'

# Django system imports
import uuid
import datetime
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.template import Context, Template as JinjaTemplate
from django.utils.translation import ugettext_lazy as _
from djongo import models

# Django project imports
from applications.logfwd.models import LogOM, LogOMMongoDB
from applications.reputation_ctx.models import ReputationContext, DATABASES_PATH
from darwin.policy.models import DarwinPolicy, FilterPolicy
from services.haproxy.haproxy import test_haproxy_conf, HAPROXY_OWNER, HAPROXY_PATH, HAPROXY_PERMS
from system.error_templates.models import ErrorTemplate
from system.cluster.models import Cluster, NetworkAddress, NetworkInterfaceCard, Node
from applications.backend.models import Backend
from system.pki.models import TLSProfile
from toolkit.network.network import JAIL_ADDRESSES
from toolkit.http.headers import Header

# Extern modules imports
from jinja2 import Environment, FileSystemLoader
from re import search as re_search
from requests import post

# Required exceptions imports
from jinja2.exceptions import (TemplateAssertionError, TemplateNotFound, TemplatesNotFound, TemplateRuntimeError,
                               TemplateSyntaxError, UndefinedError)
from services.exceptions import (ServiceJinjaError, ServiceStartError, ServiceTestConfigError, ServiceError)
from system.exceptions import VultureSystemConfigError

# Logger configuration imports
import logging
import json

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

# Modes choices of HAProxy Frontends
MODE_CHOICES = (
    ('tcp', 'TCP'),
    ('http', 'HTTP'),
    ('log', 'LOG'),
    ('impcap', 'IMPCAP')
)

LOG_LEVEL_CHOICES = (
    ('info', "Info"),
    ('debug', "Debug")
)

COMPRESSION_ALGO_CHOICES = (
    ('identity', "Identity"),
    ('gzip', "GZIP"),
    ('deflate', "Deflate"),
    ('raw-deflate', "Raw deflate"),
)

LISTENING_MODE_CHOICES = (
    ('udp', "UDP"),
    ('tcp', "TCP"),
    ('tcp,udp', "TCP & UDP"),
    ('relp', "RELP (TCP)"),
    ('file', "FILE"),
    ('api', 'API CLIENT')
)

IMPCAP_FILTER_CHOICES = (
    ('udp and port 53', "DNS"),
    ('tcp[13] & 2 != 0', "SYN FLAGS"),
    ('tcp and (port 80 or port 443)', "WEB"),
    ('custom', "Custom"),
)

DARWIN_MODE_CHOICES = (
    ('darwin', "generate alerts"),
    ('both', "enrich logs and generate alerts")
)

# Jinja template for frontends rendering
JINJA_PATH = "/home/vlt-os/vulture_os/services/frontend/config/"
JINJA_TEMPLATE = "haproxy_frontend.conf"

FRONTEND_OWNER = HAPROXY_OWNER
FRONTEND_PERMS = HAPROXY_PERMS

UNIX_SOCKET_PATH = "/var/sockets/rsyslog"
LOG_API_PATH = "/var/log/api_parser"


class Frontend(models.Model):
    """ Model used to generate fontends configuration of HAProxy """
    """ Is that section enabled or disabled """
    enabled = models.BooleanField(
        default=True,
        help_text=_("Enable the frontend"),
    )
    """ Name of the frontend, unique constraint """
    name = models.TextField(
        unique=True,
        default="Listener",
        help_text=_("Name of HAProxy frontend"),
    )
    """ Tags """
    tags = models.ListField(
        models.SlugField(default=""),
        default=[],
        help_text=_("Tags to set on this object for search")
    )
    """ Listening mode of Frontend : tcp or http """
    mode = models.TextField(
        default="tcp",
        choices=MODE_CHOICES,
        help_text=_("Listening mode"),
    )
    timeout_connect = models.PositiveIntegerField(
        default=5000,
        validators=[MaxValueValidator(20000)],
        help_text=_("HTTP request Timeout"),
        verbose_name=_("Timeout")
    )
    timeout_client = models.PositiveIntegerField(
        default=60,
        validators=[MaxValueValidator(3600)],
        help_text=_("HTTP request Timeout"),
        verbose_name=_("Timeout")
    )
    timeout_keep_alive = models.PositiveIntegerField(
        default=500,
        help_text=_("HTTP Keep-Alive timeout"),
        verbose_name=_("HTTP Keep-Alive timeout")
    )
    https_redirect = models.BooleanField(
        default=False,
        help_text=_("Redirect http requests to https, if available"),
        verbose_name=_("Redirect HTTP to HTTPS")
    )

    """ *** IMPCAP OPTIONS *** """
    """ Impcap interface """
    impcap_intf = models.ForeignKey(
        NetworkInterfaceCard,
        verbose_name=_("Listening interface"),
        help_text=_("Interface used by impcap for trafic listening"),
        null=True,
        on_delete=models.PROTECT
    )
    impcap_filter_type = models.TextField(
        default=IMPCAP_FILTER_CHOICES[0][0],
        choices=IMPCAP_FILTER_CHOICES,
        verbose_name=_("Impcap filter type"),
        help_text=_("Simple filters used by impcap")
    )
    """ Impcap filter """
    impcap_filter = models.TextField(
        default="",
        verbose_name=_("Impcap filter"),
        help_text=_("Filter used by impcap for trafic listening (tcpdump format)")
    )
    """ *** DARWIN OPTIONS *** """
    """ Darwin policy """
    darwin_policy = models.ForeignKey(
        to=DarwinPolicy,
        on_delete=models.PROTECT,
        null=True,
        blank=False,
        related_name="frontend_set",
        help_text=_("Darwin policy to use")
    )
    """ Darwin mode """
    darwin_mode = models.TextField(
        default=DARWIN_MODE_CHOICES[0][0],
        choices=DARWIN_MODE_CHOICES,
        help_text=_("Ways to call Darwin: 'enrich' will wait for a score and add it to the data, 'alert' will simply pass the data for Darwin to process and will rely on its configured alerting methods")
    )
    """ *** LOGGING OPTIONS *** """
    """ Enable logging to Rsyslog """
    enable_logging = models.BooleanField(
        default=False,
        help_text=_("Enable requests logging"),
    )
    """ Enable reputation in Rsyslog """
    enable_logging_reputation = models.BooleanField(
        default=False,
        help_text=_("Add reputation tags in rsyslog message")
    )
    """ Reputation database to use in Rsyslog """
    logging_reputation_database_v4 = models.ForeignKey(
        ReputationContext,
        default=None,
        null=True,
        on_delete=models.SET_NULL,
        related_name="frontend_reputation_v4",
        help_text=_("MMDB database used by rsyslog to get reputation tags for IPv4")
    )
    logging_reputation_database_v6 = models.ForeignKey(
        ReputationContext,
        default=None,
        null=True,
        on_delete=models.SET_NULL,
        related_name="frontend_reputation_v6",
        help_text=_("MMDB database used by rsyslog to get reputation tags for IPv6")
    )
    """ Enable reputation in Rsyslog """
    enable_logging_geoip = models.BooleanField(
        default=False,
        help_text=_("Add Geoip location in rsyslog message")
    )
    """ Geoip database to use in Rsyslog """
    logging_geoip_database = models.ForeignKey(
        ReputationContext,
        default=None,
        null=True,
        on_delete=models.SET_NULL,
        related_name="frontend_geoip",
        help_text=_("MMDB database used by rsyslog to get Geoip location of an IPv4")
    )
    """ Log level of HAProxy """
    log_level = models.TextField(
        default="warning",
        choices=LOG_LEVEL_CHOICES,
        help_text=_("Log level"),
    )
    """ Log forwarders used by this Frontend """
    log_forwarders = models.ArrayReferenceField(
        to=LogOM,
        null=True,
        blank=False,
        related_name="frontend_set",
        help_text=_("Log forwarders used in log_condition")
    )
    """ Log forwarders used by this Frontend """
    log_forwarders_parse_failure = models.ArrayReferenceField(
        to=LogOM,
        null=True,
        blank=False,
        related_name="frontend_failure_set",
        help_text=_("Log forwarders used in log_condition")
    )
    """ Condition area of log forwarders conf """
    log_condition = models.TextField(
        default="",
        help_text=_("Conditional configuration of log forwarders")
    )

    """ Generated configuration depending on Node listening on """
    configuration = models.DictField(
        default={}
    )
    """ Type of template used by rsyslog to parse/forward logs """
    ruleset = models.TextField(
        default="haproxy",
        help_text=_("RuleSet type to use by rsyslog to send output stream")
    )
    parser_tag = models.TextField(
        null=True,
        help_text=_("Tag used in rsyslog template")
    )
    """ Status of frontend for each nodes """
    status = models.DictField(
        default={}
    )
    """ Mode of listening - tcp is handled by HAProxy, udp by Rsyslog """
    listening_mode = models.TextField(
        default="tcp",
        choices=LISTENING_MODE_CHOICES,
        help_text=_("TCP mode = HAProxy, UDP mode = Rsyslog")
    )
    disable_octet_counting_framing = models.BooleanField(
        default=False,
        help_text=_("Enable option 'SupportOctetCountedFraming' in rsyslog (advanced).")
    )
    """ *** HTTP OPTIONS *** """
    """ Log forwarder - File """
    headers = models.ArrayReferenceField(
        Header,
        null=True,
        blank=False,
        on_delete=models.CASCADE,
        help_text=_("Header rules")
    )
    """ Custom HAProxy Frontend directives """
    custom_haproxy_conf = models.TextField(
        default="",
        help_text=_("Custom HAProxy configuration directives.")
    )
    """ HTTP CACHE OPTIONS """
    """ Enable HAProxy cache """
    enable_cache = models.BooleanField(
        default=False,
        help_text=_("Enable cache"),
    )
    """ total-max-size Cache section attribute """
    cache_total_max_size = models.PositiveIntegerField(
        default=4,
        help_text=_("Size of the cache in RAM, in Mb.")
    )
    """ max-age Cache section attribute """
    cache_max_age = models.PositiveIntegerField(
        default=60,
        help_text=_("Size of the cache in RAM, in Mb.")
    )
    """ HTTP COMPRESSION OPTION """
    """ Enable compression """
    enable_compression = models.BooleanField(
        default=False,
        help_text=_("Enable compression"),
    )
    """ Compression algorithms """
    compression_algos = models.TextField(
        default="gzip",
        help_text=_("List of supported compression algorithms.")
    )
    """ Mime types the compression is applied on """
    compression_mime_types = models.TextField(
        default="text/html,text/plain",
        help_text=_("List of MIME types that will be compressed.")
    )
    """ HTTP Error-File options """
    error_template = models.ForeignKey(
        to=ErrorTemplate,
        null=True,
        on_delete=models.SET_NULL
    )
    backend = models.ManyToManyField(
        Backend,
        through='workflow.Workflow'
    )
    reputation_ctxs = models.ManyToManyField(
        ReputationContext,
        through="FrontendReputationContext"
    )
    """ file_path for file listeners """
    file_path = models.TextField(
        default="/var/log/darwin/alerts.log",
        help_text=_("Local file path to listen on")
    )

    node = models.ForeignKey(
        to=Node,
        null=True,
        default=None,
        on_delete=models.SET_NULL,
        help_text=_("Vulture node")
    )

    api_parser_type = models.TextField(
        help_text=_("API Parser Type"),
        default=""
    )

    api_parser_use_proxy = models.BooleanField(
        help_text=_("Use Proxy"),
        default=False
    )

    elasticsearch_host = models.TextField(
        help_text=_('Elasticsearch URL'),
        default=""
    )

    elasticsearch_verify_ssl = models.BooleanField(
        help_text=_("Verify SSL"),
        default=True
    )

    elasticsearch_auth = models.BooleanField(
        help_text=_('Authentication Elasticsearch'),
        default=False
    )

    elasticsearch_username = models.TextField(
        help_text=_('Elasticsearch username'),
        default=""
    )

    elasticsearch_password = models.TextField(
        help_text=_('Elasticsearch password'),
        default=""
    )

    elasticsearch_index = models.TextField(
        help_text=_('Index to poll'),
        default=""
    )

    forcepoint_host = models.TextField(
        help_text=_('Forcepoint URL'),
        default=""
    )

    forcepoint_username = models.TextField(
        help_text=_('Forcepoint Username'),
        default=""
    )

    forcepoint_password = models.TextField(
        help_text=_('Forcepoint Password'),
        default=""
    )

    symantec_username = models.TextField(
        help_text=_('Symantec Username'),
        default=""
    )

    symantec_password = models.TextField(
        help_text=_('Symantec Password'),
        default=""
    )

    aws_access_key_id = models.TextField(
        help_text=_('AWS Access Key ID'),
        default=""
    )

    aws_secret_access_key = models.TextField(
        help_text=_("AWS Secret Access Key"),
        default=""
    )

    aws_bucket_name = models.TextField(
        help_text=_("AWS Bucket Name"),
        default=""
    )

    akamai_host = models.TextField(
        help_text=_('Akamai Host'),
        default=""
    )

    akamai_client_secret = models.TextField(
        help_text=_('Akamai Client Secret'),
        default=""
    )

    akamai_access_token = models.TextField(
        help_text=_('Akamai Access Token'),
        default=""
    )

    akamai_client_token = models.TextField(
        help_text=_('Akamai Client Token'),
        default=""
    )

    akamai_config_id = models.TextField(
        help_text=_('Akamai Config Id'),
        default=""
    )

    office365_tenant_id = models.TextField(
        help_text=_('Office 365 Tenant ID'),
        default=""
    )

    office365_client_id = models.TextField(
        help_text=_('Office 365 Client ID'),
        default=""
    )

    office365_client_secret = models.TextField(
        help_text=_('Office 365 Client Secret'),
        default=""
    )

    imperva_base_url = models.TextField(
        help_text=_("Imperva Base URL"),
        default=""
    )

    imperva_api_id = models.TextField(
        help_text=_("Imperva API ID"),
        default=""
    )

    imperva_api_key = models.TextField(
        help_text=_("Imperva API KEY"),
        default=""
    )

    imperva_private_key = models.TextField(
        help_text=_("Imperva Private KEY"),
        default=""
    )

    imperva_last_log_file = models.TextField(
        help_text=_("Imperva Last Log File"),
        default=""
    )

    last_api_call = models.DateTimeField(
        default=datetime.datetime.utcnow
    )

    keep_source_fields = models.DictField(
        default={}
    )

    def reload_haproxy_conf(self):
        for node in self.get_nodes():
            api_res = node.api_request("services.haproxy.haproxy.build_conf", self.id)
            if not api_res.get('status'):
                logger.error("Access_Control::edit: API error while trying to "
                             "restart HAProxy service : {}".format(api_res.get('message')))

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def __str__(self):
        return "{} Listener '{}'".format(self.mode.upper(), self.name)

    def clean_fields(self, exclude=None):
        """ Remove validation of field 'log_forwarders',
              it will be handled by the view
        """
        if not exclude:
            exclude = ['log_forwarders']
        else:
            exclude.append('log_forwarders')
        return super().clean_fields(exclude=exclude)

    def to_dict(self):
        """ This method MUST be used in API instead of to_template() method
                to prevent no-serialization of sub-models like Listeners
        :return     A JSON object
        """
        result = {
            'id': self.id,
            'enable': self.enabled,
            'name': self.name,
            'tags': self.tags,
            'mode': self.mode,
            'enable_logging': self.enable_logging,
            'status': dict(self.status),  # It is an OrderedDict
            'https_redirect': self.https_redirect,
            'listeners': []
        }

        """ Add listeners, except if listening_mode is file """
        for listener in self.listener_set.all():
            l = listener.to_template()
            # Remove frontend to prevent infinite loop
            del l['frontend']
            result['listeners'].append(l)

        """ Other attributes """
        if self.mode == "http":
            result['log_level'] = self.log_level
            result['headers'] = []

            for header in self.headers.all():
                result['headers'].append(header.to_template())

            result['enable_cache'] = self.enable_cache

            if self.enable_cache:
                result['cache_total_max_size'] = self.cache_total_max_size
                result['cache_max_age'] = self.cache_max_age

            result['enable_compression'] = self.enable_compression

            if self.enable_compression:
                result['compression_algos'] = self.compression_algos
                result['compression_mime_types'] = self.compression_mime_types
            result['error_template'] = self.error_template

        if self.mode == "log":
            result['listening_mode'] = self.listening_mode
            result['enable_logging_reputation'] = self.enable_logging_reputation
            result['enable_logging_geoip'] = self.enable_logging_geoip

            if self.listening_mode == "api":
                result['api_parser_type'] = self.api_parser_type
                result['api_parser_use_proxy'] = self.api_parser_use_proxy
                result['last_api_call'] = self.last_api_call

                if self.api_parser_type == "forcepoint":
                    result['forcepoint_host'] = self.forcepoint_host
                    result['forcepoint_username'] = self.forcepoint_username
                    result['forcepoint_password'] = self.forcepoint_password

                elif self.api_parser_type == "elasticsearch":
                    result['elasticsearch_host'] = self.elasticsearch_host
                    result['elasticsearch_verify_ssl'] = self.elasticsearch_verify_ssl
                    result['elasticsearch_auth'] = self.elasticsearch_auth
                    result['elasticsearch_username'] = self.elasticsearch_username
                    result['elasticsearch_password'] = self.elasticsearch_password
                    result['elasticsearch_index'] = self.elasticsearch_index

                elif self.api_parser_type == "symantec":
                    result['symantec_username'] = self.symantec_username
                    result['symantec_password'] = self.symantec_password

                elif self.api_parser_type == "aws_bucket":
                    result['aws_access_key_id'] = self.aws_access_key_id
                    result['aws_secret_access_key'] = self.aws_secret_access_key
                    result['aws_bucket_name'] = self.aws_bucket_name

                elif self.api_parser_type == "akamai":
                    result['akamai_host'] = self.akamai_host
                    result['akamai_client_secret'] = self.akamai_client_secret
                    result['akamai_access_token'] = self.akamai_access_token
                    result['akamai_client_token'] = self.akamai_client_token
                    result['akamai_config_id'] = self.akamai_config_id

                elif self.api_parser_type == "office_365":
                    result['office365_tenant_id'] = self.office365_tenant_id
                    result['office365_client_id'] = self.office365_client_id
                    result['office365_client_secret'] = self.office365_client_secret

                elif self.api_parser_type == "imperva":
                    result['imperva_base_url'] = self.imperva_base_url
                    result['imperva_api_id'] = self.imperva_api_id
                    result['imperva_api_key'] = self.imperva_api_key
                    result['imperva_private_key'] = self.imperva_private_key
                    result['imperva_last_log_file'] = self.imperva_last_log_file

            if self.enable_logging_reputation:
                result['logging_reputation_database_v4'] = self.logging_reputation_database_v4.to_template()
                result['logging_reputation_database_v6'] = self.logging_reputation_database_v6.to_template()

            if self.enable_logging_geoip:
                result['logging_geoip_database'] = self.logging_geoip_database.to_template()

            result['log_forwarders_parse_failure'] = [LogOM().select_log_om(log_fwd.id).to_template()
                                                      for log_fwd in self.log_forwarders_parse_failure.all().only('id')]

        if self.mode in ("http", "log", 'tcp'):
            result['log_forwarders'] = [LogOM().select_log_om(log_fwd.id).to_template()
                                        for log_fwd in self.log_forwarders.all().only('id')]

            result['log_condition'] = self.log_condition

        if not self.rsyslog_only_conf:
            result['custom_haproxy_conf'] = self.custom_haproxy_conf

        return result

    def to_html_template(self):
        """ Dictionary used to render object as html
        :return     Dictionnary of configuration parameters
        """
        """ Retrieve list/custom objects """
        if self.mode == "impcap":
            listeners_list = [str(self.impcap_intf), str(self.impcap_filter)]
        elif self.listening_mode == "file":
            listeners_list = [self.file_path]
        elif self.listening_mode == "api":
            listeners_list = [self.api_parser_type]
        else:
            listeners_list = [str(l) for l in self.listener_set.all().only(*Listener.str_attrs())]

        log_forwarders = [str(l) for l in self.log_forwarders.all()]

        mode = "UNKNOWN"
        for m in MODE_CHOICES:
            if self.mode == m[0]:
                mode = m[1]

        additional_infos = []
        if mode == "LOG":
            listening_mode = "UNKNOWN"
            for m in LISTENING_MODE_CHOICES:
                if self.listening_mode == m[0]:
                    listening_mode = m[1]
            additional_infos.append("Listening mode : {}".format(listening_mode))
            additional_infos.append("Data type : {}".format(self.ruleset))
        elif mode == "IMPCAP":
            additional_infos.append("Data type : Impcap")
        elif mode == "HTTP":
            if self.enable_cache:
                additional_infos.append("Option cache")
            if self.enable_compression:
                additional_infos.append("Option compression")

        if self.enable_logging:
            additional_infos.append("Logs => [{}]".format(",".join(log_forwarders)))

        """ And returns the attributes of the class """
        return {
            'id': str(self.id),
            'enabled': self.enabled,
            'name': self.name,
            'tags': self.tags,
            'https_redirect': self.https_redirect,
            'listeners': listeners_list,
            'mode': mode,
            'status': self.status,
            'additional_infos': additional_infos
        }

    def to_template(self, listener_list=None, header_list=None):
        """ Dictionary used to create configuration file

        :return     Dictionnary of configuration parameters
        """
        """ Retrieve list/custom objects """
        # If facultative arg listener_list is not given
        if not listener_list:
            # Retrieve all the objects used by the current frontend
            # No .only ! Used to generated conf, neither str cause we need the object
            listener_list = self.listener_set.all()  # No .only() ! Used to generated conf
        # Same for headers
        if not header_list:
            header_list = self.headers.all()

        serialized_blwl_list = []

        if self.mode == "http":
            blwl_list = self.blacklistwhitelist_set.all()

            for blwl_obj in blwl_list:
                serialized_blwl_list.append(blwl_obj.generate_conf())

        reputation_database_v4 = None
        reputation_database_v6 = None
        geoip_database = None

        if self.enable_logging_reputation:
            if self.logging_reputation_database_v4:
                reputation_database_v4 = DATABASES_PATH + '/' + self.logging_reputation_database_v4.filename

            if self.logging_reputation_database_v6:
                reputation_database_v6 = DATABASES_PATH + '/' + self.logging_reputation_database_v6.filename

        if self.logging_geoip_database:
            geoip_database = DATABASES_PATH + '/' + self.logging_geoip_database.filename

        reputation_ctxs = []
        if self.enable_logging:
            for reputation_ctx in self.frontendreputationcontext_set.all():
                reputation_ctxs.append(reputation_ctx)

        workflow_list = []
        access_controls_list = []
        if self.id:
            for workflow in self.workflow_set.filter(enabled=True):
                tmp = {
                    'id': str(workflow.pk),
                    'fqdn': workflow.fqdn,
                    'public_dir': workflow.public_dir,
                    'backend': workflow.backend,
                    'defender_policy': workflow.defender_policy
                }

                access_controls_deny = []
                access_controls_301 = []
                access_controls_302 = []
                for acl in workflow.workflowacl_set.filter(before_policy=True):
                    rules, acls_name = acl.access_control.generate_rules()
                    access_controls_list.append(rules)

                    conditions = acl.generate_condition(acls_name)

                    redirect_url = None
                    deny = False
                    for type_acl in ('action_satisfy', 'action_not_satisfy'):
                        action = getattr(acl, type_acl)
                        if action != "200":
                            if action in ("301", "302"):
                                redirect_url = getattr(acl, type_acl.replace('action', 'redirect_url'))
                            elif action == "403":
                                deny = True

                            break

                    tmp_acl = {
                        'before_policy': acl.before_policy,
                        'redirect_url': redirect_url,
                        'conditions': conditions,
                        'action': action,
                        'deny': deny
                    }

                    if action == "403":
                        access_controls_deny.append(tmp_acl)
                    elif action == "301":
                        access_controls_301.append(tmp_acl)
                    elif action == "302":
                        access_controls_302.append(tmp_acl)

                tmp['access_controls_deny'] = access_controls_deny
                tmp['access_controls_302'] = access_controls_302
                tmp['access_controls_301'] = access_controls_301
                workflow_list.append(tmp)

        result = {
            'id': str(self.id),
            'enabled': self.enabled,
            'name': self.name,
            'listeners': listener_list,
            'https_redirect': self.https_redirect,
            'mode': self.mode,
            'timeout_connect': self.timeout_connect,
            'timeout_client': self.timeout_client,
            'timeout_keep_alive': self.timeout_keep_alive,
            'enable_logging': self.enable_logging,
            'log_format': self.get_log_format(),
            'log_level': self.log_level,
            'log_condition': self.log_condition,
            'ruleset_name': self.get_ruleset(),
            'parser_tag': self.parser_tag,
            'unix_socket': self.get_unix_socket(),
            'headers': header_list,
            'custom_haproxy_conf': self.custom_haproxy_conf,
            'enable_cache': self.enable_cache,
            'cache_total_max_size': self.cache_total_max_size,
            'cache_max_age': self.cache_max_age,
            'enable_compression': self.enable_compression,
            'compression_algos': self.compression_algos,
            'compression_mime_types': self.compression_mime_types,
            'template': self.error_template.generate_frontend_conf() if self.error_template else "",
            'reputation_database_v4': reputation_database_v4,
            'reputation_database_v6': reputation_database_v6,
            'geoip_database': geoip_database,
            'reputation_ctxs': reputation_ctxs,
            'workflows': workflow_list,
            'access_controls_list': set(access_controls_list),
            'JAIL_ADDRESSES': JAIL_ADDRESSES,
            'CONF_PATH': HAPROXY_PATH,
            'tags': self.tags,
            'serialized_blwl_list': serialized_blwl_list,
            'darwin_policies': FilterPolicy.objects.filter(policy=self.darwin_policy),
            'keep_source_fields': self.keep_source_fields,
            'darwin_mode': self.darwin_mode,
        }

        if self.mode == "impcap":
            result['impcap_filter'] = self.impcap_filter
            result['impcap_intf'] = self.impcap_intf

        """ And returns the attributes of the class """
        return result

    def generate_conf(self, listener_list=None, header_list=None):
        """ Render the conf with Jinja template and self.to_template() method 
        :return     The generated configuration as string, or raise
        """
        """ If no HAProxy conf - Rsyslog only conf """
        if self.rsyslog_only_conf:
            return ""
        # The following var is only used by error, do not forget to adapt if needed
        template_name = JINJA_PATH + JINJA_TEMPLATE
        try:
            jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
            template = jinja2_env.get_template(JINJA_TEMPLATE)
            return template.render({'conf': self.to_template(listener_list=listener_list,
                                                             header_list=header_list)})
        # In ALL exceptions, associate an error message
        # The exception instantiation MUST be IN except statement, to retrieve traceback in __init__
        except TemplateNotFound:
            exception = ServiceJinjaError("The following file cannot be found : '{}'".format(template_name), "haproxy")
        except TemplatesNotFound:
            exception = ServiceJinjaError("The following files cannot be found : '{}'".format(template_name), "haproxy")
        except (TemplateAssertionError, TemplateRuntimeError) as e:
            exception = ServiceJinjaError("Unknown error in template generation: {} {}".format(template_name, str(e)), "haproxy")
        except UndefinedError:
            exception = ServiceJinjaError("A variable is undefined while trying to render the following template: "
                                          "{}".format(template_name), "haproxy")
        except TemplateSyntaxError:
            exception = ServiceJinjaError("Syntax error in the template: '{}'".format(template_name), "haproxy")
        # If there was an exception, raise a more general exception with the message and the traceback
        raise exception

    def test_conf(self):
        """ Write the configuration attribute on disk, in test directory, as {id}.conf.new
            And test the conf with 'haproxy -c'
        :return     True or raise
        """
        test_filename = self.get_test_filename()
        for node_name, conf in self.configuration.items():
            if not conf:
                return
            if node_name != Cluster.get_current_node().name:
                try:
                    global_config = Cluster().get_global_config()
                    cluster_api_key = global_config.cluster_api_key
                    infos = post("https://{}:8000/api/services/frontend/test_conf/".format(node_name),
                                 headers={'cluster-api-key': cluster_api_key},
                                 data={'conf': conf, 'filename': test_filename, 'disabled': not self.enabled},
                                 verify=False, timeout=9).json()
                except Exception as e:
                    logger.error(e)
                    raise ServiceTestConfigError("on node '{}'\n Request failure.".format(node_name), "haproxy")
                if not infos.get('status'):
                    raise ServiceTestConfigError("on node '{}'\n{}".format(node_name, infos.get('error')), "haproxy",
                                                 traceback=infos.get('error_details'))
            else:
                # Replace name of frontend to prevent duplicate frontend while testing conf
                test_haproxy_conf(test_filename,
                                  conf.replace("frontend {}".format(self.name),
                                               "frontend test_{}".format(self.id or "test"))
                                      .replace("listen {}".format(self.name),
                                               "listen test_{}".format(self.id or "test")),
                                  disabled=(not self.enabled))

    def get_base_filename(self):
        """ Return the base filename (without path) """
        return "frontend_{}.cfg".format(self.id)

    @property
    def api_file_path(self):
        """ """
        return "{}/api_file_{}.log".format(LOG_API_PATH, self.id)

    def get_filename(self):
        """ Return filename depending on current frontend object
        """
        return "{}/{}".format(HAPROXY_PATH, self.get_base_filename())

    def get_rsyslog_filename(self):
        from services.rsyslogd.rsyslog import RSYSLOG_PATH
        return "{}/{}".format(RSYSLOG_PATH, self.get_rsyslog_base_filename())

    def get_rsyslog_base_filename(self):
        return "10-{}-{}.conf".format(self.ruleset, self.id)

    def get_test_filename(self):
        """ Return test filename for test conf with haproxy
        """
        """ If object is not already saved : no id so default=test """
        return "frontend_{}.cfg".format(self.id or "test")

    def get_unix_socket(self):
        """ Return filename of unix socket on which HAProxy send data
         and on which Rsyslog listen
        """
        return "{}/frontend_{}.sock".format(UNIX_SOCKET_PATH, self.id)

    def get_ruleset(self):
        """ Return ruleset name that will be used in Rsyslog
         to parse the content
        """
        return "ruleset_{}".format(self.name)

    def save_conf(self, node):
        """ Write configuration on disk
        """
        if not self.configuration[node.name]:
            return
        params = [self.get_filename(), self.configuration[node.name], FRONTEND_OWNER, FRONTEND_PERMS]

        try:
            node.api_request('system.config.models.write_conf', config=params)
        except Exception as e:
            logger.error(e, exc_info=1)
            raise VultureSystemConfigError("on node '{}'.\nRequest failure.".format(node.name))

    def render_log_condition(self):
        log_oms = {}
        for line in self.log_condition.split('\n'):
            if line.count('{') < 2:
                continue
            match = re_search("{{([^}]+)}}", line)
            if match:
                log_om = LogOM().select_log_om_by_name(match.group(1))
                if log_om.internal and isinstance(log_om, LogOMMongoDB):
                    log_om.collection = self.ruleset
                log_oms[match.group(1)] = LogOM.generate_conf(log_om, self.ruleset, frontend=self.name)
                logger.info("Configuration of Log Forwarder named '{}' generated.".format(log_om.name))
        internal_ruleset = ""

        tpl = JinjaTemplate(self.log_condition)
        return internal_ruleset + "\n\n" + tpl.render(Context(log_oms, autoescape=False)) + "\n"

    def render_log_condition_failure(self):
        """ Render log_forwarders' config from self.log_forwarders_parse_failure 
            & Associate the correct template depending on parser
        :return  Str containing the rendered config
        """
        result = ""
        for log_forwarder in self.log_forwarders_parse_failure.all().only('id'):
            result += LogOM.generate_conf(LogOM().select_log_om(log_forwarder.id),
                                          self.ruleset+"_garbage",
                                          frontend=self.name+"_garbage") + "\n"
        return result

    def generate_rsyslog_conf(self):
        """ Generate rsyslog configuration of this frontend
        """
        # Import here to prevent
        from services.rsyslogd.rsyslog import JINJA_PATH as JINJA_RSYSLOG_PATH
        # The following var is only used by error, do not forget to adapt if needed
        template_name = "rsyslog_ruleset_{}/ruleset.conf".format(self.ruleset)
        try:
            jinja2_env = Environment(loader=FileSystemLoader(JINJA_RSYSLOG_PATH))
            template = jinja2_env.get_template(template_name)
            conf = self.to_template()
            conf['ruleset'] = self.ruleset
            conf['log_condition'] = self.render_log_condition()
            conf['log_condition_failure'] = self.render_log_condition_failure()
            conf['not_internal_forwarders'] = self.log_forwarders.exclude(internal=True)
            return template.render({'frontend': conf,
                                    'node': Cluster.get_current_node(),
                                    'global_config': Cluster.get_global_config()})
        # In ALL exceptions, associate an error message
        # The exception instantiation MUST be IN except statement, to retrieve traceback in __init__
        except TemplateNotFound as e:
            exception = ServiceJinjaError("The following file cannot be found : '{}'".format(e.message), "rsyslog")
        except TemplatesNotFound as e:
            exception = ServiceJinjaError("The following files cannot be found : '{}'".format(e.message), "rsyslog")
        except (TemplateAssertionError, TemplateRuntimeError) as e:
            exception = ServiceJinjaError("Unknown error in template generation: {}".format(e.message), "rsyslog")
        except UndefinedError as e:
            exception = ServiceJinjaError("A variable is undefined while trying to render the following template: "
                                          "{}".format(e.message), "rsyslog")
        except TemplateSyntaxError as e:
            exception = ServiceJinjaError("Syntax error in the template: '{}'".format(e.message), "rsyslog")
        # If there was an exception, raise a more general exception with the message and the traceback
        raise exception

    def get_log_socket(self):
        # FIXME : if not self.logs_enabled
        return

    def get_log_format(self):
        """ Return log format depending on frontend conf """
        log_format = "{ " \
                     "\\\"time-utc\\\": \\\"%[date,utime(%Y-%m-%dT%H:%M:%S:%Z)]\\\", " \
                     "\\\"bytes_read\\\": \\\"%B\\\", " \
                     "\\\"hostname\\\": \\\"%{+E}H\\\", " \
                     "\\\"status_code\\\": %ST, " \
                     "\\\"handshake_time\\\": %Th, " \
                     "\\\"unix_timestamp\\\": %Ts, " \
                     "\\\"bytes_received\\\": %U, " \
                     "\\\"active_conn\\\": %ac, " \
                     "\\\"backend_name\\\": \\\"%{+E}b\\\", " \
                     "\\\"beconn\\\": %bc, " \
                     "\\\"backend_ip\\\": \\\"%bi\\\", " \
                     "\\\"backend_port\\\": \\\"%bp\\\", " \
                     "\\\"backend_queue\\\": %bq, " \
                     "\\\"src_ip\\\": \\\"%ci\\\", " \
                     "\\\"src_port\\\": %cp, " \
                     "\\\"frontend_name\\\": \\\"%{+E}f\\\", " \
                     "\\\"feconn\\\": %fc, " \
                     "\\\"frontend_ip\\\": \\\"%fi\\\", " \
                     "\\\"frontend_port\\\": %fp, " \
                     "\\\"pid\\\": %pid, " \
                     "\\\"retries\\\": %rc, " \
                     "\\\"request_count\\\": %rt, " \
                     "\\\"server_name\\\": \\\"%{+E}s\\\", " \
                     "\\\"srvconn\\\": %sc, " \
                     "\\\"server_ip\\\": \\\"%si\\\", " \
                     "\\\"server_port\\\": \\\"%sp\\\", " \
                     "\\\"server_queue\\\": %sq, " \
                     "\\\"date_time\\\": \\\"%t\\\", " \
                     "\\\"termination_state\\\": \\\"%ts\\\", " \
                     "\\\"darwin_reputation_error\\\": \\\"%[var(txn.reputation.error)]\\\", " \
                     "\\\"darwin_reputation_score\\\": \\\"%[var(sess.reputation.ip_score)]\\\" "

        if self.mode == "http":
            log_format += ", \\\"unique_id\\\": \\\"%{+E}ID\\\", " \
                          "\\\"http_idle_time\\\": %Ti, " \
                          "\\\"captured_request_cookie\\\": \\\"%{+E}CC\\\", " \
                          "\\\"captured_response_cookie\\\": \\\"%{+E}CS\\\", " \
                          "\\\"http_method\\\": \\\"%{+E}HM\\\", " \
                          "\\\"http_path\\\": \\\"%{+E}HP\\\", " \
                          "\\\"http_get_params\\\": \\\"%{+E}HQ\\\", " \
                          "\\\"http_version\\\": \\\"%{+E}HV\\\", " \
                          "\\\"http_user_agent\\\": \\\"%[capture.req.hdr(0)]\\\", " \
                          "\\\"http_request_time\\\": %Ta, " \
                          "\\\"darwin_session_error\\\": \\\"%[var(txn.session.error)]\\\", " \
                          "\\\"darwin_user_agent_error\\\": \\\"%[var(txn.user_agent.error)]\\\", " \
                          "\\\"darwin_session_score\\\": \\\"%[var(sess.session.ip_score)]\\\", " \
                          "\\\"darwin_user_agent_score\\\": \\\"%[var(sess.user_agent.ip_score)]\\\", " \
                          "\\\"defender_score\\\": \\\"%[var(sess.defender.status)]\\\"" \
                          ", \\\"http_request_cookies\\\": \\\"%[capture.req.hdr(1),json(ascii)]\\\"" \
                          ", \\\"http_request_body\\\": \\\"%[var(sess.body),json(ascii)]\\\"" \
                          ", \\\"http_request_content_type\\\": \\\"%[capture.req.hdr(3),json(ascii)]\\\""
        log_format += "}"
        # TODO: Verify                          minimum one listener uses https
        # If yes : Add \\\"ssl_ciphers\\\": \\\"%sslc\\\", \\\"ssl_version\\\": \\\"%sslv\\\"
        return log_format

    def get_nodes(self):
        """
        :return: Return the node where the frontend has been declared
        """
        if self.listening_mode == "file":
            return {self.node}
        elif self.mode != "impcap":
            return set(Node.objects.filter(networkinterfacecard__networkaddress__listener__frontend=self.id))
        else:
            return {self.impcap_intf.node}

    def reload_conf(self):
        """ Generate conf based on MongoDB data and save-it on concerned nodes
         :return  A set of the updated nodes    or raise a ServiceError or SystemError
         """
        nodes = set()
        for node in self.get_nodes():
            # Generate frontend conf with no error_template
            self.configuration[node.name] = self.generate_conf()
            # And write conf on disk
            self.save_conf(node)
            # Add node to nodes, it's a set (unicity implicitly handled)
            nodes.add(node)
        # Save the object in database to save the configuration attribute
        self.save()
        return nodes

    def enable(self):
        """ Enable frontend in HAProxy, by management socket """
        """ Cannot enable a disabled frontend ('enable' field) """
        if not self.enabled:
            raise ServiceError("Cannot start a disabled frontend.", "haproxy", "enable frontend",
                               traceback="Please edit, enable and save a frontend to start-it.")
        """ If it is an Rsyslog only conf, start rsyslog """
        if self.rsyslog_only_conf:
            nodes = self.get_nodes()
            for node in nodes:
                api_res = node.api_request("services.rsyslogd.rsyslog.start_service")
                if not api_res.get('status'):
                    raise ServiceStartError("API request failure on node '{}'".format(node.name), "rsyslog",
                                            traceback=api_res.get('message'))
            return "Start rsyslog service asked on nodes {}".format(",".join([n.name for n in nodes]))
            # raise ServiceError("Cannot hot enable an Rsyslog only frontend.", "rsyslog", "enable frontend",
            #                   traceback="Please edit, enable and save the frontend.")
        else:
            nodes = self.get_nodes()
            for node in nodes:
                api_res = node.api_request("services.haproxy.haproxy.host_start_frontend", self.name)
                if not api_res.get('status'):
                    raise ServiceStartError("API request failure on node '{}'".format(node.name), "haproxy",
                                            traceback=api_res.get('message'))
            return "Start frontend '{}' asked on nodes {}".format(self.name, ",".join([n.name for n in nodes]))

    def disable(self):
        """ Disable frontend in HAProxy, by management socket """
        if not self.enabled:
            return "This frontend is already disabled."
        """ If it is an Rsyslog only conf, try to start service """
        if self.rsyslog_only_conf:
            raise ServiceError("Cannot hot disable an Rsyslog only frontend.", "rsyslog", "disable frontend",
                               traceback="Please edit, disable and save the frontend.")
        else:
            nodes = self.get_nodes()
            for node in nodes:
                api_res = node.api_request("services.haproxy.haproxy.host_stop_frontend", self.name)
                if not api_res.get('status'):
                    raise ServiceStartError("API request failure on node '{}'".format(node.name), "haproxy",
                                            traceback=api_res.get('message'))
            return "Stop frontend '{}' asked on nodes {}".format(self.name, ",".join([n.name for n in nodes]))

    @property
    def rsyslog_only_conf(self):
        """ Check if this frontend has only rsyslog configuration, not haproxy at all """
        return self.mode == "impcap" or (self.mode == "log" and (self.listening_mode in ("udp", "file", "api")))


class Listener(models.Model):
    """ Link class between NetworkAddress and Frontend """

    """ NetworkAddress object to listen on """
    network_address = models.ForeignKey(
        to=NetworkAddress,
        on_delete=models.CASCADE
    )
    """ Port To listen on """
    port = models.PositiveIntegerField(
        default=80,
        validators=[MinValueValidator(1), MaxValueValidator(65535)]
    )
    """ Frontend associated to this listener """
    frontend = models.ForeignKey(
        to=Frontend,
        null=True,
        on_delete=models.CASCADE
    )
    """ TLSProfile to use when listening """
    tls_profiles = models.ArrayReferenceField(
        TLSProfile,
        default=[],
        on_delete=models.SET_DEFAULT
    )
    """ List of ip to allow traffic from, or 'any' """
    whitelist_ips = models.TextField(
        default="any",
        help_text=_("IPs to allow traffic from")
    )
    max_src = models.PositiveIntegerField(
        default=100,
        validators=[MinValueValidator(0)],
        help_text=_("Max number of connexions per source.")
    )
    max_rate = models.PositiveIntegerField(
        default=1000,
        validators=[MinValueValidator(0)],
        help_text=_("Max number of new connexions per source per second.")
    )
    """ Incremented value between 10000 and 20000, to configure listen port of Rsyslog """
    rsyslog_port = models.PositiveIntegerField(
        default=10000
    )

    class Meta:
        """ Unicity constraint: Cannot bind twice on (address:port) """
        unique_together = ("network_address", "port")

    def to_template(self):
        """ Create a JSON representation of the object

        :return     Dictionnary of configuration parameters
        """
        """ Retrieve list/custom objects """

        return {
            'id': str(self.id),
            'network_address': str(self.network_address),
            'network_address_id': self.network_address.pk,
            'port': self.port,
            'frontend': self.frontend,
            'whitelist_ips': self.whitelist_ips,
            'max_src': self.max_src,
            'max_rate': self.max_rate,
            'addr_port': "{}:{}".format(self.network_address.ip, self.port),
            'is_tls': self.tls_profiles.count() > 0
        }

    def __str__(self):
        return "{}:{}".format(self.network_address.ip, self.port)

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['network_address', 'port']

    def generate_conf(self):
        """ Generate Listener HAProxy configuration
        :return     A string - Bind directive
        """
        result = "bind {}:{}".format(JAIL_ADDRESSES['haproxy'][self.network_address.family], self.rsyslog_port)
        if self.tls_profiles:
            for tls_profile in self.tls_profiles.all():
                result += tls_profile.generate_conf() + " "
        return result

    def generate_rsyslog_conf(self):
        """ Render Rsyslog specific configuration
         containing listening port and address
         :return    String - Rsyslog configuration parameters
        """
        """ If IPv6 - listen on IPv6 """
        return "Address=\"{}\" Port=\"{}\"".format(JAIL_ADDRESSES['rsyslog'][self.network_address.family],
                                                   self.rsyslog_port)

    def generate_server_conf(self):
        """ Generate directive configuration of "server" HAProxy
         :return     String - HAProxy server configuration parameter
         """
        return "{}:{}".format(JAIL_ADDRESSES['rsyslog'][self.network_address.family], self.rsyslog_port)

    def save(self, *args, **kwargs):
        if self.rsyslog_port == 10000:
            try:
                self.rsyslog_port = Listener.objects.latest('rsyslog_port').rsyslog_port + 1
            except:
                # Let port 1000 if no listener defined yet
                pass
        super().save(*args, **kwargs)


class FrontendReputationContext(models.Model):
    """  Intermediary class between Frontend and ReputationContext """
    frontend = models.ForeignKey(
        Frontend,
        null=True,
        on_delete=models.CASCADE
    )
    reputation_ctx = models.ForeignKey(
        ReputationContext,
        verbose_name=_("Custom tags"),
        on_delete=models.CASCADE
    )
    enabled = models.BooleanField(
        default=True,
        verbose_name=_("Enable"),
        help_text=_("Enable this ReputationContext in Frontend")
    )
    arg_field = models.TextField(
        default="",
        verbose_name=_("Input field name"),
        help_text=_("Field name to predict with MMDB Database")
    )


def ha_lt(criterion, key, value):
    return "{criterion} lt {value}".format(criterion=criterion, value=value), False


def ha_le(criterion, key, value):
    return "{criterion} le {value}".format(criterion=criterion, value=value), False


def ha_ge(criterion, key, value):
    return "{criterion} ge {value}".format(criterion=criterion, value=value), False


def ha_gt(criterion, key, value):
    return "{criterion} gt {value}".format(criterion=criterion, value=value), False


def ha_eq(criterion, key, value):
    return "{criterion} eq {value}".format(criterion=criterion, value=value), False


def ha_reg(criterion, key, value):
    return "{criterion} -m reg -i {value}".format(criterion=criterion, value=value), False


def get_comparator_ne(criterion, key, value):
    if value is None:
        return "{criterion} -m found".format(criterion=criterion), False

    else:
        if isinstance(value, str):
            return ha_str(criterion, key, value)[0], True
        elif isinstance(value, int) or isinstance(value, float):
            return ha_eq(criterion, key, value)[0], True
        else:
            return None


def ha_str(criterion, key, value):
    if not value:
        return "{criterion} -m len 0".format(criterion=criterion), False

    return "{criterion} -m str -i {value}".format(criterion=criterion, value=value), False


def ha_int(criterion, key, value):
    return "{criterion} -m int {value}".format(criterion=criterion, value=value), False


def ha_null(criterion, key, value):
    return "{criterion} -m found".format(criterion=criterion, value=value), True


def ha_count_args(line):
    args = 0

    for current_char in line:
        if current_char in ["'", "\"", " "]:
            continue

        args += 1

    return args


MAX_LINE_ARGS = 64  # as seen in the defaults.h file in the HAProxy source code

COMPARATOR_MAPPING = {
    "$regex": ha_reg,
    "equal_number": ha_int,  # custom comparator
    "equal_str": ha_str,  # custom comparator
    "equal_null": ha_null,  # custom comparator
    "$ne": get_comparator_ne,
    "$lt": ha_lt,
    "$lte": ha_le,
    "$gte": ha_ge,
    "$gt": ha_gt,
    "$eq": ha_eq,
}

CRITERION_MAPPING = {
    "-1": None,
    "active_conn": None,  # TODO: TO IMPLEMENT
    "backend_ip": None,  # TODO: TO IMPLEMENT
    "backend_name": None,  # TODO: TO IMPLEMENT
    "backend_port": None,  # TODO: TO IMPLEMENT
    "backend_queue": None,  # TODO: TO IMPLEMENT
    "beconn": None,  # TODO: TO IMPLEMENT
    "bytes_read": None,  # TODO: TO IMPLEMENT
    "bytes_received": None,  # TODO: TO IMPLEMENT
    "captured_request_cookie": "hdr(cookie)",
    "captured_response_cookie": None,  # TODO: TO IMPLEMENT
    "darwin_reputation_error": None,  # TODO: TO IMPLEMENT
    "darwin_reputation_score": None,  # TODO: TO IMPLEMENT
    "darwin_session_error": None,  # TODO: TO IMPLEMENT
    "darwin_session_score": None,  # TODO: TO IMPLEMENT
    "darwin_user_agent_error": None,  # TODO: TO IMPLEMENT
    "darwin_user_agent_score": None,  # TODO: TO IMPLEMENT
    "defender_score": None,  # TODO: TO IMPLEMENT
    "feconn": None,  # TODO: TO IMPLEMENT
    "frontend_ip": None,  # TODO: TO IMPLEMENT
    "frontend_name": None,  # TODO: TO IMPLEMENT
    "frontend_port": None,  # TODO: TO IMPLEMENT
    "handshake_time": None,  # TODO: TO IMPLEMENT
    "hostname": "hdr(host)",
    "http_get_params": None,  # TODO: TO IMPLEMENT
    "http_idle_time": None,  # TODO: TO IMPLEMENT
    "http_method": "method",
    "http_path": "path",
    "http_receive_time": None,  # TODO: TO IMPLEMENT
    "http_request": None,  # TODO: TO IMPLEMENT
    "http_request_body": None,  # TODO: TO IMPLEMENT
    "http_request_content_type": None,  # TODO: TO IMPLEMENT
    "http_request_cookies": None,  # TODO: TO IMPLEMENT
    "http_request_time": None,  # TODO: TO IMPLEMENT
    "http_response_time": None,  # TODO: TO IMPLEMENT
    "http_user_agent": "hdr(user-agent)",
    "http_version": None,  # TODO: TO IMPLEMENT
    "pid": None,  # TODO: TO IMPLEMENT
    "request_count": None,  # TODO: TO IMPLEMENT
    "retries": None,  # TODO: TO IMPLEMENT
    "server_ip": None,  # TODO: TO IMPLEMENT
    "server_name": None,  # TODO: TO IMPLEMENT
    "server_port": None,  # TODO: TO IMPLEMENT
    "server_queue": None,  # TODO: TO IMPLEMENT
    "src_ip": "src",
    "src_port": "src_port",
    "srvconn": None,  # TODO: TO IMPLEMENT
    "status_code": "status",
    "termination_state": None,  # TODO: TO IMPLEMENT
    "unique_id": None,  # TODO: TO IMPLEMENT
}


def get_haproxy_criterion(key):
    criterion = CRITERION_MAPPING[key]

    if criterion is None:
        raise KeyError(key)

    if callable(criterion):
        criterion = criterion(key)

    return criterion


class BlacklistWhitelist(models.Model):
    enabled = models.BooleanField(default=True)
    frontend = models.ForeignKey(Frontend, on_delete=models.CASCADE)
    rule = models.TextField()
    type_rule = models.TextField(default="blacklist")
    name = models.TextField(default="")

    def generate_conf(self):
        rules = json.loads(self.rule)

        mode = next(iter(rules))
        condition_list = []

        for pair in rules[mode]:
            key = next(iter(pair))
            item = pair[key]

            if not isinstance(item, dict):
                if isinstance(item, int) or isinstance(item, float):
                    current_comparator = "equal_number"
                    value = item

                elif isinstance(item, str):
                    current_comparator = "equal_str"
                    value = item

                elif item is None:
                    current_comparator = "equal_null"
                    value = item

                else:
                    logger.debug("Unknown type: {type} with {item}".format(type=type(item), item=item))
                    continue

            else:
                current_comparator = next(iter(item))
                value = item[current_comparator]

            try:
                callback = self.COMPARATOR_MAPPING[current_comparator]
            except KeyError:
                logger.debug("Unknown comparator: {comparator}".format(comparator=current_comparator))
                continue

            try:
                criterion = get_haproxy_criterion(key)
            except KeyError:
                logger.debug("Unknown criterion: {}".format(key))
                continue

            results = callback(criterion, key, value)

            if results is None:
                logger.debug("Results are None with criterion = {criterion}, key = {key} and value = {value}".format(
                    criterion=criterion, key=key, value=value
                ))

                continue

            condition_list.append(results)

        if len(condition_list) <= 0:
            return ""

        acl_name = "acl_"
        acl_name_list = []
        current_acl_name = "{}{}".format(acl_name, str(uuid.uuid4()))
        acl_name_list.append(current_acl_name)
        acl_str = ""
        spaces = "    "

        if mode == "$or":
            for condition_tuple in condition_list:
                acl_str += "acl {} {}\n{}".format(current_acl_name, condition_tuple[0], spaces)
                current_acl_name = "{}{}".format(acl_name, str(uuid.uuid4()))
                acl_name_list.append(current_acl_name)

            acl_str += "http-request deny if"
            condition_size = len(condition_list)

            for index in range(condition_size):
                inversion = ""

                if condition_list[index][1]:
                    inversion = "!"

                if index > 0:
                    acl_str += " or {}{}".format(inversion, acl_name_list[index])
                else:
                    acl_str += " {}{}".format(inversion, acl_name_list[index])

        else:
            for condition_tuple in condition_list:
                acl_str += "acl {} {}\n{}".format(current_acl_name, condition_tuple[0], spaces)
                current_acl_name = "{}{}".format(acl_name, str(uuid.uuid4()))
                acl_name_list.append(current_acl_name)

            acl_str += "http-request deny if"
            condition_size = len(condition_list)

            for index in range(condition_size):
                inversion = ""

                if condition_list[index][1]:
                    inversion = "!"

                acl_str += " {}{}".format(inversion, acl_name_list[index])

        return acl_str

    def to_html_template(self):
        """ Returns needed attributes for html rendering """
        return {
            'id': str(self.id),
            'frontend': self.frontend.name,
            'name': self.name
        }
