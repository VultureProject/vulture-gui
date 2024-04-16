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
from uuid import uuid4
import datetime
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.template import Context, Template as JinjaTemplate
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models

# Django project imports
from applications.logfwd.models import LogOM, LogOMMongoDB
from applications.reputation_ctx.models import ReputationContext, DATABASES_PATH
from darwin.policy.models import DarwinPolicy, FilterPolicy, DarwinBuffering
from services.haproxy.haproxy import test_haproxy_conf, HAPROXY_OWNER, HAPROXY_PATH, HAPROXY_PERMS
from system.error_templates.models import ErrorTemplate
from system.cluster.models import Cluster, NetworkAddress, NetworkInterfaceCard, Node
from applications.backend.models import Backend
from system.pki.models import TLSProfile, X509Certificate
from toolkit.network.network import JAIL_ADDRESSES
from toolkit.http.headers import Header
from system.tenants.models import Tenants

# Extern modules imports
from jinja2 import Environment, FileSystemLoader
from re import search as re_search
from requests import post
import glob

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
    ('log', 'LOG (Rsyslog)'),
    ('filebeat', 'LOG (Filebeat)')
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
    ('api', 'Vendor specific API'),
    ('kafka', 'KAFKA'),
    ('redis', 'REDIS'),
)

REDIS_MODE_CHOICES = (
    ('queue', "Queue mode, using push/pop"),
    ('subscribe',"Channel mode, using pub/sub"),
    ('stream',"Stream mode, using xread/xreadgroup"),
)

REDIS_STARTID_CHOICES = (
    ('$',"New entries"),
    ('-', "All entries"),
    ('>',"Undelivered entries"),
)

DARWIN_MODE_CHOICES = (
    ('darwin', "generate alerts"),
    ('both', "enrich logs and generate alerts")
)
SENTINEL_ONE_ACCOUNT_TYPE_CHOICES = (
    ('console', 'console'),
    ('user service', 'user service')
)

# Filebeat module list
FILEBEAT_MODULE_PATH = "/usr/local/etc/filebeat/modules.d"
FILEBEAT_MODULE_LIST = [('_custom', 'Custom Filebeat config')]
FILEBEAT_MODULE_CONFIG = {'_custom': '# Be sure to select the appropriate "Filebeat listening mode"\n\
# Use the following variables when needed: \n\n\
# - %ip% : This keyword will be replaced by your Listener\'s IP automatically\n\
# - %port% : This keyword will be replaced by your Listener\'s port automatically\n\n\
\
enabled: true \n\
host: "%ip%:%port%" \n\
max_message_size: 10MiB \n\n\
'}
done = []
def _getKey(item):
    return item[0]
for module in glob.glob(FILEBEAT_MODULE_PATH+'/*.yml*', recursive=True):
    name = module.split("/")[-1].replace(".yml.disabled","")
    if name not in done:
        FILEBEAT_MODULE_LIST.append ((name, name.replace('/',' ').capitalize()))
        with open (module, "r") as config:
            FILEBEAT_MODULE_CONFIG[name] = config.read()
    done.append(name)
    FILEBEAT_MODULE_LIST=sorted(FILEBEAT_MODULE_LIST, key=_getKey)


FILEBEAT_LISTENING_MODE = (
    ('tcp', "TCP"),
    ('udp', "UDP"),
    ('file', "File"),
    ('api', 'Vendor specific API')
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
    last_update_time = models.DateTimeField(
        default=timezone.now,
        editable=False,
        help_text=_("Datetime of the last frontend's update"),
    )
    """ Tags """
    tags = models.JSONField(
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
    """ *** DARWIN OPTIONS *** """
    """ Darwin policy """
    darwin_policies = models.ArrayReferenceField(
        to=DarwinPolicy,
        on_delete=models.PROTECT,
        null=True,
        blank=False,
        related_name="frontend_set",
        help_text=_("Darwin policies to use")
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
    tenants_config = models.ForeignKey(
        Tenants,
        default=1,
        null=True,
        on_delete=models.PROTECT,
        help_text=_("Tenants config used for logs enrichment")
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
    keep_source_fields = models.JSONField(
        default={}
    )
    """ Generated configuration depending on Node listening on """
    configuration = models.JSONField(
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
    ratelimit_interval = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=_("Specifies the rate-interval in seconds. 0 means no rate-limiting.")
    )
    ratelimit_burst = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=_("Specifies the rate-limiting burst in number of messages.")
    )
    """ Status of frontend for each nodes """
    status = models.JSONField(
        default={}
    )
    """ Mode of listening - tcp is handled by HAProxy, udp by Rsyslog """
    listening_mode = models.TextField(
        default="tcp",
        choices=LISTENING_MODE_CHOICES,
        help_text=_("TCP mode = HAProxy, UDP mode = Rsyslog")
    )
    """ Mode of listening for filebeat - tcp is handled by HAProxy, udp by Filebeat """
    filebeat_listening_mode = models.TextField(
        default="tcp",
        choices=FILEBEAT_LISTENING_MODE,
        help_text=_("TCP mode = HAProxy, UDP mode = Filebeat")
    )
    filebeat_module= models.TextField(
        default=FILEBEAT_MODULE_LIST[0][0],
        choices=FILEBEAT_MODULE_LIST,
        help_text=_("Filebeat built-in module")
    )
    """ Filebeat settings """
    filebeat_config = models.TextField (
        default="",
        help_text=_("Filebeat Input configuration. No output allowed here, as it is handled by Vulture")
    )
    """ Rsyslog TCP options """
    disable_octet_counting_framing = models.BooleanField(
        default=False,
        help_text=_("Enable option 'SupportOctetCountedFraming' in rsyslog (advanced).")
    )
    custom_tl_frame_delimiter = models.IntegerField(
        default=-1,
        blank=True,
        help_text=_("Additional frame delimiter"),
        verbose_name=_("Additional frame delimiter"),
        validators=[MinValueValidator(-1), MaxValueValidator(255)]
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
    """ Kafka mode attributes """
    kafka_brokers = models.JSONField(
        default=["192.168.1.2:9092"],
        help_text=_("Kafka broker(s) to connect to"),
        verbose_name=_("Kafka Broker(s)")
    )
    kafka_topic = models.TextField(
        default="mytopic",
        help_text=_("Kafka topic to connect to"),
        verbose_name=_("Kafka Topic")
    )
    kafka_consumer_group = models.TextField(
        default="my_group",
        help_text=_("Kafka consumer group to use to poll logs"),
        verbose_name=_("Kafka consumer group")
    )
    kafka_options = models.JSONField(
        default=[],
        help_text=_("Rsyslog imkafka 'confParams' options (See https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md)"),
        verbose_name=_("Kafka client options")
    )
    """ Redis attributes """
    redis_mode = models.TextField(
        default="queue",
        choices=REDIS_MODE_CHOICES,
        help_text=_("Redis comsumer mode - 'Queue' mode is recommended to avoid data loss"),
        verbose_name=_("Redis consumer mode")
    )
    redis_use_lpop = models.BooleanField(
        default=False,
        help_text=_("Default queue mode uses 'RPOP', toggle the button if you want to use 'LPOP'"),
        verbose_name=_("Use LPOP")
    )
    redis_server = models.TextField(
        default="127.0.0.5",
        help_text=_("Default Vulture internal master server is available on 127.0.0.5"),
        verbose_name=_("Redis server to use")
    )
    redis_port = models.PositiveIntegerField(
        default=6379,
        help_text=_("Default redis port is 6379"),
        verbose_name=_("Redis port to use")
    )
    redis_key = models.TextField(
        default="vulture",
        help_text=_("The redis key you want to pop from the queue / the redis channel you want to subscribe to"),
        verbose_name=_("Redis key")
    )
    redis_password = models.TextField(
        default="",
        help_text=_("Optional password to use via the 'AUTH' redis command when connecting to redis"),
        verbose_name=_("Redis password")
    )
    redis_stream_consumerGroup = models.TextField(
        default="",
        blank=True,
        help_text=_("Redis stream consumer group"),
        verbose_name=_("Redis stream consumer group")
    )
    redis_stream_consumerName = models.TextField(
        default="",
        blank=True,
        help_text=_("Redis stream consumer name"),
        verbose_name=_("Redis stream consumer name")
    )
    redis_stream_startID = models.TextField(
        default=REDIS_STARTID_CHOICES[0][0],
        choices=REDIS_STARTID_CHOICES,
        help_text=_("Redis stream start choice"),
        verbose_name=_("Redis stream start choice")
    )
    redis_stream_acknowledge = models.BooleanField(
        default=True,
        help_text=_("Acknowledge processed entries to Redis"),
        verbose_name=_("Acknowledge processed entries")
    )
    redis_stream_reclaim_timeout = models.PositiveIntegerField(
        default=0,
        blank=True,
        help_text=_("Automatically reclaim pending messages after X milliseconds"),
        verbose_name=_("Reclaim pending messages (ms)")
    )
    """ Performance settings """
    nb_workers = models.PositiveIntegerField(
        default=8,
        help_text=_("Maximum number of workers for rsyslog ruleset"),
        verbose_name=_("Maximum parser workers")
    )
    mmdb_cache_size = models.PositiveIntegerField(
        default=0,
        help_text=_("Number of entries of the LFU cache for mmdblookup."),
        verbose_name=_("mmdblookup LFU cache size")
    )
    redis_batch_size = models.PositiveIntegerField(
        default=10,
        help_text=_("Size of debatch queue for redis pipeline during *POP operations."),
        verbose_name=_("imhiredis debatch queue size")
    )
    """ Node is optional for KAFKA, FILE and REDIS modes """
    node = models.ForeignKey(
        to=Node,
        null=True,
        default=None,
        on_delete=models.SET_NULL,
        help_text=_("Vulture node")
    )
    """ *** VENDOR API OPTIONS *** """
    # General attributes
    api_parser_type = models.TextField(
        default="",
        help_text=_("API Parser Type")
    )
    api_parser_use_proxy = models.BooleanField(
        default=False,
        help_text=_("Use Proxy")
    )
    api_parser_custom_proxy = models.TextField(
        default="",
        help_text=_("Custom Proxy to use when requesting logs"),
        verbose_name=_("Custom Proxy")
    )
    api_parser_verify_ssl = models.BooleanField(
        default=True,
        help_text=_("Verify SSL"),
        verbose_name=_("Verify certificate")
    )
    api_parser_custom_certificate = models.ForeignKey(
        to=X509Certificate,
        null=True,
        on_delete=models.SET_NULL,
        related_name="certificate_used_by_api_parser",
        verbose_name=_("Custom certificate"),
        help_text=_("Custom certificate to use.")
    )
    last_api_call = models.DateTimeField(
        default=datetime.datetime.utcnow
    )
    # Forcepoint attributes
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
    # Symantec attributes
    symantec_username = models.TextField(
        help_text=_('Symantec Username'),
        default=""
    )
    symantec_password = models.TextField(
        help_text=_('Symantec Password'),
        default=""
    )
    symantec_token = models.TextField(
        help_text=_('Symantec Token'),
        default="none"
    )
    # AWS attributes
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
    # Akamai attributes
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
    # Office365 attributes
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
    # Imperva attributes
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
    # ReachFive attributes
    reachfive_host = models.TextField(
        help_text=_("ReachFive host"),
        default="reachfive.domain.com",
        verbose_name=_("ReachFive api endpoint domain")
    )
    reachfive_client_id = models.TextField(
        help_text=_("ReachFive client ID"),
        default="",
        verbose_name=_("ReachFive client ID for authentication")
    )
    reachfive_client_secret = models.TextField(
        help_text=_("ReachFive client secret"),
        default="",
        verbose_name=_("ReachFive client secret for authentication")
    )
    # MongoDB attributes
    mongodb_api_user = models.TextField(
        help_text=_("MongoDB API user"),
        default="",
        verbose_name=_("MongoDB user for authentication")
    )
    mongodb_api_password = models.TextField(
        help_text=_("MongoDB API password"),
        default="",
        verbose_name=_("MongoDB API password for authentication")
    )
    mongodb_api_group_id = models.TextField(
        help_text=_("MongoDB Group ID"),
        default="",
        verbose_name=_("MongoDB API group ID to retrieve log events from")
    )
    # Defender ATP attributes
    mdatp_api_tenant = models.TextField(
        help_text=_("Microsoft Defender ATP Tenant ID"),
        default="",
        verbose_name=_("Microsoft Defender Tenant ID")
    )
    mdatp_api_appid = models.TextField(
        help_text=_("Microsoft Defender ATP App ID"),
        default="",
        verbose_name=_("Microsoft Defender ATP App ID")
    )
    mdatp_api_secret = models.TextField(
        help_text=_("Microsoft Defender ATP App secret"),
        default="",
        verbose_name=_("Microsoft Defender ATP App secret")
    )
    # Cortex XDR attributes
    cortex_xdr_host = models.TextField(
        verbose_name=_("Cortex XDR FQDN"),
        default="xdr.domain.com",
        help_text=_("Cortex XDR api endpoint domain (without api-)")
    )
    cortex_xdr_apikey_id = models.TextField(
        verbose_name=_("Cortex XDR API Key ID"),
        default="",
        help_text=_("ID of the API Key from Cortex XDR settings")
    )
    cortex_xdr_apikey = models.TextField(
        verbose_name=_("Cortex XDR API Key"),
        default="",
        help_text=_("API Key from Cortex XDR settings")
    )
    cortex_xdr_alerts_timestamp = models.DateTimeField(
        default=None
    )
    cortex_xdr_incidents_timestamp = models.DateTimeField(
        default=None
    )
    # CyberReason attributes
    cybereason_host = models.TextField(
        help_text=_("Cybereason host"),
        default="domain.cybereason.net",
        verbose_name=_("Cybereason api endpoint")
    )
    cybereason_username = models.TextField(
        help_text=_("Cybereason username"),
        default="",
        verbose_name=_("Cybereason username for authentication")
    )
    cybereason_password = models.TextField(
        help_text=_("Cybereason password"),
        default="",
        verbose_name=_("Cybereason password for authentication")
    )
    # Cisco-Meraki attributes
    cisco_meraki_apikey = models.TextField(
        verbose_name=_("Cisco Meraki API key"),
        help_text=_("API key used to retrieve logs - as configured in Meraki settings"),
        default="",
    )
    cisco_meraki_timestamp = models.JSONField(
        default={}
    )
    # Proofpoint TAP attributes
    proofpoint_tap_host = models.TextField(
        help_text=_("ProofPoint TAP host"),
        default="https://tap-api-v2.proofpoint.com",
        verbose_name=_("ProofPoint API root url")
    )
    proofpoint_tap_endpoint = models.TextField(
        help_text=_("ProofPoint TAP endpoint"),
        choices=[
            ("/all", "all"),
            ("/clicks/blocked", "clicks/blocked"),
            ("/clicks/permitted", "clicks/permitted"),
            ("/messages/blocked", "messages/blocked"),
            ("/messages/delivered", "messages/delivered"),
            ("/issues", "issues"),
        ],
        default="/all",
        verbose_name=_("Types of messages to query from Proofpoint API")
    )
    proofpoint_tap_principal = models.TextField(
        help_text=_("ProofPoint TAP principal"),
        default="",
        verbose_name=_("API 'principal' (username)")
    )
    proofpoint_tap_secret = models.TextField(
        help_text=_("ProofPoint TAP secret"),
        default="",
        verbose_name=_("API 'secret' (password)")
    )
    # SentinelOne attributes
    sentinel_one_host = models.TextField(
        verbose_name = _("SentinelOne Host"),
        help_text = _("Hostname (without scheme or path) of the SentinelOne server"),
        default = "srv.sentinelone.net",
    )
    sentinel_one_apikey = models.TextField(
        verbose_name = _("Sentinel One API key"),
        help_text = _("API key used to retrieve logs - as configured in SentinelOne settings"),
        default = "",
    )
    sentinel_one_account_type = models.TextField(
        verbose_name = _("Sentinel One Account type"),
        choices=SENTINEL_ONE_ACCOUNT_TYPE_CHOICES,
        help_text = _("Type of account : console or user service"),
        default = SENTINEL_ONE_ACCOUNT_TYPE_CHOICES[0][0],
    )
    # CarbonBlack attributes
    carbon_black_host = models.TextField(
        verbose_name = _("CarbonBlack Host"),
        help_text = _("Hostname (without scheme or path) of the CarbonBlack server"),
        default = "defense.conferdeploy.net",
    )
    carbon_black_orgkey = models.TextField(
        verbose_name = _("CarbonBlack organisation name"),
        help_text = _("Organisation name"),
        default = "",
    )
    carbon_black_apikey = models.TextField(
        verbose_name = _("CarbonBlack API key"),
        help_text = _("API key used to retrieve logs"),
        default = "",
    )
    # Rapid7 IDR attributes
    rapid7_idr_host = models.TextField(
        verbose_name = _("rapid7 IDR Host"),
        help_text = _("Hostname (without scheme or path) of the Rapid7 server"),
        default = "eu.api.insight.rapid7.com",
    )
    rapid7_idr_apikey = models.TextField(
        verbose_name = _("Rapid7 IDR API key"),
        help_text = _("API key used to retrieve logs"),
        default = "",
    )
    # HarfangLab attributes
    harfanglab_host = models.TextField(
        verbose_name = _("HarfangLab Host"),
        help_text = _("Hostname (without scheme or path) of the HarfangLab server"),
        default = "",
    )
    harfanglab_apikey = models.TextField(
        verbose_name = _("HarfangLab API key"),
        help_text = _("API key to use to contact HarfangLab api"),
        default = "",
    )
    # Vadesecure attributes
    vadesecure_host = models.TextField(
        verbose_name = _("Vadesecure Host"),
        help_text = _("Hostname (without scheme or path) of the Vadesecure server"),
        default = "",
    )
    vadesecure_login = models.TextField(
        verbose_name = _("Vadesecure login"),
        help_text = _("Login used to fetch the token for the Vadesecure API"),
        default = "",
    )
    vadesecure_password = models.TextField(
        verbose_name = _("Vadesecure password"),
        help_text = _("Password used to fetch the token for the Vadesecure API"),
        default = "",
    )
    # Defender attributes
    defender_token_endpoint = models.TextField(
        verbose_name = _("Defender token endpoint"),
        help_text = _("Complete enpoint address to get an Oauth token before requesting Microsoft's APIs"),
        default = "",
    )
    defender_client_id = models.TextField(
        verbose_name = _("Defender OAuth client id"),
        help_text = _("Client id of the OAuth endpoint to get an OAuth token before requesting Microsoft's APIs"),
        default = "",
    )
    defender_client_secret = models.TextField(
        verbose_name = _("Defender OAuth client secret"),
        help_text = _("Client secret of the OAuth endpoint to get an OAuth token before requesting Microsoft's APIs"),
        default = "",
    )
    # CrowdStrike attributes
    crowdstrike_host = models.TextField(
        verbose_name = _("CrowdStrike Host"),
        help_text = _("Complete enpoint address"),
        default = "",
    )
    crowdstrike_client = models.TextField(
        verbose_name = _("CrowdStrike Username"),
        help_text = _("User's name"),
        default = "",
    )
    crowdstrike_client_id = models.TextField(
        verbose_name = _("CrowdStrike Client ID"),
        help_text = _("Client ID used for authentication"),
        default = "",
    )
    crowdstrike_client_secret = models.TextField(
        verbose_name = _("CrowdStrike Client's Secret"),
        help_text = _("Client's secret used for authentication"),
        default = "",
    )
    # Vadesecure 0365 attributes
    vadesecure_o365_host = models.TextField(
        verbose_name = _("Vadesecure O365 Host"),
        help_text = _("FQDN of the API endpoint"),
        default = "",
    )
    vadesecure_o365_tenant = models.TextField(
        verbose_name = _("Vadesecure O365 tenant"),
        help_text = _("Tenant"),
        default = "",
    )
    vadesecure_o365_client_id = models.TextField(
        verbose_name = _("Vadesecure O365 Client ID"),
        help_text = _("Client ID used for authentication"),
        default = "",
    )
    vadesecure_o365_client_secret = models.TextField(
        verbose_name = _("Vadesecure O365 Client's Secret"),
        help_text = _("Client's secret used for authentication"),
        default = "",
    )
    # Only used internally to keep a valid access_token across runs
    vadesecure_o365_access_token = models.TextField(
        verbose_name = _("API current cached token"),
        default = "",
    )
    # Only used internally to keep a valid access_token across runs
    vadesecure_o365_access_token_expiry = models.DateTimeField(
        default=datetime.datetime.utcnow
    )
    # Nozomi Probe attributes
    nozomi_probe_host = models.TextField(
        verbose_name = _("Nozomi Probe Host"),
        help_text = _("Hostname (without scheme or path) of the Nozomi Probe"),
        default = "",
    )
    nozomi_probe_login = models.TextField(
        verbose_name = _("Nozomi Probe User"),
        help_text = _("User to use to contact Nozomi probe api"),
        default = "",
    )
    nozomi_probe_password = models.TextField(
        verbose_name=_("Nozomi Probe Password"),
        help_text=_("Password to use to contact Nozomi probe api"),
        default="",
    )
    # Blackberry Cylance attributes
    blackberry_cylance_host = models.TextField(
        verbose_name = _("Blackberry Cylance Host"),
        help_text = _("FQDN of the API endpoint"),
        default = "",
    )
    blackberry_cylance_tenant = models.TextField(
        verbose_name = _("Blackberry Cylance tenant"),
        help_text = _("Tenant"),
        default = "",
    )
    blackberry_cylance_app_id = models.TextField(
        verbose_name = _("Blackberry Cylance Application ID"),
        help_text = _("Client ID used for authentication"),
        default = "",
    )
    blackberry_cylance_app_secret = models.TextField(
        verbose_name = _("Blackberry Cylance Application's Secret"),
        help_text = _("Client's secret used for authentication"),
        default = "",
    )
    # Microsoft Sentinel attributes
    ms_sentinel_tenant_id = models.TextField(
        verbose_name = _("Microsoft Sentinel Tenant ID"),
        help_text = _("Your Microsoft Tenant ID"),
        default = "",
    )
    ms_sentinel_appid = models.TextField(
        verbose_name = _("Microsoft Sentinel App ID"),
        help_text = _("Microsoft Sentinel Client ID"),
        default = "",
    )
    ms_sentinel_appsecret = models.TextField(
        verbose_name=_("Microsoft Sentinel App Secret"),
        help_text=_("Application Secret"),
        default="",
    )
    ms_sentinel_subscription_id = models.TextField(
        verbose_name=_("Microsoft Sentinel Subscription ID"),
        help_text=_("Subscription ID"),
        default="",
    )
    ms_sentinel_resource_group = models.TextField(
        verbose_name=_("Microsoft Sentinel Resource Group"),
        help_text=_("Resource Group name"),
        default="",
    )
    ms_sentinel_workspace = models.TextField(
        verbose_name=_("Microsoft Sentinel Workspace"),
        help_text=_("Workspace name"),
        default="",
    )
    # Proofpoint PoD Attributes
    proofpoint_pod_uri = models.TextField(
        verbose_name=_("Proofpoint PoD URI"),
        help_text=_("Server URI"),
        default="wss://logstream.proofpoint.com:443/v1/stream",
    )
    proofpoint_pod_cluster_id = models.TextField(
        verbose_name=_("Proofpoint PoD Cluster ID"),
        help_text=_("Cluster ID"),
        default="",
    )
    proofpoint_pod_token = models.TextField(
        verbose_name=_("Proofpoint PoD Authentication token"),
        help_text=_("Authentication token"),
        default="",
    )
    # Netskope attributes
    netskope_host = models.TextField(
        verbose_name = _("Netskope Host"),
        help_text = _("Hostname (without scheme or path) of the Netskope server"),
        default = "example.goskope.com",
    )
    netskope_apikey = models.TextField(
        verbose_name = _("Netskope API token used to retrieve events"),
        help_text = _("Netskope API token"),
        default = "",
    )
    # WAF Cloudflare attributes
    waf_cloudflare_apikey = models.TextField(
        verbose_name = _("WAF Cloudflare API token"),
        help_text = _("WAF Cloudflare  API token"),
        default = "",
    )
    waf_cloudflare_zoneid = models.TextField(
        verbose_name = _("WAF Cloudflare zone ID"),
        help_text = _("WAF Cloudflare zone ID"),
        default = "",
    )
    # Google worspace alertcenter attributes
    gsuite_alertcenter_json_conf = models.TextField(
        verbose_name = _("Google Alertcenter JSON Conf"),
        help_text = _("Your JSON Conf from Google"),
        default = "",
    )
    gsuite_alertcenter_admin_mail = models.TextField(
        verbose_name = _("Google Alertcenter Admin email for delegated wrights"),
        help_text = _("Google Alertcenter Admin email"),
        default = "",
    )
    # Sophos Cloud attributes
    sophos_cloud_client_id = models.TextField(
        verbose_name=_("Sophos Cloud - Client ID"),
        help_text=_("Client ID"),
        default="",
    )
    sophos_cloud_client_secret = models.TextField(
        verbose_name=_("Sophos Cloud - Client Secret"),
        help_text=_("Client Secret"),
        default="",
    )
    sophos_cloud_tenant_id = models.TextField(
        verbose_name=_("Sophos Cloud - Tenant ID"),
        help_text=_("Tenant ID"),
        default="",
    )
    # Trendmicro_worryfree attributes
    trendmicro_worryfree_access_token = models.TextField(
        verbose_name = _("Trendmicro Worryfree access token"),
        help_text = _("Trendmicro Worryfree access token"),
        default = "",
    )
    trendmicro_worryfree_secret_key = models.TextField(
        verbose_name = _("Trendmicro Worryfree secret key"),
        help_text = _("Trendmicro Worryfree secret key"),
        default = "",
    )
    trendmicro_worryfree_server_name = models.TextField(
        verbose_name = _("Trendmicro Worryfree server name"),
        help_text = _("Trendmicro Worryfree server name"),
        default = "cspi.trendmicro.com",
    )
    trendmicro_worryfree_server_port = models.TextField(
        verbose_name = _("Trendmicro Worryfree server port"),
        help_text = _("Trendmicro Worryfree server port"),
        default = "443",
    )
    # Safenet attributes
    safenet_tenant_code = models.TextField(
        verbose_name = _("Safenet Tenant Code"),
        help_text = _("Your Safenet Tenant Code"),
        default = "",
    )
    safenet_apikey = models.TextField(
        verbose_name = _("Safenet API Key"),
        help_text = _("Safenet Token API"),
        default = "",
    )
    # SignalSciences NGWAF attributes
    signalsciences_ngwaf_email = models.TextField(
        verbose_name = _("SignalSciences NGWAF email"),
        help_text = _("SignalSciences NGWAF email"),
        default = "",
    )
    signalsciences_ngwaf_token = models.TextField(
        verbose_name = _("SignalSciences NGWAF token"),
        help_text = _("SignalSciences NGWAF token"),
        default = "",
    )
    signalsciences_ngwaf_corp_name = models.TextField(
        verbose_name = _("SignalSciences NGWAF corporation name"),
        help_text = _("SignalSciences NGWAF corporation name"),
        default = "",
    )
    signalsciences_ngwaf_site_name = models.TextField(
        verbose_name = _("SignalSciences NGWAF site name"),
        help_text = _("SignalSciences NGWAF site name"),
        default = "",
    )
    # Proofpoint CASB attributes
    proofpoint_casb_api_key = models.TextField(
        help_text=_("Proofpoint CASB API KEY"),
        default=""
    )
    proofpoint_casb_client_id = models.TextField(
        help_text=_('Proofpoint CASB Client ID'),
        default=""
    )
    proofpoint_casb_client_secret = models.TextField(
        help_text=_('Proofpoint CASB Client Secret'),
        default=""
    )
    # Proofpoint TRAP attributes
    proofpoint_trap_host = models.TextField(
        verbose_name = _("ProofPoint TRAP host"),
        help_text = _("ProofPoint API root url"),
        default = "",
    )
    proofpoint_trap_apikey = models.TextField(
        verbose_name = _("ProofPoint TRAP API key"),
        help_text = _("ProofPoint TRAP API key"),
        default = "",
    )
    # WAF Cloud Protector attributes
    waf_cloud_protector_host = models.TextField(
        verbose_name = _("WAF CloudProtector host"),
        help_text = _("Hostname (without scheme or path) of the CloudProtector server"),
        default = "api-region.cloudprotector.com",
    )
    waf_cloud_protector_api_key_pub = models.TextField(
        verbose_name = _("WAF CloudProtector public key"),
        help_text = _("base64 encodid public key to contact CloudProtector API"),
        default = "base64",
    )
    waf_cloud_protector_api_key_priv = models.TextField(
        verbose_name = _("WAF CloudProtector private key"),
        help_text = _("base64 encodid private key to contact CloudProtector API"),
        default = "base64",
    )
    waf_cloud_protector_provider = models.TextField(
        verbose_name = _("WAF Cloud Protector provider"),
        help_text = _("Provider used to retrieve event from"),
        default = "",
    )
    waf_cloud_protector_tenant = models.TextField(
        verbose_name = _("WAF Cloud Protector tenant"),
        help_text = _("Tenant used to retrieve event from"),
        default = "",
    )
    waf_cloud_protector_servers = models.TextField(
        verbose_name = _("WAF Cloud Protector servers"),
        help_text = _("Servers to for wich to retrieve traffic and alert events"),
        default = "www.example.com",
    )
    waf_cloud_protector_timestamps = models.JSONField(
        default={ "alert": {}, "traffic": {} }
    )
    # Trendmicro visionone attributes
    trendmicro_visionone_token = models.TextField(
        verbose_name=_("Trendmicro visionone token"),
        help_text=_("Trendmicro visionone token"),
        default="none",
    )
    trendmicro_visionone_alerts_timestamp = models.DateTimeField(
        default=None
    )
    trendmicro_visionone_audit_timestamp = models.DateTimeField(
        default=None
    )
    trendmicro_visionone_oat_timestamp = models.DateTimeField(
        default=None
    )
    # Cisco Duo attributes
    cisco_duo_host = models.TextField(
        verbose_name=_("Cisco Duo API hostname"),
        help_text=_("Cisco Duo API hostname"),
        default="api-XXXXXXXX.duosecurity.com",
    )
    cisco_duo_ikey = models.TextField(
        verbose_name=_("Cisco Duo API ikey"),
        help_text=_("Cisco Duo API integration key"),
        default="",
    )
    cisco_duo_skey = models.TextField(
        verbose_name=_("Cisco Duo API skey"),
        help_text=_("Cisco Duo API secret key"),
        default="",
    )
    cisco_duo_offsets = models.JSONField(
        default=dict
    )
    # Sentinel One Mobile attributes
    sentinel_one_mobile_host = models.TextField(
        verbose_name=_("Sentinel One Mobile API hostname"),
        help_text=_("Sentinel One Mobile API hostname"),
        default="https://xxx.mobile.sentinelone.net",
    )
    sentinel_one_mobile_apikey = models.TextField(
        verbose_name=_("Sentinel One Mobile API ikey"),
        help_text=_("Sentinel One Mobile API integration key"),
        default="",
    )
    #CSC DomainManager attributes
    csc_domainmanager_apikey = models.TextField(
        verbose_name = ("CSC DomainManager API Key"),
        help_text = ("CSC DomainManager API Key"),
        default=""
    )
    csc_domainmanager_authorization = models.TextField(
        verbose_name = ("CSC DomainManager Authorization HTTP Header token prefixed by Bearer, ex: Bearer xxxx-xxxx-xxxx-xxxx"),
        help_text = ("CSC DomainManager Authorization"),
        default=""
    )
    # Retarus attributes
    retarus_token = models.TextField(
        verbose_name=_("Retarus token"),
        help_text=_("Retarus token"),
        default = ""
    )
    retarus_channel = models.TextField(
        verbose_name=_("Retarus channel"),
        help_text=_("Retarus channel"),
        default="",
    )
    # Vectra attributes
    vectra_host = models.TextField(
        verbose_name=_("Vectra url"),
        help_text=_("Vectra url"),
        default = ""
    )
    vectra_secret_key = models.TextField(
        verbose_name=_("Vectra secret key"),
        help_text=_("Vectra secret key"),
        default="",
    )
    vectra_client_id = models.TextField(
        verbose_name=_("Vectra client id"),
        help_text=_("Vectra client id"),
        default="",
    )
    vectra_access_token = models.TextField(
        verbose_name=_("Vectra access token"),
        help_text=_("Vectra access token"),
        default="",
    )
    vectra_expire_at = models.DateTimeField(
        verbose_name=_("Vectra access token expire at"),
        help_text=_("Vectra access token expire at"),
        default=timezone.now,
    )
    # Apex attributes
    apex_server_host = models.TextField(
        verbose_name=_("Apex server host"),
        help_text=_("Apex server host"),
        default = ""
    )
    apex_api_key = models.TextField(
        verbose_name=_("Apex api key"),
        help_text=_("Apex api key"),
        default="",
    )
    apex_application_id = models.TextField(
        verbose_name=_("Apex application id"),
        help_text=_("Apex application id"),
        default="",
    )
    apex_timestamp = models.JSONField(
        default={}
    )
    apex_page_token = models.JSONField(
        default={}
    )
    # Gatewatcher attributes
    gatewatcher_alerts_host = models.TextField(
        verbose_name=_("Gatewatcher alerts host"),
        help_text=_("Gatewatcher alerts host"),
        default = "",
    )
    gatewatcher_alerts_api_key = models.TextField(
        verbose_name=_("Gatewatcher alerts api key"),
        help_text=_("Gatewatcher alerts api key"),
        default="",
    )
    # Cisco-Umbrella attributes
    cisco_umbrella_client_id = models.TextField(
        verbose_name=_("Cisco-Umbrella client id"),
        help_text=_("Cisco-Umbrella client id"),
        default="",
    )
    cisco_umbrella_secret_key = models.TextField(
        verbose_name=_("Cisco-Umbrella secret key"),
        help_text=_("Cisco-Umbrella secret key"),
        default="",
    )
    cisco_umbrella_access_token = models.TextField(
        verbose_name=_("Cisco-Umbrella access token"),
        default="",
    )
    cisco_umbrella_expires_at = models.DateTimeField(
        verbose_name=_("Cisco-Umbrella token expiration time"),
        default=timezone.now,
    )

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
            exclude = set('log_forwarders')
        else:
            exclude.add('log_forwarders')
        return super().clean_fields(exclude=exclude)

    def to_dict(self, fields=None):
        """ This method MUST be used in API instead of to_template() method
                to prevent no-serialization of sub-models like Listeners
        :return     A JSON object
        """
        result = model_to_dict(self, fields=fields)
        if not fields or "id" in fields:
            result['id'] = str(result['id'])
        if not fields or "tenant_name" in fields:
            result['tenant_name'] = self.tenants_config.name
        if not fields or "listeners" in fields:
            result['listeners'] = []
            """ Add listeners, except if listening_mode is file """
            # Test self.pk to prevent M2M errors when object isn't saved in DB
            if self.pk:
                for listener in self.listener_set.all():
                    l = listener.to_template()
                    # Remove frontend to prevent infinite loop
                    del l['frontend']
                    result['listeners'].append(l)
        if not fields or "backend" in fields:
            result['backend'] = [b.to_dict() for b in self.backend.all()] if self.pk else []
        if not fields or "darwin_policies" in fields:
            result['darwin_policies'] = list(self.darwin_policies.all())
        if not fields or "darwin_policies" in fields:
            result['darwin_policies'] = list(self.darwin_policies.all())
        if not fields or "compression_algos" in fields:
            result['compression_algos'] = self.compression_algos.split(' ')

        """ Other attributes """
        if not fields or "headers" in fields:
            result['headers'] = []
            if self.mode == "http":
                for header in self.headers.all():
                    result['headers'].append(header.to_template())

        if not fields or "reputation_ctxs" in fields:
            # Test self.pk to prevent M2M errors when object isn't saved in DB
            result["reputation_ctxs"] = [ctx.to_dict() for ctx in self.frontendreputationcontext_set.all()] if self.pk else []
        if not fields or "logging_reputation_database_v4" in fields:
            if self.logging_reputation_database_v4:
                result['logging_reputation_database_v4'] = self.logging_reputation_database_v4.to_template()

        if not fields or "logging_reputation_database_v6" in fields:
            if self.logging_reputation_database_v6:
                result['logging_reputation_database_v6'] = self.logging_reputation_database_v6.to_template()

        if not fields or "logging_geoip_database" in fields:
            if self.enable_logging_geoip:
                result['logging_geoip_database'] = self.logging_geoip_database.to_template()

        if not fields or "log_forwarders_parse_failure" in fields:
            result['log_forwarders_parse_failure'] = [LogOM().select_log_om(log_fwd.id).to_template()
                                                    for log_fwd in self.log_forwarders_parse_failure.all().only('id')]

        if not fields or "log_forwarders" in fields:
            result['log_forwarders'] = [LogOM().select_log_om(log_fwd.id).to_template()
                                    for log_fwd in self.log_forwarders.all().only('id')]

        if not fields or "api_parser_custom_certificate" in fields:
            if result['api_parser_custom_certificate'] == None:
                result['api_parser_custom_certificate'] = {}

        return result

    def to_html_template(self):
        """ Dictionary used to render object as html
        :return     Dictionnary of configuration parameters
        """
        """ Retrieve list/custom objects """
        if self.listening_mode == "file":
            listeners_list = [self.file_path]
        elif self.listening_mode == "api":
            listeners_list = [self.api_parser_type]
        else:
            # Test self.pk to prevent M2M errors when object isn't saved in DB
            listeners_list = [str(l) for l in self.listener_set.all().only(*Listener.str_attrs())] if self.pk else []

        log_forwarders = [str(l) for l in self.log_forwarders.all()]

        mode = "UNKNOWN"
        for m in MODE_CHOICES:
            if self.mode == m[0]:
                mode = m[1]

        additional_infos = []
        if self.mode == "log":
            listening_mode = "UNKNOWN"
            for m in LISTENING_MODE_CHOICES:
                if self.listening_mode == m[0]:
                    listening_mode = m[1]
            additional_infos.append("Listening mode : {}".format(listening_mode))
            additional_infos.append("Data type : {}".format(self.ruleset))
        elif self.mode == "http":
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

    def to_template(self, listener_list=[], header_list=None, node=None):
        """ Dictionary used to create configuration file

        :return     Dictionnary of configuration parameters
        """
        """ Retrieve list/custom objects """
        # If facultative arg listener_list is not given
        # Test self.pk to prevent M2M errors when object isn't saved in DB
        if not listener_list and self.pk:
            # Retrieve listeners into database
            # No .only ! Used to generated conf, neither str, we need the whole object
            if node:
                listener_list = self.listener_set.filter(network_address__nic__node=node)
            else:
                listener_list = self.listener_set.all()

        # Same for headers
        if not header_list:
            header_list = self.headers.all()


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
        # Test self.pk to prevent M2M errors when object isn't saved in DB
        if self.enable_logging and self.pk:
            for reputation_ctx in self.frontendreputationcontext_set.filter(enabled=True):
                reputation_ctxs.append(reputation_ctx)

        workflow_list = []
        if self.pk:
            for w in self.workflow_set.filter(enabled=True):
                workflow_list.append({
                    'id': w.pk,
                    'name': w.name,
                    'backend_name': w.backend.name,
                    'timeout_connect': w.backend.timeout_connect,
                    'timeout_server': w.backend.timeout_server,
                    'mode': w.mode,
                    'fqdn': w.fqdn,
                    'public_dir': w.public_dir,
                    'enable_cors_policy': w.enable_cors_policy,
                    'cors_allowed_methods': w.cors_allowed_methods,
                    'cors_allowed_origins': w.cors_allowed_origins,
                    'cors_allowed_headers': w.cors_allowed_headers,
                    'cors_max_age': w.cors_max_age,
                })

        result = {
            'id': str(self.pk),
            'enabled': self.enabled,
            'name': self.name,
            'listeners': listener_list,
            'https_redirect': self.https_redirect,
            'mode': self.mode,
            'timeout_client': self.timeout_client,
            'timeout_keep_alive': self.timeout_keep_alive,
            'enable_logging': self.enable_logging,
            'log_format': self.get_log_format(),
            'log_level': self.log_level,
            'log_condition': self.log_condition,
            'ruleset_name': self.get_ruleset(),
            'parser_tag': self.parser_tag,
            'ratelimit_interval': self.ratelimit_interval,
            'ratelimit_burst': self.ratelimit_burst,
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
            'workflows': sorted(workflow_list, reverse=True, key=lambda x: len(x['public_dir'].split('/'))),
            'JAIL_ADDRESSES': JAIL_ADDRESSES,
            'CONF_PATH': HAPROXY_PATH,
            'tags': self.tags,
            'nb_workers': self.nb_workers,
            'mmdb_cache_size': self.mmdb_cache_size,
            'redis_batch_size': self.redis_batch_size,
            'redis_server': self.redis_server,
            'redis_port': self.redis_port,
            'redis_password': self.redis_password,
            'darwin_filters': FilterPolicy.objects.filter(policy__in=self.darwin_policies.all()),
            'keep_source_fields': self.keep_source_fields,
            'darwin_mode': self.darwin_mode,
            'tenants_config': self.tenants_config,
            'filebeat_module': self.filebeat_module,
            'filebeat_config': self.filebeat_config,
            'filebeat_listening_mode': self.filebeat_listening_mode,
            # Test self.pk to prevent M2M errors when object isn't saved in DB
            'external_idps': self.userauthentication_set.filter(enable_external=True) if self.pk else [],
        }

        """ And returns the attributes of the class """
        return result

    def generate_conf(self, listener_list=None, header_list=None, node=None):
        """ Render the conf with Jinja template and self.to_template() method
        :return     The generated configuration as string, or raise
        """
        """ If no HAProxy conf - Rsyslog only conf """
        if self.rsyslog_only_conf or self.filebeat_only_conf:
            return ""
        # The following var is only used by error, do not forget to adapt if needed
        template_name = JINJA_PATH + JINJA_TEMPLATE
        try:
            jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
            template = jinja2_env.get_template(JINJA_TEMPLATE)
            return template.render({'conf': self.to_template(listener_list=listener_list,
                                                             header_list=header_list,
                                                             node=node),
                                    'global_config': Cluster.get_global_config().to_dict()})
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

    def test_conf(self, node_name):
        """ Write the configuration attribute on disk, in test directory, as {id}.conf.new
            And test the conf with 'haproxy -c'
        :return     True or raise
        """
        test_filename = self.get_test_filename()
        conf = self.configuration.get(node_name)
        if not conf:
            return
        test_conf = conf.replace(f"frontend {self.name}", f"frontend {uuid4()}") \
                        .replace(f"listen {self.name}", f"listen test_{uuid4()}")
        if self.pk:
            for workflow in self.workflow_set.all():
                test_conf = test_conf.replace(f"backend Workflow_{workflow.pk}", f"backend {uuid4()}")
        if node_name != Cluster.get_current_node().name:
            try:
                cluster_api_key = Cluster().get_global_config().cluster_api_key
                infos = post(f"https://{node_name}:8000/api/services/frontend/test_conf/",
                             headers={'cluster-api-key': cluster_api_key},
                             data={'conf': test_conf, 'filename': test_filename, 'disabled': not self.enabled},
                             verify=X509Certificate.objects.get(name=node_name).ca_filename(), timeout=30).json()
            except Exception as e:
                # Node may be unavailable for the moment
                # Changes will be synced if node is up within 30 days
                logger.error(e)
                raise ServiceTestConfigError("on node '{}'\n Request failure.".format(node_name), "haproxy")
            if not infos.get('status'):
                raise ServiceTestConfigError(f"on node '{node_name}'\n{infos.get('error')}", "haproxy",
                                            traceback=infos.get('error_details'))
        else:
            # Replace name of frontend to prevent duplicate frontend while testing conf
            test_haproxy_conf(test_filename,
                              test_conf,
                              disabled=(not self.enabled))

    def get_base_filename(self):
        """ Return the base filename (without path) """
        return "frontend_{}.cfg".format(self.id)

    @property
    def api_file_path(self):
        """ """
        return "{}/api_file_{}.sock".format(LOG_API_PATH, self.id)

    def get_filename(self):
        """ Return filename depending on current frontend object
        """
        return "{}/{}".format(HAPROXY_PATH, self.get_base_filename())

    def get_rsyslog_filename(self):
        from services.rsyslogd.rsyslog import RSYSLOG_PATH
        return "{}/{}".format(RSYSLOG_PATH, self.get_rsyslog_base_filename())

    def get_rsyslog_base_filename(self):
        return "10-{}-{}.conf".format(self.ruleset, self.id)

    def get_filebeat_filename(self):
        from services.filebeat.filebeat import FILEBEAT_PATH
        return f"{FILEBEAT_PATH}/{self.get_filebeat_base_filename()}"

    def get_filebeat_base_filename(self):
        return f"filebeat_{self.id}.yml"

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
        clean_log_condition = self.log_condition
        for line in self.log_condition.split('\n'):
            if line.count('{') < 2:
                continue
            match = re_search("{{([^}]+)}}", line)
            if match:
                log_om = LogOM().select_log_om_by_name(match.group(1))
                if log_om.enabled:
                    if log_om.internal and isinstance(log_om, LogOMMongoDB):
                        log_om.collection = self.ruleset
                    # Ensure variable names don't have a '-' character (and only those variables)
                    clean_log_condition = self.log_condition.replace(match.group(1), match.group(1).replace('-','_'))
                    log_oms[match.group(1).replace('-','_')] = LogOM.generate_conf(log_om, self.ruleset, frontend=self.name)
                    logger.info("Configuration of Log Forwarder named '{}' generated.".format(log_om.name))
        internal_ruleset = ""

        tpl = JinjaTemplate(clean_log_condition)
        return internal_ruleset + "\n\n" + tpl.render(Context(log_oms, autoescape=False)) + "\n"

    def render_log_condition_failure(self):
        """ Render log_forwarders' config from self.log_forwarders_parse_failure
            & Associate the correct template depending on parser
        :return  Str containing the rendered config
        """
        result = ""
        for log_forwarder in self.log_forwarders_parse_failure.all().only('id'):
            log_om = LogOM().select_log_om(log_forwarder.id)
            if log_om.enabled:
                result += LogOM.generate_conf(log_om, self.ruleset+"_garbage", frontend=self.name+"_garbage") + "\n"
        return result

    @property
    def api_rsyslog_port(self):
        return 20000+self.id

    def generate_api_rsyslog_conf(self):
        """ Render Rsyslog specific configuration
         containing listening port and address
         :return    String - Rsyslog configuration parameters
        """
        return "Address=\"{}\" Port=\"{}\"".format(JAIL_ADDRESSES['rsyslog']['inet'],
                                                   self.api_rsyslog_port)

    def generate_filebeat_conf(self):
        """ Generate filebeat configuration of this frontend
        """
        conf = self.to_template()
        if self.filebeat_listening_mode in ["udp", "tcp"]:
            conf['filebeat_config'] = conf['filebeat_config'].replace ("%ip%", JAIL_ADDRESSES['rsyslog'][conf['listeners'][0].network_address.family])
            conf['filebeat_config'] = conf['filebeat_config'].replace ("%port%", str(conf['listeners'][0].rsyslog_port))

        return conf['filebeat_config']

    def generate_rsyslog_conf(self):
        """ Generate rsyslog configuration of this frontend
        """
        # Import here to prevent populate reetrant issues
        from services.rsyslogd.rsyslog import JINJA_PATH as JINJA_RSYSLOG_PATH
        # The following var is only used by error, do not forget to adapt if needed
        template_name = "rsyslog_ruleset_{}/ruleset.conf".format(self.ruleset)
        try:
            jinja2_env = Environment(loader=FileSystemLoader(JINJA_RSYSLOG_PATH))
            template = jinja2_env.get_template(template_name)
            conf = self.to_template()
            conf['ruleset'] = self.ruleset
            conf['log_condition'] = self.render_log_condition() if self.enabled and self.enable_logging else ""
            conf['log_condition_failure'] = self.render_log_condition_failure() if self.enabled and self.enable_logging else ""
            conf['not_internal_forwarders'] = self.log_forwarders.exclude(internal=True)

            darwin_actions = []
            for darwin_filter in FilterPolicy.objects.filter(policy__in=self.darwin_policies.all(), enabled=True):
                if not darwin_filter.filter_type.is_launchable:
                    continue

                action = {
                    "filter_type": darwin_filter.filter_type.name,
                    "threshold": darwin_filter.threshold,
                    "enrichment_tags": ["darwin.{}".format(darwin_filter.filter_type.name)],
                    "calls": []
                }

                # if filter is buffered
                # - enrichment should be disabled
                # - socket should point to related buffer filter
                # - inputs should include buffer source
                if darwin_filter.buffering.exists():
                    # shouldn't raise, but exceptions are handled at the end of the function anyway
                    buffering = darwin_filter.buffering.get()
                    action['disable_enrichment'] = True
                    action['buffer_source'] = "{}_{}_{}".format(buffering.destination_filter.name, self.name, buffering.destination_filter.policy.id)
                    action['filter_socket'] = buffering.buffer_filter.socket_path
                else:
                    action['filter_socket'] = darwin_filter.socket_path

                if darwin_filter.mmdarwin_enabled and darwin_filter.mmdarwin_parameters:
                    call = {
                        "inputs": darwin_filter.mmdarwin_parameters,
                        "outputs": [p.replace('.', '!') for p in darwin_filter.mmdarwin_parameters if p[0] in ['!', '.']]
                    }
                    action['calls'].append(call)

                if darwin_filter.enrichment_tags:
                    action['enrichment_tags'].extend(darwin_filter.enrichment_tags)

                darwin_actions.append(action)

            return template.render({'frontend': conf,
                                    'node': Cluster.get_current_node(),
                                    'global_config': Cluster.get_global_config(),
                                    'darwin_actions': darwin_actions})
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
        except (DarwinBuffering.DoesNotExist, DarwinBuffering.MultipleObjectsReturned) as e:
            exception = ServiceJinjaError("Could not get the expected unique buffering from a darwin filter: '{}'".format(e.message), "rsyslog")
        # If there was an exception, raise a more general exception with the message and the traceback
        raise exception

    def get_log_socket(self):
        # FIXME : if not self.logs_enabled
        return

    def get_log_format(self):
        """ Return log format depending on frontend conf """
        log_format = "{ " \
                     "\\\"time\\\": \\\"%[date(0,us),regsub(\\\"(.*)([0-9]{6})\\$\\\",\\\"\\1.\\2\\\",i)]\\\", " \
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
                          ", \\\"http_request_cookies\\\": \\\"%[capture.req.hdr(1),json(ascii)]\\\"" \
                          ", \\\"http_request_body\\\": \\\"%[var(sess.body),json(ascii)]\\\"" \
                          ", \\\"http_request_content_type\\\": \\\"%[capture.req.hdr(3),json(ascii)]\\\"" \
                          ", \\\"http_request_host\\\": \\\"%[capture.req.hdr(4),json(ascii)]\\\""
        log_format += "}"
        # TODO: Verify                          minimum one listener uses https
        # If yes : Add \\\"ssl_ciphers\\\": \\\"%sslc\\\", \\\"ssl_version\\\": \\\"%sslv\\\"
        return log_format

    def get_nodes(self):
        """
        :return: Return node(s) where the frontend has been declared
        """
        result = set()
        if self.mode == "log" and self.listening_mode in ["file", "kafka", "redis"]:
            result = {self.node} if self.node else set(Node.objects.all())
        elif self.mode == "filebeat" and self.filebeat_listening_mode in ["file", "api"] :
            result = {self.node}
        elif self.mode == "log" and self.listening_mode == "api":
            result = set(Node.objects.all())
        else:
            result = set(Node.objects.filter(networkinterfacecard__networkaddress__listener__frontend=self.id))

        if None in result:
            result.remove(None)

        return result

    def reload_conf(self):
        """ Generate conf based on MongoDB data and save-it on concerned nodes
         :return  A set of the updated nodes or raise a ServiceError or SystemError
         """
        nodes = set()
        for node in self.get_nodes():
            api_res = node.api_request("services.haproxy.haproxy.build_conf", self.id)
            if not api_res.get('status'):
                logger.error(f"[FRONTEND] API error while trying to reload {self.name} conf : {api_res.get('message')}")
            nodes.add(node)

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

        elif self.filebeat_only_conf:
            nodes = self.get_nodes()

            for node in nodes:
                api_res = node.api_request("services.filebeat.filebeat.start_service")
                if not api_res.get('status'):
                    raise ServiceStartError("API request failure on node '{}'".format(node.name), "filebeat",
                                            traceback=api_res.get('message'))

            return "Start filebeat service asked on nodes {}".format(",".join([n.name for n in nodes]))

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

        """ Cannot stop Rsyslog / Filebeat only frontend """
        if self.rsyslog_only_conf:
            raise ServiceError("Cannot hot disable an Rsyslog only frontend.", "rsyslog", "disable frontend",
                               traceback="Please edit, disable and save the frontend.")
        elif self.filebeat_only_conf:
            raise ServiceError("Cannot hot disable a Filebeat only frontend.", "filebeat", "disable frontend",
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
        return (self.mode == "log" and (self.listening_mode in ("udp", "file", "api", "kafka", "redis")))

    @property
    def filebeat_only_conf(self):
        """ Check if this frontend has only filebeat configuration, not haproxy at all """
        return self.mode == "filebeat" and self.filebeat_listening_mode in ("udp", "file", "api")

    def has_tls(self):
        # Test self.pk to prevent M2M errors when object isn't saved in DB
        if self.pk:
            for listener in self.listener_set.all():
                if listener.is_tls:
                    return True
        return False


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
        null=True,
        default=[],
        on_delete=models.PROTECT
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
            'network_address_id': str(self.network_address.pk),
            'port': self.port,
            'frontend': self.frontend,
            'whitelist_ips': self.whitelist_ips,
            'tls_profiles': [tls.pk for tls in self.tls_profiles.all()],
            'max_src': self.max_src,
            'max_rate': self.max_rate,
            'addr_port': "{}:{}".format(self.network_address.ip, self.port),
            'is_tls': self.is_tls
        }

    @property
    def is_tls(self):
        return self.tls_profiles.count() > 0

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

    def get_nodes(self):
        return [nic.node for nic in self.network_address.nic.all()]


class FrontendReputationContext(models.Model):
    """  Intermediary class between Frontend and ReputationContext """
    frontend = models.ForeignKey(
        Frontend,
        null=True,
        on_delete=models.CASCADE
    )
    reputation_ctx = models.ForeignKey(
        ReputationContext,
        verbose_name=_("IOC Database"),
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
        help_text=_("Field name to predict with Rsyslog Database")
    )
    dst_field = models.TextField(
        default="",
        verbose_name=_("Destination field name"),
        help_text=_("Field name which will contains the searched value")
    )

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "frontend" in fields:
            result['frontend'] = str(result['frontend'])
        if not fields or "reputation_ctx" in fields:
            result['reputation_ctx'] = str(result['reputation_ctx'])
        return result


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
        current_acl_name = "{}{}".format(acl_name, str(uuid4()))
        acl_name_list.append(current_acl_name)
        acl_str = ""
        spaces = "    "

        if mode == "$or":
            for condition_tuple in condition_list:
                acl_str += "acl {} {}\n{}".format(current_acl_name, condition_tuple[0], spaces)
                current_acl_name = "{}{}".format(acl_name, str(uuid4()))
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
                current_acl_name = "{}{}".format(acl_name, str(uuid4()))
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
