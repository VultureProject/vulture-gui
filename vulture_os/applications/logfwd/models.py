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
__author__ = "Jérémie JOURDIN, Kevin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Log forwarder model classes'

# Django system imports
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.template import Context, Template
from django.utils.translation import gettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models

# Django project imports
from system.pki.models import X509Certificate, TLSProfile
from toolkit.network.network import get_proxy
from gui.utils.validators import SpoolDirectoryValidator
from pyfaup.faup import Faup

# Extern modules imports
from jinja2 import Environment, FileSystemLoader
from os.path import join as path_join
import pymongo
import hashlib

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


INPUT_TYPE = (
    ('imfile', 'File'),
    ('imuxsock', 'Unix Socket'),
)

ACTION_TYPE = (
    ('omelasticsearch', 'Elasticsearch'),
    ('omfile', 'Local File'),
    ('omfwd', 'Syslog'),
    ('omhiredis', 'Redis'),
    ('ommongodb', 'MongoDB'),
    ('omrelp', 'RELP'),
    ('omkafka', 'Kafka'),
    ('omsentinel', 'Sentinel'),
)

OMFWD_PROTOCOL = (
    ('tcp', 'TCP'),
    ('udp', 'UDP')
)

ROTATION_PERIOD_CHOICES = (
    ('daily', "Every day"),
    ('weekly', "Every week"),
    ('monthly', "Every month"),
    ('yearly', "Every year")
)

ZLIB_LEVEL_CHOICES = (
    (-1, "Balanced"),
    (0, "No compression"),
    (1, "Fastest compression"),
    (2, "Compression level 2"),
    (3, "Compression level 3"),
    (4, "Compression level 4"),
    (5, "Compression level 5"),
    (6, "Compression level 6"),
    (7, "Compression level 7"),
    (8, "Compression level 8"),
    (9, "Best compression"),
)

OMHIREDIS_MODE_CHOICES = (
    ('queue', "Queue/list mode, using lpush/rpush"),
    ('set', "Set/keys mode, using set/setex"),
    ('publish', "Channel mode, using publish"),
    ('stream', "Stream mode, using xadd"),
)

JINJA_PATH = path_join(settings.BASE_DIR, "applications/logfwd/config/")


class LogOM (models.Model):
    name = models.TextField(unique=True, blank=False, null=False,
                            default="Log Output Module", help_text=_("Name of the Log Output Module"))
    internal = models.BooleanField(default=False, help_text=_("Is this LogForwarder internal"))
    enabled = models.BooleanField(default=True)
    queue_size = models.PositiveIntegerField(
        default=10000,
        help_text=_("Size of the queue in nb of message"),
        verbose_name=_("Size of the queue in nb of message"),
        validators=[MinValueValidator(100)]
    )
    dequeue_size = models.PositiveIntegerField(
        default=300,
        help_text=_("Size of the batch to dequeue"),
        verbose_name=_("Size of the batch to dequeue"),
        validators=[MinValueValidator(1)]
    )
    queue_timeout_shutdown = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text=_("Time to wait for the queue to finish processing entries (in ms)"),
        verbose_name=_("Queue timeout shutdown (ms)"),
        validators=[MinValueValidator(1)]
    )
    max_workers = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text=_("Maximum workers created for the output"),
        verbose_name=_("Queue max workers"),
        validators=[MinValueValidator(1)]
    )
    new_worker_minimum_messages = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text=_("Number of messages in queue to start a new worker thread"),
        verbose_name=_("Minimum messages to start a new worker"),
        validators=[MinValueValidator(1)]
    )
    worker_timeout_shutdown = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text=_("Inactivity delay after which to stop a worker (in ms)"),
        verbose_name=_("Worker inactivity shutdown delay (ms)"),
        validators=[MinValueValidator(1)]
    )
    enable_retry = models.BooleanField(
        default=False,
        help_text=_("Enable retry when failure occurs"),
        verbose_name=_("Enable retry on failure")
    )
    enable_disk_assist = models.BooleanField(
        default=False,
        help_text=_("Enable disk-assisted queue on failure"),
        verbose_name=_("Enable disk queue on failure")
    )
    high_watermark = models.PositiveIntegerField(
        default=8000,
        null=False,
        help_text=_("Target of the high watermark"),
        verbose_name=_("High watermark target"),
        validators=[MinValueValidator(100)]
    )
    low_watermark = models.PositiveIntegerField(
        default=6000,
        null=False,
        help_text=_("Set the value of the low watermark"),
        verbose_name=_("Low watermark target"),
        validators=[MinValueValidator(100)]
        )
    max_file_size = models.IntegerField(
        default=256,
        null=False,
        help_text=_("Set the value of the queue in MB"),
        verbose_name=_("Max file size of the queue in MB"),
        validators=[MinValueValidator(1)]
    )
    max_disk_space = models.IntegerField(
        default=0,
        null=False,
        help_text=_("Limit the maximum disk space used by the queue in MB"),
        verbose_name=_("Max disk space used by the queue in MB (set to zero to disable)"),
        validators=[MinValueValidator(0)]
    )
    spool_directory = models.TextField(
        default="/var/tmp",
        null=False,
        required=False,
        validators=[SpoolDirectoryValidator()],
        help_text=_("Defines an existing folder to store queue files into"),
        verbose_name=_("Existing folder to store queue files to"),
    )

    send_as_raw = models.BooleanField(
        default=False,
        help_text=_("Send logs without any modification"),
        verbose_name=_("Send as raw")
    )

    def __unicode__(self):
        return f"{self.name} ({self.__class__.__name__})"

    def __str__(self):
        return f"{self.name}"

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def select_log_om(self, object_id, only=None):
        """ Return a Log Output by object id
        :param object_id: Id as string of object to retrieve
        :param only: List of attributes to only retrieve, None=all
        :return:
        """
        attrs = only or []
        for obj in self.__class__.__subclasses__():
            log_om = obj.objects.filter(pk=object_id).only(*attrs).first()
            if log_om:
                return log_om
        raise ObjectDoesNotExist()

    def select_log_om_by_name(self, name, only=None):
        """ Return a Log Output by name
        :param name: Name of object to retrieve
        :param only: List of attributes to only retrieve, None=all
        :return:
        """
        attrs = only or []
        for obj in self.__class__.__subclasses__():
            # Use filter because it does not raise
            # And .first to get object, else queryset is returned
            log_om = obj.objects.filter(name=name).only(*attrs).first()
            if log_om:
                return log_om
        raise ObjectDoesNotExist(f"Log Forwarder named '{name}' not found.")

    @classmethod
    def generate_conf(cls, log_om, rsyslog_template_name, **kwargs):
        jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
        template = jinja2_env.get_template(log_om.template)
        conf = log_om.to_template(**kwargs, ruleset=rsyslog_template_name)
        conf['out_template'] = rsyslog_template_name
        return template.render(conf)

    def generate_pre_conf(self, rsyslog_template_name, **kwargs):
        return ""

    def template_id(self):
        return hashlib.sha256(self.name.encode('utf-8')).hexdigest()

    def get_rsyslog_template(self):
        """ Return the rsyslog template used to interpret the filename
             or index name
             :return    config template line, as string
         """
        # Do NOT use that doc above in child overriden method
        if hasattr(self, 'logomelasticsearch'):
            subclass_obj = self.logomelasticsearch
        elif hasattr(self, 'logomfile'):
            subclass_obj = self.logomfile
        elif hasattr(self, 'logomfwd'):
            subclass_obj = self.logomfwd
        elif hasattr(self, 'logomhiredis'):
            subclass_obj = self.logomhiredis
        elif hasattr(self, 'logommongodb'):
            subclass_obj = self.logommongodb
        elif hasattr(self, 'logomrelp'):
            subclass_obj = self.logomrelp
        elif hasattr(self, 'logomkafka'):
            subclass_obj = self.logomkafka
        elif hasattr(self, 'logomsentinel'):
            subclass_obj = self.logomsentinel
        elif hasattr(self, "logom_ptr") and not isinstance(self.logom_ptr, LogOM):
            subclass_obj = self.logom_ptr
        else:
            raise Exception(f"Cannot find type of LogOM named '{self.name}' !")
        # Prevent infinite loop if subclass method does not exists
        if subclass_obj.get_rsyslog_template.__doc__ == LogOM.get_rsyslog_template.__doc__:
            return ""
        return subclass_obj.get_rsyslog_template()

    def to_html_template(self):
        return self.select_log_om(self.id).to_html_template()

    def to_dict(self, fields=None):
        return model_to_dict(self, fields=fields)

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        return {
            'id': str(self.id),
            'output_name': f"{self.name}_{kwargs.get('frontend', '')}",
            'name': self.name,
            'template_id': self.template_id(),
            'send_as_raw': self.send_as_raw,
            'queue_size': self.queue_size,
            'dequeue_size': self.dequeue_size,
            'queue_timeout_shutdown': self.queue_timeout_shutdown,
            'max_workers': self.max_workers,
            'new_worker_minimum_messages': self.new_worker_minimum_messages,
            'worker_timeout_shutdown': self.worker_timeout_shutdown,
            'enable_retry': self.enable_retry,
            'enable_disk_assist': self.enable_disk_assist,
            'high_watermark': self.high_watermark,
            'low_watermark': self.low_watermark,
            'max_file_size': self.max_file_size,
            'max_disk_space': self.max_disk_space,
            'spool_directory': self.spool_directory,
        }


class LogOMFile(LogOM):
    file = models.TextField(null=False)
    flush_interval = models.IntegerField(default=1, null=False)
    async_writing = models.BooleanField(default=True)
    retention_time = models.PositiveIntegerField(default=30, validators=[MinValueValidator(1)])
    rotation_period = models.TextField(default=ROTATION_PERIOD_CHOICES[0][0], choices=ROTATION_PERIOD_CHOICES)

    def template_id(self, ruleset=""):
        return hashlib.sha256(ruleset.encode('utf-8') + self.name.encode('utf-8')).hexdigest()

    @property
    def template(self):
        return 'om_file.tpl'

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "id" in fields:
            result['id'] = str(result['id'])
        if not fields or "type" in fields:
            result['type'] = 'File'

        return result

    def to_html_template(self):
        """ Returns only needed attributes for display in GUI """
        return {
            'id': str(self.id),
            'internal': self.internal,
            'enabled': self.enabled,
            'name': self.name,
            'type': 'File',
            'output': self.file
        }

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        template = super().to_template(**kwargs)
        template.update({
            'file': self.file,
            'flush_interval': self.flush_interval,
            'async_writing': "on" if self.async_writing else "off",
            'template_id': self.template_id(kwargs.get('ruleset', "")),
            'type': 'File',
            'output': self.file
        })
        return template

    def get_used_parsers(self):
        """ Return parsers of frontends which uses this log_forwarder """
        result = set()
        from services.frontend.models import Frontend
        # FIXME : Add .distinct("ruleset") when implemented in djongo
        for f in Frontend.objects.filter(log_forwarders=self.pk).only('ruleset'):
            result.add(f.ruleset)
        # Retrieve log_forwarders_parse_failure for log listeners
        for f in Frontend.objects.filter(mode__in=["log", "filebeat"], log_forwarders_parse_failure=self.pk).only('ruleset'):
            result.add(f.ruleset+"_garbage")
        return result

    def get_rsyslog_filenames(self):
        """ Render filenames based on filename attribute, depending on frontend used """
        tpl = Template(self.file)
        result = set()
        for ruleset in self.get_used_parsers():
            result.add(tpl.render(Context({'ruleset': ruleset})))
        return result

    def render_file_template(self, ruleset):
        tpl = Template(self.file)
        return f"""template(name=\"{self.template_id(ruleset=ruleset)}\" type=\"string\"
                    string=\"{tpl.render(Context({'ruleset': ruleset}))}\")\n"""

    def get_rsyslog_template(self):
        res = ""
        tpl = Template(self.file)

        for ruleset in self.get_used_parsers():
            res += f"template(name=\"{self.template_id(ruleset=ruleset)}\" type=\"string\" string=\"{tpl.render(Context({'ruleset': ruleset}))}\")\n"
        return res

    def __str__(self):
        return f"{self.name} ({self.__class__.__name__})"


class LogOMRELP(LogOM):
    target = models.TextField(null=False, default="1.2.3.4")
    port = models.IntegerField(null=False, default=514)
    tls_enabled = models.BooleanField(
        default=True,
        help_text=_("If set to on, the RELP connection will be encrypted by TLS.")
    )
    x509_certificate = models.ForeignKey(
        X509Certificate,
        on_delete=models.CASCADE,
        help_text=_("X509Certificate object to use."),
        default=None,
        null=True
    )

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "type" in fields:
            result['type'] = 'RELP'
        if self.tls_enabled:
            result['tls_enabled'] = True
        if self.x509_certificate:
            result['x509_certificate'] = self.x509_certificate.id
        return result

    def to_html_template(self):
        """ Returns only needed attributes for display in GUI """
        return {
            'id': str(self.id),
            'internal': self.internal,
            'enabled': self.enabled,
            'name': self.name,
            'type': 'RELP',
            'output': self.target + ':' + str(self.port)
        }

    @property
    def template(self):
        return 'om_relp.tpl'

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        template = super().to_template(**kwargs)
        template.update({
            'target': self.target,
            'port': self.port,
            'type': 'RELP',
            'tls': self.tls_enabled,
            'output': self.target + ':' + str(self.port)
        })
        if self.tls_enabled and self.x509_certificate:
            template['ssl_ca'] = self.x509_certificate.get_base_filename() + ".chain"
            template['ssl_cert'] = self.x509_certificate.get_base_filename() + ".crt"
            template['ssl_key'] = self.x509_certificate.get_base_filename() + ".key"
        return template


class LogOMHIREDIS(LogOM):
    target = models.TextField(null=False, default="1.2.3.4")
    port = models.IntegerField(null=False, default=6379)
    mode = models.TextField(
        default=OMHIREDIS_MODE_CHOICES[0][0],
        choices=OMHIREDIS_MODE_CHOICES,
        help_text=_("Specify how Rsyslog insert logs in Redis"),
        verbose_name=_("Redis insertion mode"),
    )
    key = models.TextField(null=False, default="MyKey")
    dynamic_key = models.BooleanField(default=False)
    pwd = models.TextField(blank=True, default=None)
    use_rpush = models.BooleanField(
        default=False,
        blank=True,
        help_text=_("Use RPUSH instead of LPUSH in list mode"),
        verbose_name=_("Use RPUSH"),
    )
    expire_key = models.PositiveIntegerField(
        default=0,
        blank=True,
        help_text=_("Use SETEX instead of SET in key mode with an expiration in seconds"),
        verbose_name=_("Expiration of the key (s)"),
    )
    stream_outfield = models.TextField(
        default="msg",
        validators=[
            RegexValidator(
                regex=r"^\S+$",
                message="Value shouldn't have any spaces"
            )
        ],
        blank=True,
        help_text=_("Set the name of the index field to use when inserting log, in stream mode"),
        verbose_name=_("Index name of the log"),
    )
    stream_capacitylimit = models.PositiveIntegerField(
        default=0,
        blank=True,
        help_text=_("Set a stream capacity limit, if set to more than 0 (zero), oldest values in the stream will be evicted to stay under the max value"),
        verbose_name=_("Maximum stream size"),
    )
    tls_profile = models.ForeignKey(
        TLSProfile,
        on_delete=models.RESTRICT,
        default=None,
        null=True,
        blank=True,
        help_text=_("TLSProfile object to use."),
        verbose_name=_("Use a TLS Profile")
    )

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "type" in fields:
            result['type'] = 'Redis'
        if not fields or "key" in fields:
            result['key'] = result['key'] or ""
        if not fields or "pwd" in fields:
            result['pwd'] = result['pwd'] or ""

        return result

    def to_html_template(self):
        """ Returns only needed attributes for display in GUI """
        return {
            'id': str(self.id),
            'internal': self.internal,
            'enabled': self.enabled,
            'name': self.name,
            'type': 'Redis',
            'output': f"{self.target}:{self.port} ({'dynamic ' if self.dynamic_key else ''}key = {self.key})"
        }

    @property
    def template(self):
        return 'om_hiredis.tpl'

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        template = super().to_template(**kwargs)
        tpl = Template(self.key)
        key = tpl.render(Context({'ruleset': kwargs.get('ruleset')}))
        template.update({
            'target': self.target,
            'port': self.port,
            'mode': self.mode,
            'key': key,
            'dynamic_key': self.dynamic_key,
            'pwd': self.pwd,
            'use_rpush': self.use_rpush,
            'expire_key': self.expire_key,
            'stream_outfield': self.stream_outfield,
            'stream_capacitylimit': self.stream_capacitylimit,
            'type': 'Redis',
            'output': f"{self.target}:{self.port} (key = {self.key})"
        })
        if self.tls_profile:
            template['use_tls'] = "on"
            if self.tls_profile.ca_cert and self.tls_profile.verify_client != "none":
                template['ca_cert_bundle'] = self.tls_profile.ca_cert.bundle_filename
            if self.tls_profile.x509_certificate:
                template['client_cert'] = self.tls_profile.x509_certificate.get_base_filename() + ".crt"
                template['client_key'] = self.tls_profile.x509_certificate.get_base_filename() + ".key"
        return template

    def get_rsyslog_template(self):
        from services.frontend.models import Frontend
        if self.dynamic_key and Frontend.objects.filter(log_forwarders=self.pk).exists() | Frontend.objects.filter(log_forwarders_parse_failure=self.pk).exists():
            return f"template(name=\"{self.template_id()}\" type=\"string\" string=\"{self.key}\")"
        return ""


class LogOMFWD(LogOM):
    target = models.TextField(null=False, default="1.2.3.4")
    port = models.IntegerField(
        null=False,
        default=514,
        validators=[MinValueValidator(1), MaxValueValidator(65535)],
        help_text=_("Port on which to send logs to <target>.")
    )
    protocol = models.TextField(null=False, choices=OMFWD_PROTOCOL, default="tcp")
    zip_level = models.PositiveIntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(9)],
        help_text=_("Compression level for messages.")
    )

    ratelimit_interval = models.PositiveIntegerField(null=True, blank=True)
    ratelimit_burst = models.PositiveIntegerField(null=True, blank=True)

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "type" in fields:
            result['type'] = 'Syslog'
        return result

    def to_html_template(self):
        """ Returns only needed attributes for display in GUI """
        return {
            'id': str(self.id),
            'internal': self.internal,
            'enabled': self.enabled,
            'name': self.name,
            'type': 'Syslog',
            'output': self.target + ':' + str(self.port) + ' ({})'.format(self.protocol)
        }

    @property
    def template(self):
        return 'om_fwd.tpl'

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        template = super().to_template(**kwargs)
        template.update({
            'target': self.target,
            'port': self.port,
            'protocol': self.protocol,
            'type': 'Syslog',
            'zip_level': self.zip_level,
            'ratelimit_interval': self.ratelimit_interval,
            'ratelimit_burst': self.ratelimit_burst,
            'output': self.target + ':' + str(self.port) + ' ({})'.format(self.protocol)
        })
        return template

    def get_rsyslog_template(self):
        return ""


class LogOMElasticSearch(LogOM):
    servers = models.TextField(null=False, default='["https://els-1:9200", "https://els-2:9200"]')
    es8_compatibility = models.BooleanField(
        default=False,
        help_text=_("Enable Elasticsearch/OpenSearch 8 compatibility"),
        verbose_name=_("Elasticsearch/OpenSearch 8 compatibility")
    )
    data_stream_mode = models.BooleanField(
        default=False,
        help_text=_("Enable Elasticsearch datastreams support"),
        verbose_name=_("Enable Elasticsearch datastreams support")
    )
    retry_on_els_failures = models.BooleanField(
        default=False,
        help_text=_("Let Rsyslog's Elasticsearch module handle and retry insertion failure"),
        verbose_name=_("Handle failures and retries on ELS insertion")
    )
    index_pattern = models.TextField(unique=True, null=False, default='mylog-%$!timestamp:1:10%')
    uid = models.TextField(null=True, blank=True, default=None)
    pwd = models.TextField(null=True, blank=True, default=None)
    tls_profile = models.ForeignKey(
        TLSProfile,
        on_delete=models.CASCADE,
        default=None,
        null=True,
        blank=True,
        help_text=_("TLSProfile object to use."),
        verbose_name=_("Use a TLS Profile")
    )

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "type" in fields:
            result['type'] = 'Elasticsearch'
        if not fields or "uid" in fields:
            result['uid'] = result['uid'] or ""
        if not fields or "pwd" in fields:
            result['pwd'] = result['pwd'] or ""
        return result

    def to_html_template(self):
        """ Returns only needed attributes for display in GUI """
        return {
            'id': str(self.id),
            'name': self.name,
            'internal': self.internal,
            'enabled': self.enabled,
            'type': 'Elasticsearch',
            'output': self.servers + ' (index = {})'.format(self.index_pattern)
        }

    @property
    def template(self):
        return 'om_elasticsearch.tpl'

    @property
    def pre_template(self):
        return 'om_elasticsearch_pre.tpl'

    def generate_pre_conf(self, rsyslog_template_name, **kwargs):
        jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
        try:
            template = jinja2_env.get_template(self.pre_template)
            conf = self.to_template(**kwargs)
            conf['out_template'] = rsyslog_template_name
            rendered = template.render(conf)
        except Exception as e:
            logger.exception(e)
            rendered = ""
        return rendered

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        template = super().to_template(**kwargs)
        template.update({
            'servers': self.servers,
            'es8_compatibility': self.es8_compatibility,
            'data_stream_mode': self.data_stream_mode,
            'retry_on_els_failures': self.retry_on_els_failures,
            'index_pattern': self.index_pattern,
            'uid': self.uid,
            'pwd': self.pwd,
            'template_id': self.template_id(),
            'mapping_id': self.mapping_id,
            'type': 'Elasticsearch',
            'output': self.servers + ' (index = {})'.format(self.index_pattern)
        })
        if self.tls_profile:
            if self.tls_profile.ca_cert:
                template['ssl_ca'] = self.tls_profile.ca_cert.ca_filename()
            if self.tls_profile.x509_certificate:
                template['ssl_cert'] = self.tls_profile.x509_certificate.get_base_filename() + ".crt"
                template['ssl_key'] = self.tls_profile.x509_certificate.get_base_filename() + ".key"
        return template

    def get_rsyslog_filenames(self):
        """ Render filenames based on filename attribute, depending on frontend used """
        result = set()
        from services.frontend.models import Frontend
        for f in Frontend.objects.filter(log_forwarders=self.pk).only('name') | Frontend.objects.filter(mode="log", log_forwarders_parse_failure=self.pk).only('name'):
            result.add(f"/var/log/internal/{self.name}_{f.name}_error.log")
        return result

    def get_rsyslog_template(self):
        from services.frontend.models import Frontend
        if Frontend.objects.filter(log_forwarders=self.pk).exists() | Frontend.objects.filter(log_forwarders_parse_failure=self.pk).exists():
            return f"template(name=\"{self.template_id()}\" type=\"string\" string=\"{self.index_pattern}\")"
        return ""

    @property
    def mapping_id(self):
        return 'mapping_'+self.template_id()


class LogOMMongoDB(LogOM):
    db = models.TextField(unique=True, null=False, default='MyDatabase')
    collection = models.TextField(unique=True, null=False, default='MyLogs')
    uristr = models.TextField(null=False, default='mongodb://1.2.3.4:9091/?replicaset=Vulture&ssl=true')
    x509_certificate = models.ForeignKey(
        X509Certificate,
        on_delete=models.CASCADE,
        default=None,
        null=True,
        help_text=_("X509Certificate object to use.")
    )

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "type" in fields:
            result['type'] = 'MongoDB'
        return result

    def to_html_template(self):
        """ Returns only needed attributes for display in GUI """
        return {
            'id': str(self.id),
            'internal': self.internal,
            'enabled': self.enabled,
            'name': self.name,
            'type': 'MongoDB',
            'output': self.uristr + ' (db = {})'.format(self.db)
        }

    @property
    def template(self):
        return 'om_mongodb.tpl'

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        template = super().to_template(**kwargs)
        template.update({
            'uristr': self.uristr,
            'db': self.db,
            'collection': self.collection,
            'mapping': self.mapping,
            'type': 'MongoDB',
            'output': self.uristr + ' (db = {}, col = {})'.format(self.db, self.collection)
        })
        if self.x509_certificate:
            template['ssl_ca'] = self.x509_certificate.get_base_filename() + ".chain"
            template['ssl_cert'] = self.x509_certificate.get_base_filename() + ".pem"
        return template

    def get_connection(self):
        host_configuration = pymongo.uri_parser.parse_uri(self.uristr)
        print(host_configuration)

        host = ['mongodb://{}:{}'.format(h[0], h[1]) for h in host_configuration['nodelist']]

        if len(host) == 1:
            host = host[0]

        kwargs = {
            'host': host
        }

        if self.x509_certificate:
            ## SSL

            kwargs.update({
                'ssl': True,
                "tlsCertificateKeyFile": self.x509_certificate.get_base_filename() + ".pem"
            })

        return pymongo.MongoClient(**kwargs)

    @property
    def mapping(self):
        # FIXME: Dynamically build mongodb mapping based on Input's Log Format
        return "property(name=\"$!app_name\")"


class LogOMKAFKA(LogOM):
    broker = models.TextField(blank=True, default='["1.2.3.4:9092"]')
    topic = models.TextField()
    key = models.TextField(blank=True)
    dynaKey = models.BooleanField(default=False)
    dynaTopic = models.BooleanField(default=False)
    topicConfParam = models.JSONField(
        default=list(),
        blank=True)
    confParam = models.JSONField(
        default=list(),
        blank=True)
    partitions_useFixed = models.IntegerField(blank=True)
    partitions_auto = models.BooleanField(default=False)

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "type" in fields:
            result['type'] = 'Kafka'

        return result

    def to_html_template(self):
        """ Returns only needed attributes for display in GUI """
        return {
            'id': str(self.id),
            'internal': self.internal,
            'enabled': self.enabled,
            'name': self.name,
            'type': 'Kafka',
            'output': self.broker + ' (topic = {})'.format(self.topic)
        }

    @property
    def template(self):
        return 'om_kafka.tpl'

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        template = super().to_template(**kwargs)
        tpl = Template(self.key)
        key = tpl.render(Context({'ruleset': kwargs.get('ruleset')}))
        template.update({
            'broker': self.broker,
            'topic': self.topic,
            'key': key,
            'dynaKey': self.dynaKey,
            'dynaTopic': self.dynaTopic,
            'template_id': self.template_id(),
            'template_topic': self.template_topic(),
            'partitions_useFixed': self.partitions_useFixed,
            'partitions_auto': self.partitions_auto,
            'confParam': self.confParam,
            'topicConfParam': self.topicConfParam,
            'type': 'Kafka',
            'mode': "queue",
            'output': self.broker + ' (topic = {})'.format(self.topic),
        })
        return template

    def template_topic(self):
        return hashlib.sha256(self.topic.encode('utf-8')).hexdigest()

    def get_rsyslog_template(self):
        from services.frontend.models import Frontend
        template = ""
        if Frontend.objects.filter(log_forwarders=self.pk).exists() | Frontend.objects.filter(log_forwarders_parse_failure=self.pk).exists():
            if self.dynaKey:
                template += f"template(name=\"{self.template_id()}\" type=\"string\" string=\"{self.key}\")\n"
            if self.dynaTopic:
                template += f"template(name=\"{self.template_topic()}\" type=\"string\" string=\"{self.topic}\")\n"
        return template


class LogOMSentinel(LogOM):
    tenant_id = models.TextField(
        null=False,
        blank=False,
        default=None,
        help_text=_("the ID of the tenant to use, will be included in the URI"),
        verbose_name=_("Tenant ID"),
        validators=[RegexValidator(
                regex=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
                message="The tenant ID format is not a valid"
        )]

        )
    client_id = models.TextField(
        null=False,
        blank=False,
        default=None,
        help_text=_("the client ID for OpenID application authentication"),
        verbose_name=_("Client ID"),
        validators=[RegexValidator(
                regex=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
                message="The client ID format is not a valid"
        )]
    )
    client_secret = models.TextField(
        null=False,
        blank=False,
        default=None,
        help_text=_("the client secret for OpenID application authentication"),
        verbose_name=_("Client Secret")
    )
    dcr = models.TextField(
        null=False,
        blank=False,
        default=None,
        help_text=_("The Sentinel Data Collection Rule to use while ingesting data"),
        verbose_name=_("Data Collection Rule"),
        validators=[RegexValidator(
                regex=r"^dcr-[0-9a-f]{32}$",
                message="The DCR ID is not valid (expected format : dcr-cbb3586665ebdbc6ebadd796e3ba5bcf)."
        )]
    )
    dce = models.TextField(
        null=False,
        blank=False,
        default=None,
        help_text=_("The Sentinel Data Collection Endpoint to use for ingestion"),
        verbose_name=_("Data Collection Endpoint")
    )
    stream_name = models.TextField(
        null=False,
        blank=False,
        default=None,
        help_text=_("The Sentinel stream on which to insert the logs"),
        verbose_name=_("Stream Name")
    )
    scope = models.URLField(
        default='https://monitor.azure.com/.default',
        help_text=_("the OpenID scope to use. For Sentinel ingestion API, corresponds to the Azure Environment"),
        verbose_name=_("Scope")
    )
    batch_maxsize = models.PositiveIntegerField(
        default=100,
        help_text=_("Controls how many messages should be sent at most in one request"),
        verbose_name=_("Batch max size"),
    )
    batch_maxbytes = models.PositiveIntegerField(
        default=10485760,
        help_text=_("Defines the maximum size (in bytes) of one request"),
        verbose_name=_("Batch max bytes"),
    )
    compression_level = models.IntegerField(
        default=ZLIB_LEVEL_CHOICES[0][0],
        choices=ZLIB_LEVEL_CHOICES,
        validators=[
            MinValueValidator(-1, message="Minimum allowed value is -1 (Balanced)."),
            MaxValueValidator(9, message="Maximum allowed value is 9. (Best compression)")
        ],
        help_text=_("Activates and defines the level of compression of requests"),
        verbose_name=_("Compression level"),
    )
    tls_profile = models.ForeignKey(
        TLSProfile,
        on_delete=models.RESTRICT,
        default=None,
        null=True,
        blank=True,
        help_text=_("TLSProfile object to use."),
        verbose_name=_("Use a TLS Profile")
    )
    use_proxy = models.BooleanField(
        default=False,
        help_text=_("Use a proxy to connect to the OMSentinel APIs"),
        verbose_name=_("Use Proxy")
    )
    custom_proxy = models.TextField(
        null=True,
        blank=True,
        default=None,
        help_text=_("Custom proxy to use (will use system proxy if not set)"),
        verbose_name=_("Custom Proxy")
    )

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "type" in fields:
            result['type'] = 'Sentinel'
        return result

    def to_html_template(self):
        """ Returns only needed attributes for display in GUI """
        return {
            'id': str(self.pk),
            'name': self.name,
            'internal': self.internal,
            'enabled': self.enabled,
            'type': 'Sentinel',
            'output': f"https://{self.dce}/dataCollectionRules/{self.dcr}/streams/{self.stream_name}?api-version=2023-01-01",
        }

    @property
    def template(self):
        return 'om_sentinel.tpl'

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        proxy = self.get_parsed_proxy()
        template = super().to_template(**kwargs)
        template.update({
            'tenant_id': self.tenant_id,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'dcr': self.dcr,
            'dce': self.dce,
            'stream_name': self.stream_name,
            'scope': self.scope,
            'batch_maxsize': self.batch_maxsize,
            'batch_maxbytes': self.batch_maxbytes,
            'compression_level': self.compression_level,
            'use_proxy': self.use_proxy,
            'proxy_host': proxy['proxy_host'],
            'proxy_port': proxy['proxy_port'],
            'type': 'Sentinel',
            'output': f"https://{self.dce}/dataCollectionRules/{self.dcr}/streams/{self.stream_name}?api-version=2023-01-01",
        })
        if self.tls_profile:
            if self.tls_profile.ca_cert:
                template['ssl_ca'] = self.tls_profile.ca_cert.ca_filename()
            if self.tls_profile.x509_certificate:
                template['ssl_cert'] = self.tls_profile.x509_certificate.get_base_filename() + ".crt"
                template['ssl_key'] = self.tls_profile.x509_certificate.get_base_filename() + ".key"
        return template

    def get_rsyslog_filenames(self):
        """ Render filenames based on filename attribute, depending on frontend used """
        result = set()
        for f_name in self.frontend_set.values_list("name", flat=True) | self.frontend_failure_set.values_list("name", flat=True):
            result.add(f"/var/log/internal/{self.name}_{f_name}_error.log")
        return result

    @property
    def mapping_id(self):
        return 'mapping_'+self.template_id()

    def get_parsed_proxy(self):
        if self.use_proxy:
            faup_parser = Faup()
            if self.custom_proxy:
                raw_proxy = self.custom_proxy
            else:
                raw_proxy = get_proxy()
                if raw_proxy:
                    raw_proxy = raw_proxy.get('https')

            if raw_proxy:
                faup_parser.decode(raw_proxy)
                if not faup_parser.get_scheme():
                    return {'proxy_host': f'{faup_parser.get_host()}', 'proxy_port': faup_parser.get_port() }
                else:
                    return {'proxy_host': f'{faup_parser.get_scheme()}://{faup_parser.get_host()}', 'proxy_port': faup_parser.get_port() }

        return {'proxy_host': '', 'proxy_port': ''}
