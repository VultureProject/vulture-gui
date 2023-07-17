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
from django.core.validators import MinValueValidator, MaxValueValidator
from django.template import Context, Template
from django.utils.translation import gettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models

# Django project imports
from system.pki.models import X509Certificate

# Extern modules imports
from jinja2 import Environment, FileSystemLoader
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

CONF_PATH = "/usr/local/etc/rsyslog.d/10-applications.conf"
JINJA_PATH = "/home/vlt-os/vulture_os/applications/logfwd/config/"


class LogOM (models.Model):

    name = models.TextField(unique=True, blank=False, null=False,
                            default="Log Output Module", help_text=_("Name of the Log Output Module"))
    internal = models.BooleanField(default=False, help_text=_("Is this LogForwarder internal"))
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
        null=True,
        help_text=_("Target of the high watermark"),
        verbose_name=_("High watermark target"),
        validators=[MinValueValidator(100)]
    )
    low_watermark = models.PositiveIntegerField(
        default=6000,
        null=True,
        help_text=_("Set the value of the low watermark"),
        verbose_name=_("Low watermark target"),
        validators=[MinValueValidator(100)]
        )
    max_file_size = models.IntegerField(
        default=256,
        null=True,
        help_text=_("Set the value of the queue in MB"),
        verbose_name=_("Max file size of the queue in MB"),
        validators=[MinValueValidator(1)]
    )
    max_disk_space = models.IntegerField(
        default=1024,
        null=True,
        help_text=_("Limit the maximum disk space used by the queue in MB"),
        verbose_name=_("Max disk space used by the queue in MB"),
        validators=[MinValueValidator(1)]
    )

    def __unicode__(self):
        return "{} ({})".format(self.name, self.__class__.__name__)

    def __str__(self):
        return "{}".format(self.name)

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
        raise ObjectDoesNotExist("Log Forwarder named '{}' not found.".format(name))

    @classmethod
    def generate_conf(cls, log_om, rsyslog_template_name, **kwargs):
        jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
        template = jinja2_env.get_template(log_om.template)
        conf = log_om.to_template(**kwargs, ruleset=rsyslog_template_name)
        conf['out_template'] = rsyslog_template_name
        return template.render(conf)

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
        elif hasattr(self, "logom_ptr") and type(self.logom_ptr) != LogOM:
            subclass_obj = self.logom_ptr
        else:
            raise Exception("Cannot find type of LogOM named '{}' !".format(self.name))
        # Prevent infinite loop if subclass method does not exists
        if subclass_obj.get_rsyslog_template.__doc__ == LogOM.get_rsyslog_template.__doc__:
            return ""
        return subclass_obj.get_rsyslog_template()

    def to_html_template(self):
        return self.select_log_om(self.id).to_html_template()

    def to_dict(self, fields=None):
        return model_to_dict(self, fields=fields)


class LogOMFile(LogOM):

    file = models.TextField(null=False)
    flush_interval = models.IntegerField(default=1, null=False)
    async_writing = models.BooleanField(default=True)
    enabled = models.BooleanField(default=True)
    stock_as_raw = models.BooleanField(default=True)
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
            'name': self.name,
            'type': 'File',
            'output': self.file
        }

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        return {
            'id': str(self.id),
            'output_name': "{}_{}".format(self.name, kwargs.get('frontend', "")),
            'name': self.name,
            'file': self.file,
            'flush_interval': self.flush_interval,
            'async_writing': "on" if self.async_writing else "off",
            'template_id': self.template_id(kwargs.get('ruleset', "")),
            'type': 'File',
            'output': self.file,
            'stock_as_raw': self.stock_as_raw,
            'queue_size': self.queue_size,
            'dequeue_size': self.dequeue_size,
            'enable_retry': self.enable_retry,
            'enable_disk_assist': self.enable_disk_assist,
            'high_watermark': self.high_watermark,
            'low_watermark': self.low_watermark,
            'max_file_size': self.max_file_size,
            'max_disk_space': self.max_disk_space
        }

    def get_used_parsers(self):
        """ Return parsers of frontends which uses this log_forwarder """
        result = set()
        from services.frontend.models import Frontend
        # FIXME : Add .distinct("ruleset") when implemented in djongo
        for f in Frontend.objects.filter(log_forwarders=self.id).only('ruleset'):
            result.add(f.ruleset)
        # Retrieve log_forwarders_parse_failure for log listeners
        for f in Frontend.objects.filter(mode="log", log_forwarders_parse_failure=self.id).only('ruleset'):
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
        return "template(name=\"{}\" type=\"string\" string=\"{}\") \n" \
               .format(self.template_id(ruleset=ruleset), tpl.render(Context({'ruleset': ruleset})))

    def get_rsyslog_template(self):
        res = ""
        tpl = Template(self.file)

        for ruleset in self.get_used_parsers():
            res += "template(name=\"{}\" type=\"string\" string=\"{}\") \n" \
                .format(self.template_id(ruleset=ruleset), tpl.render(Context({'ruleset': ruleset})))
        return res

    def __str__(self):
        return "{} ({})".format(self.name, self.__class__.__name__)


class LogOMRELP(LogOM):
    target = models.TextField(null=False, default="1.2.3.4")
    port = models.IntegerField(null=False, default=514)
    enabled = models.BooleanField(default=True)
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
            'name': self.name,
            'type': 'RELP',
            'output': self.target + ':' + str(self.port)
        }

    @property
    def template(self):
        return 'om_relp.tpl'

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        result = {
            'id': str(self.id),
            'name': self.name,
            'output_name': "{}_{}".format(self.name, kwargs.get('frontend', "")),
            'target': self.target,
            'port': self.port,
            'type': 'RELP',
            'tls': self.tls_enabled,
            'queue_size': self.queue_size,
            'dequeue_size': self.dequeue_size,
            'enable_retry': self.enable_retry,
            'enable_disk_assist': self.enable_disk_assist,
            'high_watermark': self.high_watermark,
            'low_watermark': self.low_watermark,
            'max_file_size': self.max_file_size,
            'max_disk_space': self.max_disk_space,
            'output': self.target + ':' + str(self.port)
        }
        if self.tls_enabled and self.x509_certificate:
            result['ssl_ca'] = self.x509_certificate.get_base_filename() + ".chain"
            result['ssl_cert'] = self.x509_certificate.get_base_filename() + ".crt"
            result['ssl_key'] = self.x509_certificate.get_base_filename() + ".key"
        return result


class LogOMHIREDIS(LogOM):
    target = models.TextField(null=False, default="1.2.3.4")
    port = models.IntegerField(null=False, default=6379)
    key = models.TextField(null=False, default="MyKey")
    pwd = models.TextField(blank=True, default=None)
    enabled = models.BooleanField(default=True)

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
            'name': self.name,
            'type': 'Redis',
            'output': self.target + ':' + str(self.port) + ' (key = {})'.format(self.key)
        }

    @property
    def template(self):
        return 'om_hiredis.tpl'

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        tpl = Template(self.key)
        key = tpl.render(Context({'ruleset': kwargs.get('ruleset')}))
        return {
            'id': str(self.id),
            'name': self.name,
            'output_name': "{}_{}".format(self.name, kwargs.get('frontend', "")),
            'target': self.target,
            'port': self.port,
            'key': key,
            'pwd': self.pwd,
            'type': 'Redis',
            'queue_size': self.queue_size,
            'dequeue_size': self.dequeue_size,
            'enable_retry': self.enable_retry,
            'enable_disk_assist': self.enable_disk_assist,
            'high_watermark': self.high_watermark,
            'low_watermark': self.low_watermark,
            'max_file_size': self.max_file_size,
            'max_disk_space': self.max_disk_space,
            'output': self.target + ':' + str(self.port) + ' (key = {})'.format(self.key),
            'mode': "queue"
        }

    def get_rsyslog_template(self):
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
    enabled = models.BooleanField(default=True)
    zip_level = models.PositiveIntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(9)],
        help_text=_("Compression level for messages.")
    )
    send_as_raw = models.BooleanField(default=False)

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
            'name': self.name,
            'type': 'Syslog',
            'output': self.target + ':' + str(self.port) + ' ({})'.format(self.protocol)
        }

    @property
    def template(self):
        return 'om_fwd.tpl'

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        return {
            'id': str(self.id),
            'name': self.name,
            'output_name': "{}_{}".format(self.name, kwargs.get('frontend', "")),
            'target': self.target,
            'port': self.port,
            'protocol': self.protocol,
            'type': 'Syslog',
            'zip_level': self.zip_level,
            'send_as_raw': self.send_as_raw,
            'queue_size': self.queue_size,
            'dequeue_size': self.dequeue_size,
            'enable_retry': self.enable_retry,
            'enable_disk_assist': self.enable_disk_assist,
            'high_watermark': self.high_watermark,
            'low_watermark': self.low_watermark,
            'max_file_size': self.max_file_size,
            'max_disk_space': self.max_disk_space,
            'ratelimit_interval': self.ratelimit_interval,
            'ratelimit_burst': self.ratelimit_burst,
            'output': self.target + ':' + str(self.port) + ' ({})'.format(self.protocol)
        }

    def get_rsyslog_template(self):
        return ""


class LogOMElasticSearch(LogOM):
    enabled = models.BooleanField(default=True)
    servers = models.TextField(null=False, default='["https://els-1:9200", "https://els-2:9200"]')
    es8_compatibility = models.BooleanField(
        default=False,
        help_text=_("Enable Elasticsearch/OpenSearch 8 compatibility"),
        verbose_name=_("Elasticsearch/OpenSearch 8 compatibility")
    )
    index_pattern = models.TextField(unique=True, null=False, default='mylog-%$!timestamp:1:10%')
    uid = models.TextField(null=True, blank=True, default=None)
    pwd = models.TextField(null=True, blank=True, default=None)
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
            'type': 'Elasticsearch',
            'output': self.servers + ' (index = {})'.format(self.index_pattern)
        }

    @property
    def template(self):
        return 'om_elasticsearch.tpl'

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        result = {
            'id': str(self.id),
            'name': self.name,
            'output_name': "{}_{}".format(self.name, kwargs.get('frontend', "")),
            'servers': self.servers,
            'es8_compatibility': self.es8_compatibility,
            'index_pattern': self.index_pattern,
            'uid': self.uid,
            'pwd': self.pwd,
            'template_id': self.template_id(),
            'mapping_id': self.mapping_id,
            'type': 'Elasticsearch',
            'queue_size': self.queue_size,
            'dequeue_size': self.dequeue_size,
            'enable_retry': self.enable_retry,
            'enable_disk_assist': self.enable_disk_assist,
            'high_watermark': self.high_watermark,
            'low_watermark': self.low_watermark,
            'max_file_size': self.max_file_size,
            'max_disk_space': self.max_disk_space,
            'output': self.servers + ' (index = {})'.format(self.index_pattern)
        }
        if self.x509_certificate:
            result['ssl_ca'] = self.x509_certificate.ca_filename()
            if not self.x509_certificate.is_ca_cert():
                result['ssl_cert'] = self.x509_certificate.get_base_filename() + ".crt"
                result['ssl_key'] = self.x509_certificate.get_base_filename() + ".key"
        return result

    def get_rsyslog_template(self):
        return "template(name=\"{}\" type=\"string\" string=\"{}\")".format(self.template_id(), self.index_pattern)

    def template_id(self):
        return hashlib.sha256(self.name.encode('utf-8')).hexdigest()

    @property
    def mapping_id(self):
        return 'mapping_'+self.template_id()


class LogOMMongoDB(LogOM):
    db = models.TextField(unique=True, null=False, default='MyDatabase')
    collection = models.TextField(unique=True, null=False, default='MyLogs')
    uristr = models.TextField(null=False, default='mongodb://1.2.3.4:9091/?replicaset=Vulture&ssl=true')
    enabled = models.BooleanField(default=True)
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
            'name': self.name,
            'type': 'MongoDB',
            'output': self.uristr + ' (db = {})'.format(self.db)
        }

    @property
    def template(self):
        return 'om_mongodb.tpl'

    def to_template(self, **kwargs):
        """  returns the attributes of the class """
        result = {
            'id': str(self.id),
            'name': self.name,
            'output_name': "{}_{}".format(self.name, kwargs.get('frontend', "")),
            'uristr': self.uristr,
            'db': self.db,
            'collection': self.collection,
            'mapping': self.mapping,
            'internal': self.internal,
            'type': 'MongoDB',
            'queue_size': self.queue_size,
            'dequeue_size': self.dequeue_size,
            'enable_retry': self.enable_retry,
            'enable_disk_assist': self.enable_disk_assist,
            'high_watermark': self.high_watermark,
            'low_watermark': self.low_watermark,
            'max_file_size': self.max_file_size,
            'max_disk_space': self.max_disk_space,
            'output': self.uristr + ' (db = {}, col = {})'.format(self.db, self.collection)
        }
        if self.x509_certificate:
            result['ssl_ca'] = self.x509_certificate.get_base_filename() + ".chain"
            result['ssl_cert'] = self.x509_certificate.get_base_filename() + ".pem"
        return result

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
                "ssl_certfile": self.x509_certificate.get_base_filename() + ".pem"
            })

        return pymongo.MongoClient(**kwargs)

    def template_id(self):
        return hashlib.sha256(self.name.encode('utf-8')).hexdigest()

    @property
    def mapping(self):
        # FIXME: Dynamically build mongodb mapping based on Input's Log Format
        return "property(name=\"$!app_name\")"
