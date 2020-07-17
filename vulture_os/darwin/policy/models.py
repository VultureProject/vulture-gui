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

__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Darwin model'

# Django system imports
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.validators import MinValueValidator, RegexValidator
from django.utils.translation import ugettext_lazy as _
from djongo import models

# Django project imports
from daemons.reconcile import REDIS_LIST as DARWIN_REDIS_ALERT_LIST
from daemons.reconcile import REDIS_CHANNEL as DARWIN_REDIS_ALERT_CHANNEL

JINJA_PATH = "/home/vlt-os/vulture_os/darwin/log_viewer/config/"


SOCKETS_PATH = "/var/sockets/darwin"
FILTERS_PATH = "/home/darwin/filters"
CONF_PATH = "/home/darwin/conf/"
TEMPLATE_OWNER = "darwin:vlt-web"
TEMPLATE_PERMS = "644"


DARWIN_LOGLEVEL_CHOICES = (
    ('ERROR', 'Error'),
    ('WARNING', 'Warning'),
    ('INFO', 'Informational'),
    ('DEBUG', 'Debug')
)

DARWIN_OUTPUT_CHOICES = (
    ('NONE', 'Do not send any data to next filter'),
    ('LOG', 'Send filters alerts to next filter'),
    ('RAW', 'Send initial body to next filter'),
    ('PARSED', 'Send parsed body to next filter'),
)


def validate_content_inspection_config(config):
    yara_scan_type = config.get('yaraScanType', None)
    stream_store_folder = config.get('streamStoreFolder', None)
    yara_rule_file = config.get('yaraRuleFile', None)
    yara_scan_max_size = config.get('yaraScanMaxSize', None)
    max_connections = config.get('maxConnections', None)
    max_memory_usage = config.get('maxMemoryUsage', None)

    if not yara_scan_type and not stream_store_folder:
        raise ValidationError(_("configuration should at least define 'yaraScanType' or 'streamStoreFolder'"))
    if yara_scan_type and not yara_rule_file:
        raise ValidationError(_("configuration should define 'yaraRuleFile' when 'yaraScanType' is set"))

    if yara_scan_type and not isinstance(yara_scan_type, str):
        raise ValidationError(_("'yaraScanType' should be a string"))
    if yara_scan_type and yara_scan_type not in ['stream', 'packet']:
        raise ValidationError(_("'yaraScanType' should be either 'stream' or 'packet'"))
    if stream_store_folder and not isinstance(stream_store_folder, str):
        raise ValidationError(_("'streamStoreFolder' should be a string"))
    if yara_rule_file and not isinstance(yara_rule_file, str):
        raise ValidationError(_("'yaraRuleFile' should be a string"))
    if yara_scan_max_size and (not isinstance(yara_scan_max_size, int) or yara_scan_max_size < 0):
        raise ValidationError(_("'yaraScanMaxSize' should be a positive integer"))
    if max_connections and (not isinstance(max_connections, int) or max_connections < 0):
        raise ValidationError(_("'maxConnections' should be a positive integer"))
    if max_memory_usage and (not isinstance(max_memory_usage, int) or max_memory_usage < 0):
        raise ValidationError(_("'maxMemoryUsage' should be a positive integer"))


def validate_connection_config(config):
    redis_socket_path = config.get('redis_socket_path')
    if not redis_socket_path:
        raise ValidationError(_("configuration misses a 'redis_socket_path' field"))

    if not isinstance(redis_socket_path, str):
        raise ValidationError(_("'redis_socket_path' should be a string"))


def validate_dga_config(config):
    token_map_path = config.get("token_map_path", None)
    model_path = config.get("model_path", None)

    if not token_map_path or not model_path:
        raise ValidationError(_("configuration should contain at least 'token_map_path' and 'model_path' parameters"))

    if token_map_path and not isinstance(token_map_path, str):
        raise ValidationError(_("'token_map_path' should be a string"))
    if model_path and not isinstance(model_path, str):
        raise ValidationError(_("'model_path' should be a string"))

def validate_hostlookup_config(config):
    database = config.get('database', None)
    db_type = config.get('db_type', None)

    if not database:
        raise ValidationError(_("configuration should contain at least the 'database' parameter"))

    if db_type and not db_type in ['text', 'json', 'rsyslog']:
        raise ValidationError(_("'db_type' should be either 'text', 'json' or 'rsyslog'"))

def validate_yara_config(config):
    rule_file_list = config.get('rule_file_list', None)

    if rule_file_list is None:
        raise ValidationError(_("configuration should contain at least the 'rule_file_list' parameter"))

    # If rule_file_list is not a list or is empty
    if not isinstance(rule_file_list, list) or not rule_file_list:
        raise ValidationError(_("'rule_file_list' should be a non-empty list"))


DARWIN_FILTER_CONFIG_VALIDATORS = {
    'connection': validate_connection_config,
    'content_inspection': validate_content_inspection_config,
    'dga': validate_dga_config,
    'hostlookup': validate_hostlookup_config,
    'yara': validate_yara_config,
}

class DarwinFilter(models.Model):
    name = models.TextField(unique=True)
    description = models.TextField()
    is_internal = models.BooleanField(default=False)
    """ conf_path directive in Darwin filter conf
     for example the MMDB database """

    def __str__(self):
        return self.name

    @property
    def exec_path(self):
        return "{}/darwin_{}".format(FILTERS_PATH, self.name)

    @staticmethod
    def is_launchable():
        return False

    @staticmethod
    def str_attrs():
        return ['name']


class DarwinPolicy(models.Model):
    name = models.TextField(unique=True, default="Custom Policy")
    description = models.TextField(blank=True)

    def to_dict(self):
        return_data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "filters": []
        }

        for filt in self.filterpolicy_set.all():
            return_data['filters'].append(filt.to_dict())

        return return_data

    def to_template(self):
        """  returns the attributes of the class """
        return {
            'id': str(self.id),
            'name': self.name,
        }

    def to_html_template(self):
        """ Returns needed attributes for html rendering """
        return_data = {
            'id': str(self.id),
            'name': self.name,
            'filters': [],
            'status': {}
        }
        try:
            return_data['filters'] = [str(f) for f in self.filterpolicy_set.filter(enabled=True).only(*FilterPolicy.str_attrs())]
            return_data['status'] = {f.filter.name: f.status for f in self.filterpolicy_set.all().only('status', 'filter')}
        except ObjectDoesNotExist:
            pass

        return return_data

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def __str__(self):
        return self.name

    @property
    def decision_filter(self):
        return "decision_{}".format(self.id)


class FilterPolicy(models.Model):
    """ Associated filter template """
    filter = models.ForeignKey(
        DarwinFilter,
        on_delete=models.CASCADE
    )

    """ Associated policy """
    policy = models.ForeignKey(
        DarwinPolicy,
        on_delete=models.CASCADE
    )

    """ Is the Filter activated? """
    enabled = models.BooleanField(default=False)

    """ Number of threads """
    nb_thread = models.PositiveIntegerField(default=5)

    """ Level of logging (not alerts) """
    log_level = models.TextField(default=DARWIN_LOGLEVEL_CHOICES[1][0], choices=DARWIN_LOGLEVEL_CHOICES)

    """ Alert detection thresold """
    threshold = models.PositiveIntegerField(default=80)

    """ Does the filter has a custom Rsyslog configuration? """
    mmdarwin_enabled = models.BooleanField(default=False)
    mmdarwin_parameters = models.ListField(default=[], blank=True)
    weight = models.FloatField(default=1.0, validators=[MinValueValidator(0.0)])
    is_internal = models.BooleanField(default=False)
    tag = models.TextField(
        default="",
        blank=True,
        max_length=32)

    """ Status of filter for each nodes """
    status = models.DictField(default={})

    """ The number of cache entries (not memory size) """
    cache_size = models.PositiveIntegerField(
        default=0,
        help_text=_("The cache size to use for caching darwin requests."),
        verbose_name=_("Cache size")
    )

    """Output format to send to next filter """
    output = models.TextField(
        default=DARWIN_OUTPUT_CHOICES[0][0],
        choices=DARWIN_OUTPUT_CHOICES
    )
    """ Next filter in workflow """
    next_filter = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        default=None,
        on_delete=models.SET_NULL
    )

    conf_path = models.TextField(blank=True)
    config = models.DictField(
        default={
            "redis_socket_path": "/var/sockets/redis/redis.sock",
            "alert_redis_list_name": DARWIN_REDIS_ALERT_LIST,
            "alert_redis_channel_name": DARWIN_REDIS_ALERT_CHANNEL,
            "log_file_path": "/var/log/darwin/alerts.log"
        },
        blank=True
    )

    def save(self, *args, **kwargs):
        # Save object to get an id, then set conf_path and save again
        if not self.pk:
            super().save(*args, **kwargs)
            self.conf_path = "{darwin_path}f{filter_name}/f{filter_name}_{filter_id}.conf".format(darwin_path=CONF_PATH, filter_name=self.filter.name, filter_id=self.pk)
        super().save(*args, **kwargs)

    @property
    def name(self):
        """ Method used in Darwin conf to define a filter """
        return "{}_{}".format(self.filter.name, self.id)

    def __str__(self):
        return "[{}] {}".format(self.policy.name, self.filter.name)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.filter.name,
            "policy": self.policy.id,
            "enabled": self.enabled,
            "nb_thread": self.nb_thread,
            "log_level": self.log_level,
            "threshold": self.threshold,
            "mmdarwin_enabled": self.mmdarwin_enabled,
            "mmdarwin_parameters": self.mmdarwin_parameters,
            "weight": self.weight,
            "is_internal": self.is_internal,
            "tag": self.tag,
            "status": self.status,
            "cache_size": self.cache_size,
            "output": self.output,
            "next_filter": self.next_filter,
            "config": self.config
        }

    @staticmethod
    def str_attrs():
        return ['filter', 'conf_path', 'nb_thread', 'log_level', 'config']

    @property
    def socket_path(self):
        return "{}/{}_{}.sock".format(SOCKETS_PATH, self.filter.name, self.id)

    def mmdarwin_parameters_rsyslog_str(self):
        return str(self.mmdarwin_parameters).replace("\'", "\"")
