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
from applications.reputation_ctx.models import ReputationContext
from daemons.reconcile import REDIS_LIST as DARWIN_REDIS_ALERT_LIST
from daemons.reconcile import REDIS_CHANNEL as DARWIN_REDIS_ALERT_CHANNEL
from darwin.inspection.models import InspectionPolicy

# External modules imports
from glob import glob as file_glob

JINJA_PATH = "/home/vlt-os/vulture_os/darwin/log_viewer/config/"


SOCKETS_PATH = "/var/sockets/darwin"
FILTERS_PATH = "/home/darwin/filters"
CONF_PATH = "/home/darwin/conf/"
TEMPLATE_OWNER = "darwin:vlt-web"
TEMPLATE_PERMS = "644"

DGA_MODELS_PATH = CONF_PATH + 'fdga/'

DARWIN_LOGLEVEL_CHOICES = (
    ('CRITICAL', 'Critical'),
    ('ERROR', 'Error'),
    ('WARNING', 'Warning'),
    ('NOTICE', 'Notice'),
    ('INFO', 'Informational'),
    ('DEBUG', 'Debug')
)

DARWIN_OUTPUT_CHOICES = (
    ('NONE', 'Do not send any data to next filter'),
    ('LOG', 'Send filters alerts to next filter'),
    ('RAW', 'Send initial body to next filter'),
    ('PARSED', 'Send parsed body to next filter'),
)

HOSTLOOKUP_VALID_DB_TYPES = [
    "ipv4_netset",
    "ipv6_netset",
    "domain",
    "lookup"
]


def validate_yara_file(policy_id):
    try:
        inspection_policy = InspectionPolicy.objects.get(pk=policy_id)
    except InspectionPolicy.DoesNotExist:
        raise ValidationError(_("yara policy %(value)s not found"), params={'value': policy_id})

    return inspection_policy.get_full_filename()


def validate_content_inspection_config(config):
    yara_scan_type = config.get('yaraScanType', None)
    stream_store_folder = config.get('streamStoreFolder', None)
    yara_rule_file = config.get('yaraRuleFile', None)
    yara_scan_max_size = config.get('yaraScanMaxSize', None)
    max_connections = config.get('maxConnections', None)
    max_memory_usage = config.get('maxMemoryUsage', None)

    if not yara_scan_type and not stream_store_folder:
        raise ValidationError({'config': _("configuration should at least define 'yaraScanType' or 'streamStoreFolder'")})
    if yara_scan_type and not yara_rule_file:
        raise ValidationError({'config': _("configuration should define 'yaraRuleFile' when 'yaraScanType' is set")})

    if yara_scan_type and not isinstance(yara_scan_type, str):
        raise ValidationError({'yaraScanType': _("'yaraScanType' should be a string")})
    if yara_scan_type and yara_scan_type not in ['stream', 'packet']:
        raise ValidationError({'yaraScanType': _("'yaraScanType' should be either 'stream' or 'packet'")})
    if stream_store_folder and not isinstance(stream_store_folder, str):
        raise ValidationError({'streamStoreFolder': _("'streamStoreFolder' should be a string")})
    if yara_rule_file:
        if not isinstance(yara_rule_file, int):
            raise ValidationError({'yaraRuleFile': _("'yaraRuleFile' should be an ID to an Inspection Policy")})
        else:
            config['yaraRuleFile'] = validate_yara_file(yara_rule_file)
    if yara_scan_max_size and (not isinstance(yara_scan_max_size, int) or yara_scan_max_size < 0):
        raise ValidationError({'yaraScanMaxSize': _("'yaraScanMaxSize' should be a positive integer")})
    if max_connections and (not isinstance(max_connections, int) or max_connections < 0):
        raise ValidationError({'maxConnections': _("'maxConnections' should be a positive integer")})
    if max_memory_usage and (not isinstance(max_memory_usage, int) or max_memory_usage < 0):
        raise ValidationError({'maxMemoryusage': _("'maxMemoryUsage' should be a positive integer")})


def validate_connection_config(config):
    redis_socket_path = config.get('redis_socket_path')
    if not redis_socket_path:
        raise ValidationError({'config': _("configuration misses a 'redis_socket_path' field")})

    if not isinstance(redis_socket_path, str):
        raise ValidationError({'redis_socket_path': _("'redis_socket_path' should be a string")})


def validate_dga_config(config):
    token_map_path = config.get("token_map_path", None)
    model_path = config.get("model_path", None)

    if not token_map_path or not model_path:
        raise ValidationError({'config': _("configuration should contain at least 'token_map_path' and 'model_path' parameters")})

    if token_map_path and not isinstance(token_map_path, str):
        raise ValidationError({'token_map_path': _("'token_map_path' should be a string")})
    if model_path and not isinstance(model_path, str):
        raise ValidationError({'model_path': _("'model_path' should be a string")})

    full_model_path = file_glob(DGA_MODELS_PATH + model_path)
    full_token_map_path = file_glob(DGA_MODELS_PATH + token_map_path)

    if not full_model_path:
        raise ValidationError({'model_path': _("The model file '{}' is not valid".format(model_path))})
    else:
        config['model_path'] = full_model_path[0]

    if not full_token_map_path:
        raise ValidationError({'token_map_path': _("The token map file '{}' is not valid".format(token_map_path))})
    else:
        config['token_map_path'] = full_token_map_path[0]


def validate_hostlookup_config(config):
    reputation_id = config.get('database', None)
    db_type = config.get('db_type', None)

    if not reputation_id:
        raise ValidationError({'config': _("configuration should contain at least the 'database' parameter")})

    if not isinstance(reputation_id, int):
        raise ValidationError({'database': _("'database' should be a Reputation Context ID")})

    try:
        reputation_context = ReputationContext.objects.get(pk=reputation_id)
        if reputation_context.db_type not in HOSTLOOKUP_VALID_DB_TYPES:
            raise ValidationError({'database': _("database ID {} does not have a valid db_type, correct types are {}".format(reputation_id, HOSTLOOKUP_VALID_DB_TYPES))})
        config['database'] = reputation_context.absolute_filename
        if reputation_context.db_type == "lookup":
            config['db_type'] = 'rsyslog'
        else:
            config['db_type'] = 'text'
    except ReputationContext.DoesNotExist:
        raise ValidationError({'database': _("'database' with ID {} not found".format(reputation_id))})

    if db_type and not db_type in ['text', 'json', 'rsyslog']:
        raise ValidationError({'db_type': _("'db_type' should be either 'text', 'json' or 'rsyslog'")})


def validate_yara_config(config):
    rule_file_list = config.get('rule_file_list', None)

    if rule_file_list is None:
        raise ValidationError({'config': _("configuration should contain at least the 'rule_file_list' parameter")})

    # If rule_file_list is not a list or is empty
    if not isinstance(rule_file_list, list) or not rule_file_list:
        raise ValidationError({'rule_file_list': _("'rule_file_list' should be a non-empty list")})

    file_paths = []
    for object_id in rule_file_list:
        if not isinstance(object_id, int):
            raise ValidationError({'rule_file_list': _("'{}' is not a yara policy ID".format(object_id))})
        file_paths.append(validate_yara_file(object_id))
    config['rule_file_list'] = file_paths


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

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "is_internal": self.is_internal,
        }

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
    name = models.TextField(
        unique=True,
        default="Custom Policy",
        help_text="The friendly name of your policy (should be unique)")

    description = models.TextField(
        blank=True,
        help_text="A description for your policy")

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
        on_delete=models.CASCADE,
        help_text=_("The type of darwin filter this instance is"),
    )

    """ Associated policy """
    policy = models.ForeignKey(
        DarwinPolicy,
        on_delete=models.CASCADE,
        help_text=_("The policy associated with this filter instance"),
    )

    """ Is the Filter activated? """
    enabled = models.BooleanField(
        default=False,
        help_text=_("Wheter this filter should be started"),
        )

    """ Number of threads """
    nb_thread = models.PositiveIntegerField(
        default=5,
        help_text=_("The number of concurrent threads to run for this instance (going above 10 is rarely a good idea)"),
        )

    """ Level of logging (not alerts) """
    log_level = models.TextField(
        default=DARWIN_LOGLEVEL_CHOICES[2][0], choices=DARWIN_LOGLEVEL_CHOICES,
        help_text=_("The logging level for this particular instance (closer to DEBUG means more info, but also more disk space taken and less performances overall)"),
        )

    """ Alert detection thresold """
    threshold = models.PositiveIntegerField(
        default=80,
        help_text=_("The threshold above which the filter should trigger an alert: filters return a certitude between 0 and 100 (inclusive), this tells the filter to raise an alert if the certitude for the data analysed is above or equal to this threshold"),
        )

    """ Does the filter has a custom Rsyslog configuration? """
    mmdarwin_enabled = models.BooleanField(
        default=False,
        help_text=_("!!! ADVANCED FEATURE !!! Activates a custom call to Darwin from Rsyslog"),
        )

    mmdarwin_parameters = models.ListField(
        default=[],
        blank=True,
        help_text=_("!!! ADVANCED FEATURE !!! the list of rsyslog fields to take when executing the custom call to Darwin (syntax is Rsyslog "),
        )

    weight = models.FloatField(
        default=1.0,
        validators=[MinValueValidator(0.0)],
        help_text=_("The weight of this filter when calculating mean certitude during multiple calls to different filters with the same data"),
        )

    is_internal = models.BooleanField(
        default=False,
        help_text=_("Whether this filter is a system one"),
        )

    tag = models.TextField(
        default="",
        blank=True,
        max_length=32,
        help_text=_("A simple tag to differentiate easily a particular filter from others"),
        )

    """ Status of filter for each nodes """
    status = models.DictField(
        default={},
        help_text=_("The statuses of the filter on each cluster's node"),
        )

    """ The number of cache entries (not memory size) """
    cache_size = models.PositiveIntegerField(
        default=0,
        help_text=_("The number of cache entries the filter can have to keep previous results"),
        verbose_name=_("Cache size")
    )

    """Output format to send to next filter """
    output = models.TextField(
        default=DARWIN_OUTPUT_CHOICES[0][0],
        choices=DARWIN_OUTPUT_CHOICES,
        help_text=_("The type of output this filter should send to the next one (when defined, see 'next_filter'). This should be 'NONE', unless you know what you're doing"),
    )
    """ Next filter in workflow """
    next_filter = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        default=None,
        on_delete=models.SET_NULL,
        help_text=_("A potential filter to send results and/or data to continue analysis"),
    )

    conf_path = models.TextField(
        blank=True,
        help_text=_("The fullpath to the configuration file of this filter"),
        )

    config = models.DictField(
        default={},
        blank=True,
        help_text=_("A dictionary containing all specific parameters of this filter"),
    )

    def clean(self):
        self.config['redis_socket_path'] = "/var/sockets/redis/redis.sock"
        self.config['alert_redis_list_name'] = "darwin_alerts"
        self.config['alert_redis_channel_name'] = "darwin.alerts"
        self.config['log_file_path'] = "/var/log/darwin/alerts.log"

        conf_validator = DARWIN_FILTER_CONFIG_VALIDATORS.get(self.filter.name, None)

        if conf_validator:
            conf_validator(self.config)


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
