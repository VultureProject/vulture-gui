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
from django.conf import settings
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
from json import dumps as json_dumps

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

JINJA_PATH = "/home/vlt-os/vulture_os/darwin/log_viewer/config/"


SOCKETS_PATH = "/var/sockets/darwin"
FILTERS_PATH = "/home/darwin/filters"
CONF_PATH = "/home/darwin/conf/"
TEMPLATE_OWNER = "darwin:vlt-web"
TEMPLATE_PERMS = "644"

REDIS_SOCKET_PATH = "/var/sockets/redis/redis.sock"
ALERTS_REDIS_LIST_NAME = "darwin_alerts"
ALERTS_REDIS_CHANNEL_NAME = "darwin.alerts"
ALERTS_LOG_FILEPATH = "/var/log/darwin/alerts.log"

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
    "lookup",
    "google",
]


def validate_mmdarwin_parameters(mmdarwin_parameters):
    if not isinstance(mmdarwin_parameters, list):
        raise ValidationError(_("should be a list of strings"))

    for field in mmdarwin_parameters:
        if not isinstance(field, str):
            raise ValidationError(_("fields should be strings"))


def validate_anomaly_config(config):
    cleaned_config = {}
    return cleaned_config


def validate_connection_config(config):
    cleaned_config = {}
    redis_expire = config.get('redis_expire', None)

    # redis_expire validation
    if redis_expire is not None:
        if not isinstance(redis_expire, int) or not redis_expire > 0:
            raise ValidationError({'redis_expire': _("'redis_expire' should be a positive integer")})
        else:
            cleaned_config['redis_expire'] = redis_expire

    return cleaned_config


def validate_content_inspection_config(config):
    cleaned_config = {}

    yara_scan_type = config.get('yara_scan_type', None)
    yara_policy_id = config.get('yara_policy_id', None)
    yara_scan_max_size = config.get('yara_scan_max_size', None)
    max_connections = config.get('max_connections', None)
    max_memory_usage = config.get('max_memory_usage', None)

    # Mandatory parameters
    if not yara_scan_type:
        raise ValidationError({'config': _("configuration should define 'yara_scan_type'")})
    if not yara_policy_id:
        raise ValidationError({'config': _("configuration should define 'yara_policy_id'")})

    # yaraScanType validation
    if not isinstance(yara_scan_type, str):
        raise ValidationError({'yara_scan_type': _("should be a string")})
    if yara_scan_type not in ['stream', 'packet']:
        raise ValidationError({'yara_scan_type': _("should be either 'stream' or 'packet'")})
    else:
        cleaned_config['yara_scan_type'] = yara_scan_type

    # yaraRuleFile validation
    if not isinstance(yara_policy_id, int):
        raise ValidationError({'yara_policy_id': _("should be an integer")})
    if not InspectionPolicy.objects.filter(pk=yara_policy_id).exists():
        raise ValidationError({'yara_policy_id': _("yara policy {} not found".format(yara_policy_id))})
    else:
        cleaned_config['yara_policy_id'] = yara_policy_id

    # yaraScanMaxSize validation
    if yara_scan_max_size is not None:
        if not isinstance(yara_scan_max_size, int) or not yara_scan_max_size > 0:
            raise ValidationError({'yara_scan_max_size': _("should be a positive integer")})
        else:
            cleaned_config['yara_scan_max_size'] = yara_scan_max_size

    # maxConnections validation
    if max_connections is not None:
        if not isinstance(max_connections, int) or not max_connections > 0:
            raise ValidationError({'max_connections': _("should be a positive integer")})
        else:
            cleaned_config['max_connections'] = max_connections

    # maxMemoryUsage validation
    if max_memory_usage is not None:
        if not isinstance(max_memory_usage, int) or not max_memory_usage > 0:
            raise ValidationError({'max_memory_usage': _("should be a positive integer")})
        else:
            cleaned_config['max_memory_usage'] = max_memory_usage

    return cleaned_config


def validate_dga_config(config):
    cleaned_config = {}

    max_tokens = config.get("max_tokens", None)

    # token_map validation
    cleaned_config['token_map'] = "fdga_tokens.csv"

    # model validation
    cleaned_config['model'] = "fdga.pb"

    # max_tokens validation
    if max_tokens is not None:
        if not isinstance(max_tokens, int) or not max_tokens > 0:
            raise ValidationError({'max_tokens': _("should be a positive integer")})
        else:
            cleaned_config['max_tokens'] = max_tokens

    return cleaned_config


def validate_hostlookup_config(config):
    cleaned_config = {}

    reputation_ctx_id = config.get('reputation_ctx_id', None)

    if not reputation_ctx_id:
        raise ValidationError({'config': _("configuration should contain at least the 'reputation_ctx_id' parameter")})

    # reputation_ctx_id validation
    if not isinstance(reputation_ctx_id, int):
        raise ValidationError({'reputation_ctx_id': _("should be an integer")})
    try:
        reputation_context = ReputationContext.objects.get(pk=reputation_ctx_id)
        if reputation_context.db_type not in HOSTLOOKUP_VALID_DB_TYPES:
            raise ValidationError({'reputation_ctx_id': _("reputation context {} does not have a valid db_type, correct types are {}".format(reputation_ctx_id, HOSTLOOKUP_VALID_DB_TYPES))})
        if reputation_context.db_type == "lookup":
            db_type = 'rsyslog'
        else:
            db_type = 'text'
        cleaned_config['reputation_ctx_id'] = reputation_ctx_id
        cleaned_config['db_type'] = db_type
    except ReputationContext.DoesNotExist:
        raise ValidationError({'reputation_ctx_id': _("ID {} is not a valid reputation context".format(reputation_ctx_id))})

    return cleaned_config


def validate_sofa_config(config):
    cleaned_config = {}
    return cleaned_config


def validate_tanomaly_config(config):
    cleaned_config = {}
    return cleaned_config


def validate_yara_config(config):
    cleaned_config = {}

    yara_policies_id = config.get('yara_policies_id', None)
    fastmode = config.get('fastmode', None)
    timeout = config.get('timeout', None)

    if yara_policies_id is None:
        raise ValidationError({'config': _("configuration should contain at least the 'yara_policies_id' parameter")})

    # yara_policies_id validation
    if not isinstance(yara_policies_id, list) or yara_policies_id == []:
        raise ValidationError({'yara_policies_id': _("should be a non-empty list")})
    for yara_policy_id in yara_policies_id:
        if not isinstance(yara_policy_id, int):
            raise ValidationError({'yara_policies_id': _("values should be integers")})
        if not InspectionPolicy.objects.filter(pk=yara_policy_id).exists():
            raise ValidationError({'yara_policies_id': _("{} is not a valid inspection policy ID".format(yara_policy_id))})
    cleaned_config["yara_policies_id"] = yara_policies_id

    # fastmode validation
    if fastmode is not None:
        if not isinstance(fastmode, bool):
            raise ValidationError({'fastmode': _("should be a boolean")})
        else:
            cleaned_config['fastmode'] = fastmode

    # timeout validation
    if timeout is not None:
        if not isinstance(timeout, int) or timeout < 0:
            raise ValidationError({'timeout': _("should be a positive integer or zero")})
        else:
            cleaned_config['timeout'] = timeout

    return cleaned_config



DARWIN_FILTER_CONFIG_VALIDATORS = {
    'anomaly': validate_anomaly_config,
    'connection': validate_connection_config,
    'content_inspection': validate_content_inspection_config,
    'dga': validate_dga_config,
    'hostlookup': validate_hostlookup_config,
    'sofa': validate_sofa_config,
    'tanomaly': validate_tanomaly_config,
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
            return_data['status'] = [{f.filter.name: f.status} for f in self.filterpolicy_set.all().only('status', 'filter')]
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
        validators=[validate_mmdarwin_parameters])

    weight = models.FloatField(
        default=1.0,
        validators=[MinValueValidator(0.0)],
        help_text=_("The weight of this filter when calculating mean certitude during multiple calls to different filters with the same data"),
        )

    is_internal = models.BooleanField(
        default=False,
        help_text=_("Whether this filter is a system one"),
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
        # get the validator associated to the filter (there should be one defined in the list, even when it has no configuration parameters)
        conf_validator = DARWIN_FILTER_CONFIG_VALIDATORS.get(self.filter.name)
        self.config = conf_validator(self.config)

        self.config['redis_socket_path'] = REDIS_SOCKET_PATH
        self.config['alert_redis_list_name'] = ALERTS_REDIS_LIST_NAME
        self.config['alert_redis_channel_name'] = ALERTS_REDIS_CHANNEL_NAME
        self.config['log_file_path'] = ALERTS_LOG_FILEPATH


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
            "status": self.status,
            "cache_size": self.cache_size,
            "output": self.output,
            "next_filter": self.next_filter,
            "config": self.config
        }

    def conf_to_json(self):
        """
        Function to clean and validate filter configuration before translating it to string and writing it in the configuration file
        """
        json_conf = {}

        # Those fields were already validated and don't need any modification, let them be in the resulting configuration as-is
        PASS_THROUGH_FIELDS = ['redis_expire', 'max_tokens', 'fastmode', 'timeout', 'redis_socket_path', 'alert_redis_list_name', 'alert_redis_channel_name', 'log_file_path']

        # Resolve yara_policy_id into yaraRuleFile for fcontent_inspection
        yara_policy_id = self.config.get('yara_policy_id', None)
        if yara_policy_id:
            try:
                yara_policy = InspectionPolicy.objects.get(pk=yara_policy_id)
                json_conf['yaraRuleFile'] = yara_policy.get_full_filename()
            except InspectionPolicy.DoesNotExist:
                logger.error("FilterPolicy::conf_to_json:: Could not find InspectionPolicy with id {}".format(yara_policy_id))

        # Resolve yara_policies_id into rule_file_list for fyara
        yara_policies_id = self.config.get('yara_policies_id', None)
        if yara_policies_id:
            json_conf['rule_file_list'] = []
            for yara_policy_id in yara_policies_id:
                try:
                    yara_policy = InspectionPolicy.objects.get(pk=yara_policy_id)
                    json_conf['rule_file_list'].append(yara_policy.get_full_filename())
                except InspectionPolicy.DoesNotExist:
                    logger.error("FilterPolicy::conf_to_json:: Could not find InspectionPolicy with id {}".format(yara_policy_id))

        # Resolve reputation_ctx_id into database for fhostlookup
        reputation_ctx_id = self.config.get('reputation_ctx_id', None)
        if reputation_ctx_id:
            try:
                database = ReputationContext.objects.get(pk=reputation_ctx_id)
                json_conf['database'] = database.absolute_filename
            except ReputationContet.DoesNotExist:
                logger.error("FilterPolicy::conf_to_json:: Could not find ReputationContext with id {}".format(reputation_ctx_id))

        # generate dga model full path for fdga
        model = self.config.get('model', None)
        if model:
            json_conf['model_path'] = DGA_MODELS_PATH + model

        # generate dga token_map full path for fdga
        token_map = self.config.get('token_map', None)
        if token_map:
            json_conf['token_map_path'] = DGA_MODELS_PATH + token_map

        # rename content_inspection fields
        yara_scan_type = self.config.get('yara_scan_type', None)
        if yara_scan_type:
            json_conf['yaraScanType'] = yara_scan_type
        yara_scan_max_size = self.config.get('yara_scan_max_size', None)
        if yara_scan_max_size:
            json_conf['yaraScanMaxSize'] = yara_scan_max_size
        max_connections = self.config.get('max_connections', None)
        if max_connections:
            json_conf['maxConnections'] = max_connections
        max_memory_usage = self.config.get('max_memory_usage', None)
        if max_memory_usage:
            json_conf['maxMemoryUsage'] = max_memory_usage

        # Add all listed fields without need for modification
        for key, value in self.config.items():
            if key in PASS_THROUGH_FIELDS:
                json_conf[key] = value

        # Finally, translate the dictionary into json string
        try:
            json_conf = json_dumps(json_conf, sort_keys=True, indent=4)
        except Exception as e:
            logger.error("FilterPolicy::conf_to_json:: could not dump config to json: {}".format(e))

        return json_conf


    @staticmethod
    def str_attrs():
        return ['filter', 'conf_path', 'nb_thread', 'log_level', 'config']

    @property
    def socket_path(self):
        return "{}/{}_{}.sock".format(SOCKETS_PATH, self.filter.name, self.id)

    def mmdarwin_parameters_rsyslog_str(self):
        return str(self.mmdarwin_parameters).replace("\'", "\"")
