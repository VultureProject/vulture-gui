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
from django.core.validators import MinValueValidator
from django.utils.translation import gettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models

# Django project imports
from applications.reputation_ctx.models import ReputationContext
from system.cluster.models import Cluster

# External modules imports
from json import dumps as json_dumps
from os import path as os_path

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

JINJA_PATH = "/home/vlt-os/vulture_os/darwin/log_viewer/config/"


SOCKETS_PATH = "/var/sockets/darwin"
FILTERS_PATH = "/home/darwin/filters"
CONF_PATH = "/home/darwin/conf"
DATA_PATH = "/var/db/darwin"
TEMPLATE_OWNER = "darwin:vlt-web"
TEMPLATE_PERMS = "644"

REDIS_SOCKET_PATH = "/var/sockets/redis/redis.sock"
ALERTS_REDIS_LIST_NAME = "darwin_alerts"
ALERTS_REDIS_CHANNEL_NAME = "darwin.alerts"
ALERTS_LOG_FILEPATH = "/var/log/darwin/alerts.log"

DGA_MODELS_PATH = CONF_PATH + '/fdgad/'
VAST_MODELS_PATH = CONF_PATH + '/fvast/'
VAML_MODELS_PATH = CONF_PATH + '/fvaml/'

DARWIN_LOGLEVEL_CHOICES = (
    ('CRITICAL', 'Critical'),
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


def validate_vast_config(config):
    cleaned_config = {}

    # model validation
    model = config.get('model', None)
    if model is None:
        raise ValidationError({'model': _("configuration should contain a 'model' parameter")})
    if not os_path.exists(VAST_MODELS_PATH + model + ".dat"):
        raise ValidationError({'model': _("could not find model on system")})
    cleaned_config['model'] = model

    return cleaned_config


def validate_vaml_config(config):
    cleaned_config = {}

    # model validation
    model = config.get('model', None)
    if model is None:
        raise ValidationError({'model': _("configuration should contain a 'model' parameter")})
    if not os_path.exists(VAML_MODELS_PATH + model + ".dat"):
        raise ValidationError({'model': _("could not find model on system")})
    cleaned_config['model'] = model

    # holidays file validation
    holidays_file = config.get('holidays_file', None)
    if holidays_file is None:
        raise ValidationError({'holidays_file': _("configuration should contain a 'holidays_file' parameter")})
    if not os_path.exists(VAML_MODELS_PATH + holidays_file + ".holidays"):
        raise ValidationError({'holidays_file': _("could not find holidays_file on system")})
    cleaned_config['holidays_file'] = holidays_file

    # percent_more_alert validation
    percent_more_alert = config.get('percent_more_alert', None)
    if percent_more_alert is None:
        ValidationError({'percent_more_alert': _("configuration should contain a 'percent_more_alert' parameter")})
    if not isinstance(percent_more_alert, float) or percent_more_alert < 0:
        ValidationError({'percent_more_alert': _("'percent_more_alert' should be a positive float")})
    cleaned_config['percent_more_alert'] = percent_more_alert

    # percent_less_alert validation
    percent_less_alert = config.get('percent_less_alert', None)
    if percent_less_alert is None:
        ValidationError({'percent_less_alert': _("configuration should contain a 'percent_less_alert' parameter")})
    if not isinstance(percent_less_alert, float) or percent_less_alert < 0:
        ValidationError({'percent_less_alert': _("'percent_less_alert' should be a positive float")})
    cleaned_config['percent_less_alert'] = percent_less_alert

    # percent_more_warning validation
    percent_more_warning = config.get('percent_more_warning', None)
    if percent_more_warning is not None:
        if not isinstance(percent_more_warning, float) or percent_more_warning < 0:
            ValidationError({'percent_more_warning': _("'percent_more_warning' should be a positive float")})
        cleaned_config['percent_more_warning'] = percent_more_warning

    # percent_less_warning validation
    percent_less_warning = config.get('percent_less_warning', None)
    if percent_less_warning is not None:
        if not isinstance(percent_less_warning, float) or percent_less_warning < 0:
            ValidationError({'percent_less_warning': _("'percent_less_warning' should be a positive float")})
        cleaned_config['percent_less_warning'] = percent_less_warning

    # minimal_variation validation
    minimal_variation = config.get('minimal_variation', None)
    if minimal_variation is not None:
        if not isinstance(minimal_variation, float) or minimal_variation < 0:
            ValidationError({'minimal_variation': _("'minimal_variation' should be a positive float")})
        cleaned_config['minimal_variation'] = minimal_variation

    # lower_absolute validation
    lower_absolute = config.get('lower_absolute', None)
    if lower_absolute is not None:
        if not isinstance(lower_absolute, float):
            ValidationError({'lower_absolute': _("'lower_absolute' should be a positive float")})
        cleaned_config['lower_absolute'] = lower_absolute

    return cleaned_config



DARWIN_FILTER_CONFIG_VALIDATORS = {
    'unad': validate_anomaly_config,
    'conn': validate_connection_config,
    'dgad': validate_dga_config,
    'lkup': validate_hostlookup_config,
    'sofa': validate_sofa_config,
    'tanomaly': validate_tanomaly_config,
    'vast': validate_vast_config,
    'vaml': validate_vaml_config,
}

class DarwinFilter(models.Model):
    """The quadrigram of the filter"""
    name = models.TextField(unique=True)

    """A Long name to develop the quadrigram or give a more explicit name"""
    longname = models.TextField()

    """The description on what the filter does"""
    description = models.TextField()

    """Whether this filter type should be visible on GUI"""
    is_internal = models.BooleanField(default=False)

    """Whether this filter can be buffered with the BUFR filter"""
    can_be_buffered = models.BooleanField(default=False)

    def __str__(self):
        return self.name

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "is_launchable" in fields:
            result['is_launchable'] = self.is_launchable
        return result

    @property
    def exec_path(self):
        return "{}/darwin_{}".format(FILTERS_PATH, self.name)

    @property
    def is_launchable(self):
        return os_path.isfile("{conf_path}/f{filter_name}/f{filter_name}.conf".format(conf_path=CONF_PATH, filter_name=self.name))

    @staticmethod
    def str_attrs():
        return ['name']


class DarwinPolicy(models.Model):
    name = models.TextField(
        unique=True,
        default="Custom Policy",
        help_text="The friendly name of your policy (should be unique)"
    )

    description = models.TextField(
        blank=True,
        help_text="A description for your policy"
    )

    is_internal = models.BooleanField(
        default=False,
        help_text=_("Whether this policy is a system one"),
    )

    def to_dict(self, fields=None):
        return_data = model_to_dict(self, fields=fields)
        if not fields or "filters" in fields:
            return_data['filters'] = []
            # Test self.pk to prevent M2M errors when object isn't saved in DB
            if self.pk:
                for filt in self.filterpolicy_set.all():
                    return_data['filters'].append(filt.to_dict())

        return return_data

    def to_template(self):
        """  returns the attributes of the class """
        return {
            'id': str(self.id),
            'name': self.name,
            'description': self.description,
        }

    def to_html_template(self):
        """ Returns needed attributes for html rendering """
        return_data = {
            'id': str(self.id),
            'name': self.name,
            'description': self.description,
            'inputs': [],
            'status': []
        }
        try:
            # Test self.pk to prevent M2M errors when object isn't saved in DB
            return_data['inputs'] = [f.name for f in self.frontend_set.all()] if self.pk else []
            return_data['status'] = [{f.filter_type.name: f.status} for f in self.filterpolicy_set.all() if not f.filter_type.is_internal] if self.pk else []
        except ObjectDoesNotExist:
            pass

        return return_data


    @staticmethod
    def update_buffering():
        """
        This function updates all models to create/assign buffer filter(s) to corresponding buffering actions
        it also enables or disables buffer filter depending on conditions
        """
        logger.debug("darwin::update_buffering:: starting to update buffering filters")
        # Get new (incomplete) bufferings
        new_bufferings = DarwinBuffering.objects.filter(buffer_filter=None)
        buffer_type = DarwinFilter.objects.get(name="bufr")

        for buffering in new_bufferings:
            buffer_filter= None
            # Get equivalent buffering, for same destination filter type
            existing_buffering = DarwinBuffering.objects.exclude(buffer_filter=None).filter(destination_filter__filter_type=buffering.destination_filter.filter_type).first()
            # If there is none existing, that means the buffering filter doesn't exist either
            if not existing_buffering:
                logger.info("darwin::update_buffering:: no buffer filter for '{}' filter type, creating".format(buffering.destination_filter.filter_type))
                # Create the internal policy if necessary
                internal_policy, created = DarwinPolicy.objects.get_or_create(
                    is_internal=True,
                    name="Internal Policy",
                    defaults={
                        "description": "Policy used to contain all internal filters"
                    })
                if created:
                    logger.info("darwin::update_buffering:: internal policy created")
                # Create the buffer filter for this destination filter type
                buffer_filter = FilterPolicy.objects.create(
                    filter_type=buffer_type,
                    policy=internal_policy,
                    enabled=True)
            # Equivalent buffering already exists, just get the assigned buffer filter
            else:
                buffer_filter = existing_buffering.buffer_filter

            # Update the buffering action with the assigned or newly-created buffer filter
            buffering.buffer_filter = buffer_filter
            buffering.save()

        # Enable/Disable buffer filters depending on conditions
        for buffer_filter in FilterPolicy.objects.filter(filter_type=buffer_type):
            enable = False

            # Update buffer filter only if it still has buffers, delete it otherwise
            if buffer_filter.buffers.exists():
                # Iterate over buffers associated with buffer filter
                # if a destination_filter is associated with a frontend through a policy, the buffer filter can be enabled
                # (In other words, the buffer filter is enabled only if it has at least one valid source of data)
                for buffer in buffer_filter.buffers.all():
                    if buffer.destination_filter.enabled and buffer.destination_filter.policy.frontend_set.exists():
                        logger.info("darwin::update_buffering:: enabling buffering filter {}".format(buffer_filter))
                        enable = True

                buffer_filter.enabled = enable
                buffer_filter.save()
            else:
                logger.info("darwin::update_buffering:: filter doesn't have buffers, deleting {}".format(buffer_filter))
                Cluster.api_request("services.darwin.darwin.delete_filter_conf", buffer_filter.conf_path)
                buffer_filter.delete()

        try:
            internal_policy = DarwinPolicy.objects.get(name="Internal Policy", is_internal=True)
            Cluster.api_request("services.darwin.darwin.write_policy_conf", internal_policy.pk)
            Cluster.api_request("services.darwin.darwin.reload_policy_filters", internal_policy.pk)
        except DarwinPolicy.DoesNotExist:
            logger.error("darwin_policy::update_buffering:: could not find internal policy")


    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def __str__(self):
        return self.name


class DarwinBuffering(models.Model):

    interval = models.PositiveIntegerField(
        default=300,
        help_text=_("Number of seconds to cache data before analysing the batch"),
        null=False
    )

    required_log_lines = models.PositiveIntegerField(
        default=10,
        help_text=_("Minimal number of entries to require before launching analysis"),
        null=False
    )

    buffer_filter = models.ForeignKey(
        "darwin.FilterPolicy",
        related_name="buffers",
        on_delete=models.CASCADE,
        null=True
    )

    destination_filter = models.ForeignKey(
        "darwin.FilterPolicy",
        related_name="buffering",
        on_delete=models.CASCADE
    )

    def to_dict(self, fields=None):
        return model_to_dict(self, fields=fields)


class FilterPolicy(models.Model):
    """ Associated filter template """
    filter_type = models.ForeignKey(
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

    """ The list of custom fields to take from the rsyslog message to send to Darwin """
    mmdarwin_parameters = models.JSONField(
        default=[],
        blank=True,
        help_text=_("!!! ADVANCED FEATURE !!! the list of rsyslog fields to take when executing the custom call to Darwin (syntax is Rsyslog "),
        validators=[validate_mmdarwin_parameters])

    """ The tag put in rsyslog enrichment field in case of match """
    enrichment_tags = models.JSONField(
        default=[],
        blank=True,
        help_text=_("The tag to use as enrichment value for this filter, if none is set the filter type is used")
    )

    weight = models.FloatField(
        default=1.0,
        validators=[MinValueValidator(0.0)],
        help_text=_("The weight of this filter when calculating mean certitude during multiple calls to different filters with the same data"),
        )

    """ Status of filter for each nodes """
    status = models.JSONField(
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

    """ The configuration written in the filter's configuration file """
    config = models.JSONField(
        default={},
        blank=True,
        help_text=_("A dictionary containing all specific parameters of this filter"),
    )

    def clean(self):
        # get the validator associated to the filter (there should be one defined in the list, even when it has no configuration parameters)
        conf_validator = DARWIN_FILTER_CONFIG_VALIDATORS.get(self.filter_type.name)
        if conf_validator:
            self.config = conf_validator(self.config)
        else:
            logger.critical("darwin:: could not validate filterpolicy configuration, no validator for '{}' type".format(self.filter_type.name))


    @property
    def name(self):
        """ Method used in Darwin conf to define a filter """
        return "{}_{}".format(self.filter_type.name, self.id)

    @property
    def conf_path(self):
        return "{darwin_path}/f{filter_name}/f{filter_name}_{filter_id}.conf".format(darwin_path=CONF_PATH, filter_name=self.filter_type.name, filter_id=self.pk)

    @property
    def socket_path(self):
        return "{darwin_socket_path}/{filter_name}_{filter_id}.sock".format(darwin_socket_path=SOCKETS_PATH, filter_name=self.filter_type.name, filter_id=self.pk)

    def __str__(self):
        return "[{}] {}".format(self.policy.name, self.filter_type.name)

    def to_dict(self, fields=None):
        ret = model_to_dict(self, fields=fields)
        if not fields or "buffering" in fields:
            buffering = DarwinBuffering.objects.filter(destination_filter=self).first()
            if buffering:
                ret['buffering'] = buffering.to_dict()

        return ret

    def _generate_lkup_conf(self):
        json_conf = {}

        db_type = self.config.get('db_type', None)
        if db_type and db_type in ['rsyslog', 'text', 'json']:
            json_conf['db_type'] = db_type

        # Resolve reputation_ctx_id into database for fhostlookup
        reputation_ctx_id = self.config.get('reputation_ctx_id', None)
        if reputation_ctx_id:
            try:
                database = ReputationContext.objects.get(pk=reputation_ctx_id)
                json_conf['database'] = database.absolute_filename
            except ReputationContext.DoesNotExist:
                logger.error("FilterPolicy::conf_to_json:: Could not find ReputationContext with id {}".format(reputation_ctx_id))

        return json_conf


    def _generate_dgad_conf(self):
        json_conf = {}

        # generate dga model full path for fdga
        model = self.config.get('model', None)
        if model:
            json_conf['model_path'] = DGA_MODELS_PATH + model

        # generate dga token_map full path for fdga
        token_map = self.config.get('token_map', None)
        if token_map:
            json_conf['token_map_path'] = DGA_MODELS_PATH + token_map

        return json_conf


    def _generate_bufr_conf(self):
        json_conf = {
            "input_format": [],
            "outputs": []
        }
        filter_type = ""

        if self.buffers.exists():
            some_buffer = self.buffers.first()
            input_type = some_buffer.destination_filter.filter_type.name

            if input_type == "unad":
                # TODO remove when BUFR is updated with new name format
                filter_type = "fanomaly"
                json_conf['input_format'] = [
                    {"name": "net_src_ip", "type": "string"},
                    {"name": "net_dst_ip", "type": "string"},
                    {"name": "net_dst_port", "type": "string"},
                    {"name": "ip_proto", "type": "string"}
                ]
            elif input_type == "sofa":
                filter_type = "fsofa"
                json_conf['input_format'] = [
                    {"name": "ip", "type": "string"},
                    {"name": "hostname", "type": "string"},
                    {"name": "os", "type": "string"},
                    {"name": "proto", "type": "string"},
                    {"name": "port", "type": "string"}
                ]
            elif input_type in ["vast", "vaml"]:
                filter_type = "sum"
                json_conf['input_format'] = [
                    {"name": "decimal", "type": "string"}
                ]

            for buffer in self.buffers.all():
                redis_lists = []
                for listener in buffer.destination_filter.policy.frontend_set.all().only("name"):
                    # different source name for each listener/frontend
                    # different source name for each filter
                    # different source name for each policy
                    source = "{}_{}_{}".format(buffer.destination_filter.name, listener.name, buffer.destination_filter.policy.id)
                    redis_lists.append({
                        "source": source,
                        "name": "darwin_bufr_{}".format(source)
                    })

                # Only create the output if there are sources
                if redis_lists:
                    json_conf['outputs'].append({
                        "filter_type": "{}".format(filter_type),
                        "filter_socket_path": buffer.destination_filter.socket_path,
                        "interval": buffer.interval,
                        "required_log_lines": buffer.required_log_lines,
                        "redis_lists": redis_lists
                    })

        return json_conf


    def _generate_vast_conf(self):
        json_conf = {}

        # generate vast model full path for fvast
        model = self.config.get('model', None)
        if model:
            json_conf['model'] = VAST_MODELS_PATH + model + ".dat"

        return json_conf


    def _generate_vaml_conf(self):
        json_conf = {}

        # generate vaml model full path for fvaml
        model = self.config.get('model', None)
        if model:
            json_conf['model'] = VAML_MODELS_PATH + model + ".dat"

        # generate vaml holidyas_file full path for fvaml
        holidays_file = self.config.get('holidays_file', None)
        if holidays_file:
            json_conf['holidays_file'] = VAML_MODELS_PATH + holidays_file + ".holidays"

        return json_conf


    def conf_to_json(self):
        """
        Function to clean and validate filter configuration before translating it to string and writing it in the configuration file
        """
        json_conf = {
            'redis_socket_path': REDIS_SOCKET_PATH,
            'alert_redis_list_name': ALERTS_REDIS_LIST_NAME,
            'alert_redis_channel_name': ALERTS_REDIS_CHANNEL_NAME,
            'log_file_path': ALERTS_LOG_FILEPATH
        }

        if self.enrichment_tags:
            json_conf['alert_tags'] = self.enrichment_tags

        # Those fields were already validated and don't need any modification, let them be in the resulting configuration as-is
        PASS_THROUGH_FIELDS = ['redis_expire', 'max_tokens', 'fastmode', 'timeout', 'redis_socket_path',
                                'alert_redis_list_name', 'alert_redis_channel_name', 'log_file_path',
                                'percent_more_alert', 'percent_less_alert', 'percent_more_warning',
                                'percent_less_warning', 'minimal_variation', 'lower_absolute']

        if self.filter_type.name == "lkup":
            json_conf.update(self._generate_lkup_conf())
        if self.filter_type.name == "dgad":
            json_conf.update(self._generate_dgad_conf())
        if self.filter_type.name == "bufr":
            json_conf.update(self._generate_bufr_conf())
        if self.filter_type.name == "vast":
            json_conf.update(self._generate_vast_conf())
        if self.filter_type.name == "vaml":
            json_conf.update(self._generate_vaml_conf())

        # Add all listed fields without need for modification
        for key, value in self.config.items():
            if key in PASS_THROUGH_FIELDS:
                json_conf[key] = value

        # Add enrichment tags as additional alert tags
        json_conf['alert_tags'] = self.enrichment_tags

        # Finally, translate the dictionary into json string
        try:
            json_conf = json_dumps(json_conf, sort_keys=True, indent=4)
        except Exception as e:
            logger.error("FilterPolicy::conf_to_json:: could not dump config to json: {}".format(e))

        return json_conf


    @staticmethod
    def str_attrs():
        return ['conf_path', 'nb_thread', 'log_level', 'config']

    def __str__(self):
        return "[{}] {}".format(self.policy, self.name)

