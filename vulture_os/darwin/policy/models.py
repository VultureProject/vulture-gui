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
from django.core.exceptions import ObjectDoesNotExist
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
    def str_attrs():
        return ['name']


class DarwinPolicy(models.Model):
    name = models.TextField(unique=True, default="Custom Policy")
    description = models.TextField()

    filters = models.ManyToManyField(
        DarwinFilter,
        through='FilterPolicy'
    )

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

    """ The custom rsyslog message's fields to get """
    mmdarwin_parameters = models.ListField(default=[])

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
        default=None,
        on_delete=models.SET_NULL
    )

    """ The fullpath to its configuration file """
    conf_path = models.TextField()

    """ A dict representing the filter configuration """
    config = models.DictField(default={
            "redis_socket_path": "/var/sockets/redis/redis.sock",
            "alert_redis_list_name": DARWIN_REDIS_ALERT_LIST,
            "alert_redis_channel_name": DARWIN_REDIS_ALERT_CHANNEL,
            "log_file_path": "/var/log/darwin/alerts.log"
    })

    @property
    def name(self):
        """ Method used in Darwin conf to define a filter """
        return "{}_{}".format(self.filter.name, self.policy.id)

    def __str__(self):
        return "[{}] {}".format(self.policy.name, self.filter.name)

    @staticmethod
    def str_attrs():
        return ['filter', 'conf_path', 'nb_thread', 'log_level', 'config']

    @property
    def socket_path(self):
        return "{}/{}_{}.sock".format(SOCKETS_PATH, self.filter.name, self.policy.id)

    def mmdarwin_parameters_rsyslog_str(self):
        return str(self.mmdarwin_parameters).replace("\'", "\"")
