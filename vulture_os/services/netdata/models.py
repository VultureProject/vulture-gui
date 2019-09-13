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
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Netdata service main models'

from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from djongo import models

import logging
import logging.config

logging.config.dictConfig(settings.LOG_SETTINGS)

CHOICES_HISTORY = (
    (3600, 3600),
    (7200, 7200),
    (14400, 14400),
    (28800, 28800),
    (43200, 43200),
    (86400, 86400)
)

BACKEND_TYPE_CHOICES = (
    ('graphite', "Graphite"),
    ('opentsdb', "OpenTSDB"),
    ('json', "JSON")
)

DATA_SOURCE_CHOICES = (
    ('average', "Average"),
    ('sum', "Sum"),
    ('as collected', "As collected")
)


class NetdataSettings(models.Model):
    """ Model used to manage global configuration fields of Netdata """
    """ max size of history database in memory """
    history = models.IntegerField(
        default=3600,
        choices=CHOICES_HISTORY
    )

    """ *** BACKEND OPTIONS (influxDB) """
    backend_enabled = models.BooleanField(
        default=False,
        verbose_name=_("Enable backend"),
        help_text=_("Enable the output of metrics in an external DB"),
    )
    backend_type = models.TextField(
        default="opentsdb",
        choices=BACKEND_TYPE_CHOICES,
        verbose_name=_("Type of backend"),
        help_text=_("Type of backend, see https://docs.netdata.cloud/backends/#features."),
    )
    backend_host_tags = models.ListField(
        default=[],
        verbose_name=_("List of tags"),
        help_text=_(" Defines tags that should be appended on all metrics for the given host.")
    )
    backend_destination = models.TextField(
        default="tcp:[ffff:...:0001]:4242 tcp:10.11.12.1:4242",
        verbose_name=_("Destinations list"),
        help_text=_("Space separated list of [PROTOCOL:]HOST[:PORT] - the first working will be used.")
    )
    backend_data_source = models.TextField(
        default="average",
        choices=DATA_SOURCE_CHOICES,
        verbose_name=_("Kind of data"),
        help_text=_("Select the kind of data that will be sent to the backend."),
    )
    backend_prefix = models.TextField(
        default="netdata",
        verbose_name=_("Prefix"),
        help_text=_("The prefix to add to all metrics."),
    )
    backend_update_every = models.IntegerField(
        default=10,
        verbose_name=_("Update every (s)"),
        help_text=_("The number of seconds between sending data to the backend."),
    )
    backend_buffer_on_failure = models.IntegerField(
        default=10,
        verbose_name=_("Buffer on failure"),
        help_text=_("The number of iterations to buffer data, when the backend is not available."),
    )
    backend_timeout = models.IntegerField(
        default=20000,
        verbose_name=_("Timeout (ms)"),
        help_text=_("The timeout in milliseconds to wait for the backend server to process the data."),
    )
    backend_send_hosts_matching = models.TextField(
        default="localhost *",
        verbose_name=_("Send hosts matching"),
        help_text=_("Allow to filter which hosts will be sent to the server."),
    )
    backend_send_charts_matching = models.TextField(
        default="*",
        verbose_name=_("Send charts matching"),
        help_text=_("Allow to filter which charts will be sent to the server."),
    )
    backend_send_names_or_ids = models.BooleanField(
        default=True,
        verbose_name=_("Send names instead of ids"),
        help_text=_("Controls the metric names netdata should send to backend.."),
    )

    def to_template(self):
        """ Dictionary used to create configuration file
        :return     Dictionnary of configuration parameters
        """
        return {
            'history': self.history,
            'backend_enabled': self.backend_enabled,
            'backend_type': self.backend_type,
            'backend_host_tags': self.backend_host_tags,
            'backend_destination': self.backend_destination,
            'backend_data_source': self.backend_data_source,
            'backend_prefix': self.backend_prefix,
            'backend_update_every': self.backend_update_every,
            'backend_buffer_on_failure': self.backend_buffer_on_failure,
            'backend_timeout': self.backend_timeout,
            'backend_send_hosts_matching': self.backend_send_hosts_matching,
            'backend_send_charts_matching': self.backend_send_charts_matching,
            'backend_send_names_or_ids': self.backend_send_names_or_ids
        }

    def to_dict(self):
        result = {
            'history': self.history,
            'backend_enabled': self.backend_enabled
        }
        if self.backend_enabled:
            result['backend_type'] = self.backend_type
            result['backend_host_tags'] = self.backend_host_tags
            result['backend_destination'] = self.backend_destination
            result['backend_data_source'] = self.backend_data_source
            result['backend_prefix'] = self.backend_prefix
            result['backend_update_every'] = self.backend_update_every
            result['backend_buffer_on_failure'] = self.backend_buffer_on_failure
            result['backend_timeout'] = self.backend_timeout
            result['backend_send_hosts_matching'] = self.backend_send_hosts_matching
            result['backend_send_charts_matching'] = self.backend_send_charts_matching
            result['backend_send_names_or_ids'] = self.backend_send_names_or_ids
        return result
