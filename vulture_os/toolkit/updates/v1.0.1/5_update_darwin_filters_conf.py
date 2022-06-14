#!/home/vlt-os/env/bin/python

"""This file is part of Vulture 4.

Vulture 4 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 4 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 4.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = ''

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

from system.cluster.models import Cluster
from darwin.policy.models import FilterPolicy

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        for filter in FilterPolicy.objects.all():
            filter.config["redis_socket_path"] = "/var/sockets/redis/redis.sock"
            filter.config["alert_redis_list_name"] = "darwin_alerts"
            filter.config["alert_redis_channel_name"] = "darwin.alerts"
            filter.config["log_file_path"] = "/var/log/darwin/alerts.log"

            if filter.filter_type.name == 'tanomaly':
                if filter.config.get("redis_list_name", None):
                    del filter.config['redis_list_name']
                filter.mmdarwin_enabled = False
                filter.mmdarwin_parameters = []

            # Remove useless cache for filters not using it
            if filter.filter_type.name not in ['dga', 'hostlookup']:
                filter.cache_size = 0

            if filter.nb_thread == 10:
                filter.nb_thread = 5

            if filter.filter_type.name == "content_inspection" and filter.nb_thread == 30:
                filter.nb_thread = 8

            # Put default log level to Warning
            if filter.log_level == "ERROR":
                filter.log_level = "WARNING"

            try:
                filter.save()
            except Exception as e:
                print("Error while saving filter {}: {}.".format(filter.name, e))

        print("Done.")