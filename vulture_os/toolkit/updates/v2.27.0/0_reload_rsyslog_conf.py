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
__author__ = "Fabien Amelinck"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = "Reload Rsyslog configurations"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
django.setup()

from django.db.models import Q
from system.cluster.models import Cluster
from services.frontend.models import Frontend
from applications.logfwd.models import LogOMElasticSearch

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialised yet.")
    else:
        try:
            print("Rebuilding Frontend configurations using an Elasticsearch forwarder...")
            logfwds = list(LogOMElasticSearch.objects.all())
            for frontend in Frontend.objects.filter(
                Q(log_forwarders__in=logfwds) |
                Q(log_forwarders_parse_failure__in=logfwds)).distinct():
                print(f"Reloading configuration of {frontend}")
                frontend.reload_conf()

        except Exception as e:
            print(f"Failed to rebuild Frontends: {e}")
            print("Please relaunch this script after solving the issue.")

        print("Done.")
