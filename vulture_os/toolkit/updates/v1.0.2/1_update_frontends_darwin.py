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
__author__ = "Theo Bertin"
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

from system.cluster.models import Cluster, Node
from services.frontend.models import Frontend

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        try:
            frontends = Frontend.objects.filter(mode__in=["impcap", "log"], darwin_policy__isnull=False)
        except Exception as e:
            print("Failed to get Frontends with a darwin policy: {}".format(str(e)))
        for frontend in frontends:
            print("reloading frontend {}".format(frontend.name))
            if node in frontend.get_nodes():
                api_res = node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.id)
                if not api_res.get("status"):
                    print("Error while updating rsyslog configuration of frontend '{}': "
                          "{}.".format(frontend.name, api_res.get("message")))

        print("Done.")
