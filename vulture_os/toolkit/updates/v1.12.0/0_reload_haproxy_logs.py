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
__doc__ = "Update script to reload haproxy and rsyslog conf of frontends having logging enabled"

import sys
import os

if not os.path.exists("/home/vlt-os/vulture_os/.node_ok"):
    sys.exit(0)

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

from system.cluster.models import Cluster, Node
from services.frontend.models import Frontend


if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        try:
            # If authentication, reload frontend and portal Haproxy configs
            for frontend in Frontend.objects.filter(mode="http", enable_logging=True):
                frontend.reload_conf()
                print("Frontend {} haproxy conf reloaded".format(frontend.name))

                print("Asking reload of Rsyslog conf for frontend {}".format(frontend.name))
                api_res = node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.id)
                if not api_res.get("status"):
                    print("Error while updating rsyslog configuration of frontend '{}': "
                        "{}.".format(frontend.name, api_res.get("message")))

            print("Restarting Haproxy service")
            node.api_request("services.haproxy.haproxy.restart_service")

        except Exception as e:
            print("Failed to update logging frontend related configurations: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
