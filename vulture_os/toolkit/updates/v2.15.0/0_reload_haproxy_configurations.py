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
__doc__ = "Reload all service configurations that communicate with Redis"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
from django.db.models import Q
django.setup()

from system.cluster.models import Cluster
from services.frontend.models import Frontend

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialised yet.")
    else:
        try:
            node.api_request("services.haproxy.haproxy.configure_node")
            api_res = node.api_request("services.haproxy.haproxy.reload_service")
            if not api_res.get('status'):
                print(f"API error while trying to restart HAProxy service : {api_res.get('message')}")

            query = Q(mode="log", listening_mode="redis") | Q(mode="filebeat")
            for frontend in Frontend.objects.filter(query).only(*Frontend.str_attrs(), 'ruleset'):
                if node in frontend.get_nodes():
                    node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.id)
                    print(f"Listener {frontend}({frontend.ruleset}) Rsyslog configuration reload asked.")
                    if frontend.mode == "filebeat":
                        node.api_request("services.filebeat.filebeat.build_conf", frontend.id)
                        print(f"Listener {frontend}({frontend.ruleset}) Filebeat configuration reload asked.")
            node.api_request("services.rsyslogd.rsyslog.restart_service")

        except Exception as e:
            print(f"Failed to update some Haproxy configurations: {e}")
            print("Please relaunch this script after solving the issue.")

        print("Done.")
