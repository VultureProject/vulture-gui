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
__doc__ = "Remove defined Backends with unix servers"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

from applications.backend.models import Backend
from system.cluster.models import Cluster

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialised yet.")
    else:
        workflows_to_delete = list()
        backends_to_delete = list()
        nodes_to_reload = list()
        try:
            backends = Backend.objects.filter(server__mode="unix")
            for backend in backends:
                if list(backend.server_set.values_list('mode', flat=True)) == ['unix']:
                    # Backend only has unix servers, needs deletion
                    backends_to_delete.append(backend)
                    workflows_to_delete.extend(backend.workflow_set.all())
                else:
                    # Backend has mixed-type servers, only remove the unix servers
                    print(f"Removing Unix server(s) from Backend '{backend.name}'")
                    backend.server_set.filter(mode="unix").delete()

            for workflow in set(workflows_to_delete):
                print(f"Removing Workflow '{workflow.name}'")
                nodes_to_reload.extend(workflow.frontend.reload_conf())
                filename = workflow.get_base_filename()
                Cluster.api_request('services.haproxy.haproxy.delete_conf', filename)
                workflow.delete()

            for backend in set(backends_to_delete):
                print(f"Removing Backend '{backend.name}'")
                backend_filename = backend.get_base_filename()
                Cluster.api_request('services.haproxy.haproxy.delete_conf', backend_filename)
                backend.delete()

            for node in set(nodes_to_reload):
                print(f"Reloading Haproxy for node '{node}'")
                node.api_request("services.haproxy.haproxy.reload_service")

            print(f"reloading PF configuration on all nodes")
            Cluster.api_request ("services.pf.pf.gen_config")

        except Exception as e:
            print("Failed to update some Frontend Haproxy configurations: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
