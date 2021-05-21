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
__doc__ = "Update portal template(s) content with initial image"

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
from workflow.models import Workflow
from authentication.user_portal.models import UserAuthentication


if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        try:
            # If authentication, reload frontend and portal Haproxy configs
            for workflow in Workflow.objects.filter(authentication__isnull=False):
                workflow.frontend.reload_conf()
                print("Frontend {} conf reload asked".format(workflow.frontend))
                workflow.save_conf()
                print("Workflow {} conf reload asked".format(workflow))
            for portal in UserAuthentication.objects.filter(enable_external=True):
                # Ensure portals with IDP activated have oauth enabled
                portal.enable_oauth = True
                portal.save()
                portal.external_listener.reload_conf()
                print("Frontend {} conf reload asked".format(portal.external_listener))
                portal.save_conf()
                print("IDP portal {} conf reload asked".format(portal))

            node.api_request("services.haproxy.haproxy.restart_service")

        except Exception as e:
            print("Failed to update authentication related configurations: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
