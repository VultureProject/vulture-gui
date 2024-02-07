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
__doc__ = "Reload the Haproxy Frontend configurations"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

from authentication.user_portal.models import UserAuthentication
from services.frontend.models import Frontend
from system.cluster.models import Cluster
from workflow.models import Workflow

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialised yet.")
    else:
        try:
            for frontend in Frontend.objects.filter(mode__in=['tcp', 'http'], workflow__isnull=False).distinct():
                print(f"Triggering configuration rebuild for Frontend '{frontend.name}'")
                node.api_request("services.haproxy.haproxy.build_conf", frontend.pk)

            api_res = node.api_request("services.haproxy.haproxy.reload_service")
            if not api_res.get('status'):
                print("API error while trying to "
                            "restart HAProxy service : {}".format(api_res.get('message')))

        except Exception as e:
            print("Failed to update some Frontend Haproxy configurations: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
