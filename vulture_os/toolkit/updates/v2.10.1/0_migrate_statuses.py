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
__doc__ = "Migrate statuses from JSON to List"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

from system.cluster.models import Cluster
from services.frontend.models import Frontend
from applications.backend.models import Backend
from darwin.policy.models import FilterPolicy

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialised yet.")
    else:
        try:
            # Migrate frontend status
            for frontend in Frontend.objects.all():
                if type(frontend.status) != list:
                    status = []
                    for node_name in frontend.status.keys():
                        status.append({"node": node_name, "status": frontend.status.get(node_name, "DOWN")})

                    frontend.status = status
                    frontend.save()

            # Migrate backend status
            for backend in Backend.objects.all():
                backend.http_health_check_version = backend.http_health_check_version.rstrip('\\r\\n') if backend.http_health_check_version in ('HTTP/1.0\\r\\n', 'HTTP/1.1\\r\\n') else backend.http_health_check_version

                if type(backend.status) != list:
                    status = []
                    for node_name in backend.status.keys():
                        status.append({"node": node_name, "status": backend.status.get(node_name, "DOWN")})

                    backend.status = status
                    backend.save()

            # Migrate policy status
            for policy in FilterPolicy.objects.all():
                if type(policy.status) != list:
                    status = []
                    for node_name in policy.status.keys():
                        status.append({"node": node_name, "status": policy.status.get(node_name, "DOWN")})

                    policy.status = status
                    policy.save()

        except Exception as e:
            print("Failed to migrate statuses: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
