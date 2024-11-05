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
__doc__ = "Updating default Tenant's name and related configurations"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
django.setup()

from system.cluster.models import Cluster
from system.tenants.models import Tenants

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialized yet.")
    else:
        try:
            frontends_to_reload = set()
            print("Updating Tenant name's with space to remove it")
            for tenant in Tenants.objects.filter(name__contains=" "):
                print(f"Updating '{tenant.name}'")
                tenant.name = tenant.name.replace(' ', "_")
                tenant.save()

                for frontend in tenant.frontend_set.filter(mode__in=["log", "filebeat"]):
                    if node in frontend.get_nodes():
                        frontends_to_reload.add(frontend)

            print("Updating associated Frontend's configuration...")
            for frontend in frontends_to_reload:
                print(f"Updating Frontend '{frontend.name}'")
                node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.id)

            if len(frontends_to_reload) > 0:
                node.api_request("services.rsyslogd.rsyslog.restart_service")

        except Exception as e:
            print("Failed to update frontends related to tenant: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
