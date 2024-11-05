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
__doc__ = "Removal of deprecated Redis forwarder for deprecated internal dashboard"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
django.setup()

from system.cluster.models import Cluster
from applications.logfwd.models import LogOMHIREDIS

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialised yet.")
    else:
        try:
            frontends = set()
            try:
                forwarder = LogOMHIREDIS.objects.get(name="Internal_Dashboard")
            except LogOMHIREDIS.DoesNotExist:
                print("log forwarder doesn't exist, skipping")
                sys.exit(0)

            for frontend in forwarder.frontend_set.all():
                print(f"Removing Forwarder from Frontend {frontend.name}")
                frontend.log_forwarders.remove(forwarder)
                # This is needed to really get rid of the forwarder in the Rsyslog configuration...
                frontend.log_condition = frontend.log_condition.replace("""{{Internal_Dashboard}}""", "")
                frontend.save()
                frontends.add(frontend)
            for frontend in forwarder.frontend_failure_set.all():
                print(f"Removing (failure) Forwarder from Frontend {frontend.name}")
                frontend.log_forwarders_parse_failure.remove(forwarder)
                frontend.save()
                frontends.add(frontend)

            # Reload all impacted Frontend's rsyslog configuration
            for frontend in frontends:
                for node_call in frontend.get_nodes():
                    print(f"Rebuilding Rsyslog configuration for frontend {frontend.name} on node {node.name}")
                    node_call.api_request("services.rsyslogd.rsyslog.build_conf", frontend.id)

            print("Reloading Rsyslog's pstats configuration")
            Cluster.api_request("services.rsyslogd.rsyslog.configure_pstats")
            print("Restarting Rsyslog")
            Cluster.api_request("services.rsyslogd.rsyslog.restart_service")

            print('Removing Forwarder...')
            forwarder.delete()

        except Exception as e:
            print(f"Error while reloading workflow configurations: {e}")
            print("Please relaunch this script after solving the issue.")

        print("Done.")
