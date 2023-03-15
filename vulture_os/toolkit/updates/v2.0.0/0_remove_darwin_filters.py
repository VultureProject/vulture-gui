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
__doc__ = "remove CONTENT_INSPECTION and YARA filters from the list of available filters"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

from system.cluster.models import Cluster
from darwin.policy.models import DarwinFilter, DarwinPolicy, FilterPolicy

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialised yet.")
    else:
        reload_frontends_set = set()
        reload_policies_set = set()
        filter_conf_paths_set = set()
        try:
            content_inspection_type = DarwinFilter.objects.filter(name="content_inspection")
            yara_type = DarwinFilter.objects.filter(name="yara")

            if content_inspection_type:
                for filter_instance in FilterPolicy.objects.filter(filter_type=content_inspection_type.first()):
                    policy = filter_instance.policy
                    reload_policies_set.add(policy)

                    print(f"removing configuration of filter 'content_inspection' in policy {policy.name}")
                    Cluster.api_request("services.darwin.darwin.delete_filter_conf", filter_instance.conf_path)

                    for frontend in policy.frontend_set.all():
                        reload_frontends_set.add(frontend)

                    try:
                        filter_instance.delete()
                    except Exception as e:
                        print(f"Could not remove filter {filter_instance.filter_type.name} in policy {policy.name}: {e}")

                print("Removing content_inspection filter type...")
                content_inspection_type.delete()

            if yara_type:
                for filter_instance in FilterPolicy.objects.filter(filter_type=yara_type.first()):
                    policy = filter_instance.policy
                    reload_policies_set.add(policy)

                    print(f"removing configuration of filter 'yara' in policy {policy.name}")
                    Cluster.api_request("services.darwin.darwin.delete_filter_conf", filter_instance.conf_path)

                    for frontend in policy.frontend_set.all():
                        reload_frontends_set.add(frontend)

                    try:
                        filter_instance.delete()
                    except Exception as e:
                        print(f"Could not remove filter {filter_instance.filter_type.name} in policy {policy.name}: {e}")

                print("Removing yara filter type...")
                yara_type.delete()

            # No need to udpate buffering : content_inspection and yara filter types does not allow buffering

            print("[+] Reloading dependent frontends...")
            updated_nodes = set()
            for frontend in reload_frontends_set:
                print(f"-> Reloading frontend {frontend.name}")
                frontend.darwin_policies.clear()
                for frontend_node in frontend.get_nodes():
                    frontend_node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.pk)
                    updated_nodes.add(frontend_node)
            for node in updated_nodes:
                node.api_request("services.rsyslogd.rsyslog.restart_service")
            print("[-] Reloaded dependent frontends")

            print("[+] Removing empty policies...")
            for policy in reload_policies_set:
                if policy.filterpolicy_set.count() == 0:
                    print(f"-> Removing policy {policy.name}")
                    policy.delete()
            print("[-] Removed all empty policies")

            print("[+] Reloading Darwin...")
            Cluster.api_request("services.darwin.darwin.reload_conf")
            print("[-] Darwin reloaded")

        except Exception as e:
            print(f"Error while processing filters: {e}")
            print("Please relaunch this script after solving the issue.")

        print("Done.")
