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
__doc__ = "Reload the default TLSProfile object and underlying configurations"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

from system.cluster.models import Cluster
from system.pki.models import TLSProfile


if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialised yet.")
    else:
        try:
            reload_haproxy = False
            default_tls_profile = TLSProfile.objects.get(name="Default TLS profile")
            default_tls_profile.protocols = ["tlsv13", "tlsv12"]
            default_tls_profile.save()
            default_tls_profile.save_conf()
            print("Updating updated TLS profile configuration on disk...")

            for frontend in set(listener.frontend for listener in default_tls_profile.listener_set.all()):
                if node in frontend.get_nodes():
                    print(f"Updating Frontend '{frontend.name}' configuration on disk...")
                    node.api_request("services.haproxy.haproxy.build_conf", frontend.id)
                    reload_haproxy = True

            for backend in set(server.backend for server in default_tls_profile.server_set.all()):
                print(f"Updating Backend '{backend.name}' configuration on disk...")
                backend.reload_conf()

            if reload_haproxy:
                node.api_request("services.haproxy.haproxy.reload_service")

        except TLSProfile.DoesNotExist:
            print("Default TLS profile doesn't exist anymore (or was renamed), skipping!")
            print("If you want to manually execute the change, you can edit the profile in the GUI, ensure TLSv1.3 is activated (under 'Allowed cipher protocols' in advanced options), then save the profile to apply the change")
        except Exception as e:
            print("Failed to update TLS profile: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
