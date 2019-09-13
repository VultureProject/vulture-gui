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

__author__ = "Kevin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = ''

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
try:
    django.setup()
except Exception as e:
    print("Node not configured yet. Quitting.")
    exit(0)

from darwin.policy.models import DarwinFilter
from services.exceptions import ServiceReloadError
from services.frontend.models import Frontend
from system.cluster.models import Cluster

if __name__ == "__main__":
    print("Executing the Injection filter removal (v0.8 migration)...")

    try:
        injection_filter = DarwinFilter.objects.get(name="injection")

        print("Deleting the injection filter...")
        injection_filter.delete()

    except Exception as error:
        print("Something went wrong. Maybe the migration was already run on this system: '{}'".format(error))
        exit(0)

    api_res = Cluster.api_request("services.darwin.darwin.build_conf")

    if not api_res.get("status"):
        print("Error while building Darwin configuration: {}.".format(api_res.get("message")))
    else:
        print("Successfully built Darwin configuration.")

    listeners = Frontend.objects.all()
    node_listeners = {}

    for listener in listeners:
        nodes = listener.get_nodes()

        for node in nodes:
            if node_listeners.get(node, None) is None:
                node_listeners[node] = []

            if listener not in node_listeners[node]:
                node_listeners[node].append(listener)

    for node, listeners in node_listeners.items():
        for listener in listeners:
            listener.configuration[node.name] = listener.generate_conf()

            """ API request asynchrone to save conf on node """
            # Save conf first, to raise if there is an error
            listener.save()
            listener.save_conf(node)
            print("Frontend {} configuration updated on node {}".format(listener.name, node.name))

            if not listener.rsyslog_only_conf:
                """ Reload HAProxy service - After rsyslog to prevent logging crash """
                api_res = node.api_request("services.haproxy.haproxy.reload_service")
                if not api_res.get('status'):
                    raise ServiceReloadError("on node {}\n API request error.".format(node.name), "haproxy",
                                             traceback=api_res.get('message'))

    print("Injection filter removal (v0.8 migration) DONE")
