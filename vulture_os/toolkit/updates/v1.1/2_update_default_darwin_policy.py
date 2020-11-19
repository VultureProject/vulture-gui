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
__author__ = "Théo Bertin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Update Default internal policy to become internal ones'

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
from darwin.policy.models import DarwinPolicy, FilterPolicy, DarwinFilter, REDIS_SOCKET_PATH

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        try:
            try:
                old_policy = DarwinPolicy.objects.get(name="Default darwin policy")
                print("deleting old default policy")
                old_policy.delete()
            except DarwinPolicy.DoesNotExist:
                pass

            policy, created = DarwinPolicy.objects.get_or_create(name="Internal Policy", is_internal=True)

            if not created:
                for dfilter in policy.filterpolicy_set.all():
                    dfilter.delete()

            policy.description = "Policy used to contain all internal filters"
            policy.save()

            try:
                session_type = DarwinFilter.objects.get(name="sess")
            except DarwinFilter.DoesNotExist:
                print("not adding session filter to internal policy: could not get 'sess' DarwinFilter type")
                sys.exit(0)

            session_filter = FilterPolicy.objects.create(
                filter_type=session_type,
                policy=policy,
                config={
                    "redis_socket_path": REDIS_SOCKET_PATH
                }
            )

        except Exception as e:
            print("could not update default darwin policy: {}".format(e))
            
        print("Done.")
