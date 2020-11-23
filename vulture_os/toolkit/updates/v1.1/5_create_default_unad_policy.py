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
__doc__ = 'Create a default anomaly detection Darwin policy'

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
from darwin.policy.models import DarwinPolicy, FilterPolicy, DarwinFilter, DarwinBuffering

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        try:
            unad_filter_type = DarwinFilter.objects.get(name="unad")
        except DarwinFilter.DoesNotExist:
            print("cannot create default unad policy, 'unad' filter type does not exist")
            sys.exit(0)

        try:
            policy, created = DarwinPolicy.objects.get_or_create(
                name="Default Detect Network Anomaly",
                defaults={
                    "description": "This policy is an example of network anomaly detection",
                    "is_internal": False
                }
            )
        except Exception as e:
            print("error while creating default unad policy: {}".format(e))
            sys.exit(0)

        try:
            dfilter, created = FilterPolicy.objects.get_or_create(
                enabled=True,
                filter_type=unad_filter_type,
                policy=policy
            )
            if created:
                # create the corresponding buffering
                DarwinBuffering.objects.create(
                    interval=300,
                    required_log_lines=10,
                    # Will be updated with next command
                    buffer_filter=None,
                    destination_filter=dfilter
                )
            DarwinPolicy.update_buffering()
        except Exception as e:
            print("error while creating unad filter: {}".format(e))
            sys.exit(0)
            
        print("Done.")
