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
__doc__ = "Add new VAST and VAML filters to Darwin's list of filters"

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
from darwin.policy.models import DarwinPolicy, FilterPolicy, DarwinFilter, DarwinBuffering, REDIS_SOCKET_PATH

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        # Create new darwin VAST filter
        try:
            dfilter, created = DarwinFilter.objects.get_or_create(
                name="vast",
                defaults={
                    "longname": "STatistical VAriation",
                    "description": "Detection of abnormal variation through statistical approach",
                    "is_internal": False,
                    "can_be_buffered": True
                }
            )
            if created:
                print("created '{}' successfuly".format(dfilter))
            else:
                print("DarwinFilter '{}' existed already".format(dfilter))
        except Exception as e:
            print("could not create DarwinFilter '{}': {}".format(e, dfilter))

        # Create new darwin VAML filter
        try:
            dfilter, created = DarwinFilter.objects.get_or_create(
                name="vaml",
                defaults={
                    "longname": "VAriation Machine Learning",
                    "description": "Detection of abnormal variation through supervised regression",
                    "is_internal": False,
                    "can_be_buffered": True
                }
            )
            if created:
                print("created '{}' successfuly".format(dfilter))
            else:
                print("DarwinFilter '{}' existed already".format(dfilter))
        except Exception as e:
            print("could not create DarwinFilter '{}': {}".format(e, dfilter))

        print("Done.")
