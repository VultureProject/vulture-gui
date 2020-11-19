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
__doc__ = 'Create new Darwin Filter types'

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
from darwin.policy.models import DarwinFilter

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        try:
            dfilter, created = DarwinFilter.objects.get_or_create(
                name="bufr",
                defaults={
                    "longname": "Buffer",
                    "description": "Caches data in Redis to request other filters with bulks at regular intervals",
                    "is_internal": True,
                    "can_be_buffered": False
                }
            )
            if created:
                print("created '{}' successfuly".format(dfilter))
            else:
                print("DarwinFilter '{}' existed already".format(dfilter))
        except Exception as e:
            print("could not create DarwinFilter 'bufr': {}".format(e))
        
        try:
            dfilter, created = DarwinFilter.objects.get_or_create(
                name="yara",
                defaults={
                    "longname": "Yara Engine",
                    "description": "Scans arbitrary chunks of data with the Yara engine",
                    "is_internal": False,
                    "can_be_buffered": False
                }
            )
            if created:
                print("created '{}' successfuly".format(dfilter))
            else:
                print("DarwinFilter '{}' existed already".format(dfilter))
        except Exception as e:
            print("could not create DarwinFilter 'yara': {}".format(e))

        print("Done.")
