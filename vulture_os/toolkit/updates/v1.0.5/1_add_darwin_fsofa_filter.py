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
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = ''

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

from system.cluster.models import Cluster
from darwin.policy.models import DarwinFilter, FilterPolicy, DarwinPolicy


if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        try:
            darwinFilter = DarwinFilter.objects.create(
                name="sofa",
                description="Scan Outliers Finding and Analysis, allows finding outliers in scan results coming from network scanners",
                is_internal=False
            )
        except Exception as e:
            print("Error while adding Fsofa filter: {}".format(e))
            exit

        try:
            defaultPolicy = DarwinPolicy.objects.get(pk=1)
            if defaultPolicy is not None:
                filterPolicy = FilterPolicy.objects.create(
                    filter = darwinFilter,
                    policy = defaultPolicy,
                    enabled = False,
                    nb_thread = 1,
                    log_level = "WARNING",
                    threshold = 0,
                    mmdarwin_enabled = False,
                    mmdarwin_parameters = [],
                    cache_size = 0,
                    output = "NONE",
                    conf_path = "/home/darwin/conf/fsofa/fsofa.conf",
                    config = {
                        "python_env_path": "/home/vlt-os/env/bin/python",
                        "module": "scan_analysis_anomaly_core",
                        "function": "main",
                        "custom_python_path": "/home/darwin/conf/fsofa/"
                    }
                )
        except Exception as e:
            print("Error while adding default Fsofa filter to Default Policy: {}".format(e))
            exit

        print("Done.")