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
__doc__ = "Remove old workflow_*.cfg files, not used anymore by vulture"

import sys
import os
from glob import glob as file_glob

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

from system.cluster.models import Cluster

if not Cluster.is_node_bootstrapped():
    sys.exit(0)
from workflow.models import Workflow

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        try:
            active_workflow_files = [w.get_filename() for w in Workflow.objects.all()]
            # Using hardcoded filepath as script is dependent on current version and path
            files_to_remove = [file for file in file_glob(f"/usr/local/etc/haproxy.d/workflow_*.cfg") if file not in active_workflow_files]

            for remove_file in files_to_remove:
                print(f"removing obsolete {remove_file}")
                node.api_request("services.haproxy.haproxy.delete_conf", os.path.basename(remove_file))

        except Exception as e:
            print("Failed to remove all obsolete workflow files: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
