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

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

from applications.logfwd.models import LogOMHIREDIS
from system.cluster.models import Cluster

if not Cluster.is_node_bootstrapped():
    sys.exit(0)


if __name__ == "__main__":

    logom, created = LogOMHIREDIS.objects.get_or_create(
        internal=True,
        name="Internal_Dashboard",
        enabled=True,
        target="127.0.0.3",
        port=6379,
        key="vlt.rsyslog.{{ruleset}}",
        pwd=""
    )
    if created:
        print("[+] New log forwarder added : {}".format(logom))
    print("2_add_internal_dashboard_forwarder done.")
