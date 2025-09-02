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
__doc__ = "Update GeoLite default databases to make them editable"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
django.setup()

from django.db.models import Q
from system.cluster.models import Cluster
from applications.reputation_ctx.models import ReputationContext

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialised yet.")
    else:
        try:
            if ReputationContext.objects.filter(Q(name="Geolite2 Country")).exists():
                    db = ReputationContext.objects.filter(Q(name="Geolite2 Country")).first()
                    if db.internal is True:
                        print("Modifying GeoLite Country default DB...")
                        db.url = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
                        db.auth_type = "basic"
                        db.user = "YOURACCOUNTID"
                        db.password = "YOURLICENSEKEY"
                        db.description = "Maxmind DBs Geoip country database.\n" \
                            "PLEASE FILL-IN YOUR PERSONAL ACCOUNDID AND LICENSEKEY TO USE THOSE DBS"
                        db.enable_hour_download = False
                        db.internal = False
                        db.save()
            if ReputationContext.objects.filter(Q(name="Geolite2 City")).exists():
                    db = ReputationContext.objects.filter(Q(name="Geolite2 City")).first()
                    if db.internal is True:
                        print("Modifying GeoLite City default DB...")
                        db.url = "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
                        db.auth_type = "basic"
                        db.user = "YOURACCOUNTID"
                        db.password = "YOURLICENSEKEY"
                        db.description = "Maxmind DBs Geoip city database.\n" \
                            "PLEASE FILL-IN YOUR PERSONAL ACCOUNDID AND LICENSEKEY TO USE THOSE DBS"
                        db.enable_hour_download = False
                        db.internal = False
                        db.save()
        except Exception as e:
            print(f"Failed to update Reputation Contexts: {e}")
            print("Please relaunch this script after solving the issue.")

        print("Done.")
