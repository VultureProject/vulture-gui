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
__doc__ = "Updating default Tenant's name and related configurations"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

from system.cluster.models import Cluster, Node
from applications.reputation_ctx.models import ReputationContext

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialized yet.")
    else:
        try:
            try:
                print("Updating 'Geolite2 Country' database name...")
                geolite_country = ReputationContext.objects.get(name="Geolite2 Country")
                geolite_country.filename = "GeoLite2-Country.mmdb"
                geolite_country.save()
                print("OK!")
            except ReputationContext.DoesNotExist():
                print("'Geolite2 Country' database doesn't exist, ignoring.")

            try:
                print("Updating 'Geolite2 City' database name...")
                geolite_city = ReputationContext.objects.get(name="Geolite2 City")
                geolite_city.filename = "GeoLite2-City.mmdb"
                geolite_city.save()
                print("OK!")
            except ReputationContext.DoesNotExist():
                print("'Geolite2 City' database doesn't exist, ignoring.")

        except Exception as e:
            print("Failed to update Geolite2 databases: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
