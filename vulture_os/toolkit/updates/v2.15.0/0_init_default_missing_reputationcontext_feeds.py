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
__author__ = "Fabien Amelinck"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = "Add missing default ReputationContext feeds (GeoLite)"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
django.setup()

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
            try:
                existing_wrong_name = ReputationContext.objects.get(name="Geolite2_Country")
                existing_wrong_name.name = "Geolite2 Country"
                existing_wrong_name.save()
            except ReputationContext.DoesNotExist:
                pass
            db, created = ReputationContext.objects.update_or_create(
                name="Geolite2 Country",
                defaults={
                    "db_type": "GeoIP",
                    "method": "GET",
                    "url": "https://barricade.vultureproject.org/ipsets/GeoLite2-Country.mmdb",
                    "verify_cert": True,
                    "filename": "GeoLite2-Country.mmdb",
                    "description": "Maxmind DBs Geoip country database",
                    "nb_netset": 0,
                    "nb_unique": 0,
                    "internal": True,
                    "enable_hour_download": True
                }
            )
            if created:
                print("GeoLite Country default feed created")

            try:
                existing_wrong_name = ReputationContext.objects.get(name="Geolite2_City")
                existing_wrong_name.name = "Geolite2 City"
                existing_wrong_name.save()
            except ReputationContext.DoesNotExist:
                pass

            db, created = ReputationContext.objects.update_or_create(
                name="Geolite2 City",
                defaults={
                    "db_type": "GeoIP",
                    "method": "GET",
                    "url": "https://barricade.vultureproject.org/ipsets/GeoLite2-City.mmdb",
                    "verify_cert": True,
                    "filename": "GeoLite2-City.mmdb",
                    "description": "Maxmind DBs Geoip city database",
                    "nb_netset": 0,
                    "nb_unique": 0,
                    "internal": True,
                    "enable_hour_download": True
                }
            )
            if created:
                print("GeoLite City default feed created")

        except Exception as e:
            print("Failed to create default GeoLite ReputationContext feeds: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
