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
__doc__ = "Update default values for existing LDAPRepositories' user_objectclasses and group_objectclasses"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
django.setup()

from system.cluster.models import Cluster
from authentication.ldap.models import LDAPRepository

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialised yet.")
    else:
        try:
            # Cannot use filtering as JSONFields are not correctly filtered upon...
            for ldap_repo in LDAPRepository.objects.all():
                save = False
                if not ldap_repo.user_objectclasses:
                    save = True
                    ldap_repo.user_objectclasses = ["top", "InetOrgPerson"]
                if not ldap_repo.group_objectclasses:
                    save = True
                    ldap_repo.group_objectclasses = ["top", "groupOfNames"]

                if save:
                    ldap_repo.save()
                    print(f"Updated and saved repository {ldap_repo}")

        except Exception as e:
            print("Failed to update LDAP Repositories: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
