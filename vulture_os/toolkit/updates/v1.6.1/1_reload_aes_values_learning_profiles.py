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
__author__ = "Theo BERTIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Reload LearningProfile objects with updated AES utils to corret padding issues'

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
django.setup()

from system.cluster.models import Cluster

if not Cluster.is_node_bootstrapped():
    sys.exit(0)
from authentication.learning_profiles.models import LearningProfile
from toolkit.system.aes_utils import AESCipher

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        for profile in LearningProfile.objects.all():
            try:
                print(f"Refreshing LearningProfile for app '{profile.app_name}', repo '{profile.repo_name}', login '{profile.login}'")
                aes = AESCipher("") # Do not worry about the key, it will be overridden...
                aes.key = bytes.fromhex(profile.encrypted_name) # ...just here
                value = aes.decrypt(profile.encrypted_value) # decrypt value to remove piotential excessive padding
                profile.encrypted_value = aes.encrypt(value).decode('utf-8') # and encrypt it once again with corrected AES utils
                profile.store()
            except Exception as e:
                print(f"Could not reload LearningProfile for {profile.login}: {e}")

        print("Done.")
