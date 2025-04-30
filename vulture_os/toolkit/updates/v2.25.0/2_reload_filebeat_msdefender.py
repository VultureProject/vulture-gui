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
__doc__ = "Reload Filebeat configurations using MS Defender module"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
django.setup()

from system.cluster.models import Cluster
from services.frontend.models import Frontend
from django.utils import timezone


UPDATED_RULESETS = ["api_beyondtrust_reportings", "api_carbon_black", "trellix", "paloalto-ecs", "hillstone_ngfw"]

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        for frontend in Frontend.objects.filter(mode="filebeat", filebeat_module="microsoft").only(*Frontend.str_attrs(),
                                                                                                'ruleset'):
            node.api_request('services.filebeat.filebeat.restart_service', frontend.pk)
            print("Reload configuration of Filebeat service for listener {}({}) asked.".format(frontend, frontend.ruleset))
        print("Done.")
