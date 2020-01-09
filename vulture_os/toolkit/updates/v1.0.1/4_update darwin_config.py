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

from system.cluster.models import Cluster, Node
from darwin.policy.models import DarwinPolicy, DarwinFilter, FilterPolicy


if __name__ == "__main__":

    policies = DarwinPolicy.objects.all()
    for policy in policies:

        filter_list = policy.filters.all()
        for filter in filter_list:
            filter_policy = FilterPolicy.objects.get(policy=policy, filter=filter)

            for node in Node.objects.all().only('name'):
                    filter_policy.status[node.name] = "WAITING"

            Cluster.api_request("services.darwin.darwin.write_policy_conf", filter_policy.pk)
            if filter_policy.enabled:
                for frontend in policy.frontend_set.all():
                    # regenerate rsyslog conf for each frontend associated with darwin policy
                    Cluster.api_request('services.rsyslogd.rsyslog.build_conf', frontend.pk)

    Cluster.api_request("services.darwin.darwin.build_conf")