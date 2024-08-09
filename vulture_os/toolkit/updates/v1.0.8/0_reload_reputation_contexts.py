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
__author__ = "Kevin GUILLEMOT"
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
django.setup()

from system.cluster.models import Cluster
from services.frontend.models import Frontend
from applications.reputation_ctx.models import ReputationContext

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()

    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        old_reputation_contexts = [r.filename for r in ReputationContext.objects.filter(internal=True)]
        # Launch reputation contexts download to reload filenames
        node.api_request("gui.crontab.feed.security_update")
        # Reload configuration of Rsyslog templates
        node.api_request("services.rsyslogd.rsyslog.configure_node")
        # And, considering the filenames has changed, reload Rsyslog configuration of frontends
        restart_rsyslog = False
        for frontend in Frontend.objects.filter(enabled=True, enable_logging=True):
            if node in frontend.get_nodes():
                restart_rsyslog = True
                print("Reloading Rsyslog conf of frontend {}".format(frontend.name))
                api_res = node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.id)
                if not api_res.get("status"):
                    print("Error while updating rsyslog configuration of frontend '{}': "
                          "{}.".format(frontend.name, api_res.get("message")))

        if restart_rsyslog:
            api_res = node.api_request("services.rsyslogd.rsyslog.restart_service")
            if not api_res.get("status"):
                print("Error while restarting rsyslog: "
                        "{}.".format(api_res.get("message")))

        # Delete old Reputation Contexts
        for r in ReputationContext.objects.filter(filename__in=old_reputation_contexts):
            print("Deleting ReputationContext {}".format(r.name))
            r.delete()

        print("Done.")
