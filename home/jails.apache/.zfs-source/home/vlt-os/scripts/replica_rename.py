#!/home/vlt-os/env/bin/python
# -*- coding: utf-8 -*-
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""

import os
import sys

sys.path.append("/home/vlt-os/vulture_os/")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
django.setup()
from django.db.models import Q

from applications.logfwd.models import LogOMMongoDB
from services.frontend.models import Frontend
from system.cluster.models import Cluster, Node
from toolkit.mongodb.mongo_base import MongoBase


if __name__ == "__main__":
    """ If 2 arguments : Refresh MongoDB replicaset config by replacing old_hostname 
                             by new hostname 
        If 0 arguments : Refresh MongoDB replicaset config
    """

    old_hostname = ""
    new_hostname = ""
    # Check args
    if len(sys.argv) != 1 and len(sys.argv) != 3:
        print("Replica_rename:: Usage: {} [old_hostname new_hostname]".format(sys.argv[0]))
        exit(1)
    elif len(sys.argv) == 3:
        old_hostname = sys.argv[1]
        new_hostname = sys.argv[2]

    # MongoDB - rename of node
    c = MongoBase()
    # Connect to the current renamed node
    c.connect(node=new_hostname+":9091", primary=False)
    c.connect(node=new_hostname+":9091", primary=False)
    print("Connected to {}".format(new_hostname))
    # Automagically connect to the primary node
    res = c.repl_rename(old_hostname, new_hostname)
    print("Node renamed.")

    node = Node.objects.get(name=old_hostname)
    node.name = new_hostname
    node.save()

    logfwd = LogOMMongoDB.objects.get(internal=True)
    logfwd.uristr = c.get_replicaset_uri()
    logfwd.save()

    # Update node name in services config
    Cluster.api_request("services.rsyslogd.rsyslog.configure_node")
    Cluster.api_request("services.haproxy.haproxy.configure_node")

    # Update Internal mongodb forwarder config in concerned frontends
    for frontend in Frontend.objects.filter(Q(log_forwarders_id=1) | Q(mode="http")):
        for node in frontend.get_nodes():
            node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.id)

    if not res[0]:
        print("Replica_rename::Error : Rename failure : {}".format(res[1]))
        exit(1)

    print("Replica_rename::Success: {}".format(res[1]))
