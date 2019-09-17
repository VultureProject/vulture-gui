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
__author__ = "Florian HAGNIEL, Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = ''

import sys
import re
import ipaddress

nb_args = len(sys.argv)
if nb_args >= 3:
    hostname = sys.argv[1]
    ip = sys.argv[2]
    try:
        delete = sys.argv[3]
    except IndexError:
        delete = False

        # Testing IP Address validity
        try:
            ipaddress.ip_address(ip)
        except Exception as e:
            print("INCORRECT IP", file=sys.stderr)
            sys.exit(2)

        # Testing hostname validity
        pattern = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
        reg = re.compile(pattern)
        if not reg.match(hostname):
            print("INCORRECT HOSTNAME", file=sys.stderr)
            sys.exit(2)

    # Inputs are good, we can process them
    with open("/etc/hosts", 'r') as f:
        content = f.read()

    # Looking if host already exist, if yes we replace its ip address
    pattern = re.compile("^[a-z0-9:\.]+\s+{}$".format(hostname), re.M)
    if pattern.search(content):
        if delete:
            content = pattern.sub("", content)
            what = "deleted"
        else:
            content = pattern.sub("{}\t{}".format(ip, hostname), content)
            what = "updated"
    elif not delete:
        # Host doesnt exist, we add it
        content += "\n{}\t{}\n".format(ip, hostname)
        what = "added"
    else:
        print("Nothing to do")
        sys.exit(0)

    # Writing result into /etc/hosts
    with open('/etc/hosts', 'w') as f:
        f.write(content)

    try:
        # And into jails - It can fail if we are inside a jail => Nevermind
        for jail in ("apache", "mongodb", "redis", "rsyslog", "haproxy"):
            with open("/zroot/{}/etc/hosts".format(jail), "w") as f:
                f.write(content)
    except Exception:
        pass

    print("Host successfully {}".format(what))
    sys.exit(0)
else:
    print("ARGS ERROR", file=sys.stderr)
    sys.exit(2)
