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
__doc__ = "Regenerate internal certificates"

import cryptography.x509.extensions
import sys
import os
from pwd import getpwnam
from grp import getgrnam

from django.utils import timezone

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
django.setup()

from system.cluster.models import Cluster
from system.pki.models import X509Certificate

from services.haproxy.haproxy import HaproxyService
from services.service import Service

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialised yet.")
    else:
        try:
            print("Looking for local x509 certificates to regenerate (missing SANs)...")
            cert_with_san_found = False
            old_certs = list()
            for cert in X509Certificate.objects.filter(
                cn=node.name,
                is_external=False,
                valid_from__lte=timezone.now(),
                valid_until__gt=timezone.now(),
                status=X509Certificate.X509CertificateStatus.VALID,
                ):
                try:
                    _ = cert.san
                    cert_with_san_found = True
                except cryptography.x509.extensions.ExtensionNotFound:
                    old_certs.append(cert)
                    continue

            if not cert_with_san_found:
                print(f"Certificate(s) for node {node.name} is missing SANs, generating a new one...")
                new_cert = X509Certificate(name=node.name, cn=node.name)
                # Cert is written on all nodes after this function
                if new_cert.gen_cert():
                    cert = new_cert.cert
                    key = new_cert.key
                    bundle = cert + key

                    print("Writing new cert as default...")

                    with open("/var/db/pki/node.cert", "w") as f:
                        print("Writing node.cert...")
                        f.write(cert)
                    os.chmod("/var/db/pki/node.cert", 440)
                    os.chown(
                        "/var/db/pki/node.cert",
                        getpwnam("root").pw_uid,
                        getgrnam("vlt-conf").gr_gid
                    )

                    with open("/var/db/pki/node.key", "w") as f:
                        print("Writing node.key...")
                        f.write(key)
                    os.chmod("/var/db/pki/node.key", 440)
                    os.chown(
                        "/var/db/pki/node.key",
                        getpwnam("root").pw_uid,
                        getgrnam("vlt-conf").gr_gid
                    )

                    with open("/var/db/pki/node.pem", "w") as f:
                        print("Writing node.pem...")
                        f.write(bundle)
                    os.chmod("/var/db/pki/node.pem", 440)
                    os.chown(
                        "/var/db/pki/node.pem",
                        getpwnam("root").pw_uid,
                        getgrnam("vlt-conf").gr_gid
                    )

                    print("writing done")

                    haproxy_service = HaproxyService()
                    if haproxy_service.process_is_running():
                        print("Reloading Haproxy...")
                        try:
                            haproxy_service.restart()
                        except Exception as e:
                            print(f"Error while restarting haproxy: {e}")
                    for name, jail in [("mongodb", ""), ("nginx", "apache"), ("gunicorn", "apache"), ("gunicorn", "portal")]:
                        print(f"Reloading {name}...")
                        service = Service(name, jail)
                        if service.process_is_running():
                            try:
                                service.restart()
                            except Exception as e:
                                print(f"Error while restarting {name}: {e}")

                    for cert in old_certs:
                        print(f"Revoking old {cert} certificate")
                        cert.revoke()

        except Exception as e:
            print(f"Failed to regenerate certificates: {e}")
            print("Please relaunch this script after solving the issue.")

        print("Done.")
