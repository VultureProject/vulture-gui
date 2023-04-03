#!/home/vlt-os/env/bin/python
"""This file is part of Vulture OS.

Vulture OS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture OS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture OS.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Jobs related to PKI'

from system.pki.models import X509Certificate
from system.cluster.models import Cluster
from cryptography import x509
import subprocess
import os.path


def update_crl():
    """
    :return: Update internal vulture's CRL
    """
    if Cluster.get_current_node().is_master_mongo:
        for cert in X509Certificate.objects.filter(status='V'):
            cert.gen_crl()

    return True


def acme_update():
    """
    :return: Run acme.sh to automatically renew Let's encrypt certificates
    """
    subprocess.check_output(["/usr/local/sbin/acme.sh", "--cron", "--home", "/var/db/acme/.acme.sh"])

    """ Now update certificate database"""
    need_restart = False
    for cert in X509Certificate.objects.filter(is_vulture_ca=False, is_external=True):
        crypto_cert = x509.load_pem_x509_certificate(cert.cert.encode())
        subject = crypto_cert.subject
        common_name_obj = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]
        cn = common_name_obj.value
        if os.path.isfile("/var/db/acme/.acme.sh/{}/{}.cer".format(cn, cn)):
            with open("/var/db/acme/.acme.sh/{}/{}.cer".format(cn, cn)) as file_cert:
                pem_cert = file_cert.read()
                cert.cert = pem_cert
                cert.save()

                """ Update cert on cluster """
                cert.save_conf()
                need_restart = True

    if need_restart:
        Cluster.api_request("services.haproxy.haproxy.reload_service")
