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

from django.utils.crypto import get_random_string
import subprocess
import os
import sys

sys.path.append("/home/vlt-os/vulture_os/")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')


from toolkit.system.x509 import mk_ca_cert_files, mk_signed_cert_files


if __name__ == "__main__":

    pki = {
        "country": "FR",
        "state": "59",
        "city": "Lille",
        "organization": "VultureProject.ORG",
        "organizational_unit": "Internal PKI"
    }

    """ Nothing to do if PKI is already set up """
    if os.path.isfile("/var/db/pki/ca.key"):
        print("Warning: CA certificate already exists... ignoring CA creation")
        try:
            with open("/var/db/pki/ca.pem", "rb") as cert_file:
                cacert_pem = cert_file.read()
        except Exception as e:
            print(f"Could not read CA certificate: {e}")
        try:
            with open("/var/db/pki/ca.key", "rb") as key_file:
                cakey_pem = key_file.read()
        except Exception as e:
            print(f"Could not read CA key: {e}")

    else:

        """ Build CA Certificate """
        print("Creating CA certificate and private key")
        ca_name = "Vulture_PKI_" + get_random_string(16, 'abcdef0123456789')
        cacert_pem, cakey_pem = mk_ca_cert_files(
            ca_name,
            pki["country"],
            pki["state"],
            pki["city"],
            pki["organization"],
            pki["organizational_unit"]
        )

    """ Build node certificate (overwrite if it exist) """
    hostname = subprocess.check_output(['hostname']).strip().decode('utf-8')
    # TODO give ca_cert and ca_key
    _, _ = mk_signed_cert_files(
        hostname,
        pki["country"],
        pki["state"],
        pki["city"],
        pki["organization"],
        pki["organizational_unit"],
        2,
        cacert_pem,
        cakey_pem
    )

    """ Generate Diffie hellman configuration """
    os.system("openssl dhparam -out /var/db/pki/dh2048.pem 2048")

    os.system("chown root:vlt-conf /var/db/pki/*")
    os.system("chmod 440 /var/db/pki/*")
