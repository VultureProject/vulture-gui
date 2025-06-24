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

__author__ = "Fabien AMELINCK"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Tests for TLS Profile and X509 Certificates'

from django.test import TestCase
from cryptography.x509 import random_serial_number as x509_random_serial_number, load_pem_x509_certificate

from system.cluster.models import Node
from system.pki.models import X509Certificate, TLSProfile
from toolkit.system.x509 import mk_ca_cert_files, mk_signed_cert_files

class TLSProfileCase(TestCase):
    TEST_CASE_NAME=f"{__name__}"
    def setUp(self):
        # Prevent logger from printing logs to stdout during tests
        # self.logger_patcher = patch('system.cluster.models.logger')
        # self.logger_patcher.start()

        self.node = Node.objects.create(
            name=f"node_test_{self.TEST_CASE_NAME}"
        )

        self.cacert_pem, self.cakey_pem = mk_ca_cert_files(
            f"Vulture_PKI_{self.TEST_CASE_NAME}",
            "FR",
            "59",
            "Lille",
            "VultureProject.ORG",
            "Internal PKI"
        )

        self.cert_pem, self.key_pem = mk_signed_cert_files(
            self.node.name,
            "FR",
            "59",
            "Lille",
            "VultureProject.ORG",
            "Internal PKI",
            x509_random_serial_number(),
            self.cacert_pem,
            self.cakey_pem
        )

    def tearDown(self) -> None:
        # Cleanly remove the logger patch
        # self.logger_patcher.stop()
        return super().tearDown()

    def test_ca_generation(self):
        internal_ca = X509Certificate(
            is_vulture_ca=True,
            is_ca=True,
            is_external=False,
            status=X509Certificate.X509CertificateStatus.VALID,
            cert=self.cacert_pem.decode(),
            key=self.cakey_pem.decode(),
            serial=x509_random_serial_number()
        )

        ca_name = internal_ca.explose_dn()['CN']
        internal_ca.name = ca_name
        internal_ca.save()
        self.assertIsNotNone(internal_ca)

    def test_x509_certificates(self):
        node_cert = X509Certificate.objects.create(
            name=self.node.name,
            is_vulture_ca=False,
            is_ca=False,
            is_external=False,
            status=X509Certificate.X509CertificateStatus.VALID,
            cert=self.cert_pem.decode(),
            key=self.key_pem.decode(),
            chain=self.cacert_pem.decode(),
            serial=1
        )

        self.assertIsNotNone(self.cert_pem)
        self.assertIsNotNone(self.key_pem)
        self.assertIsNotNone(node_cert)

    def test_gen_cert(self):
        internal_ca = X509Certificate(
            is_vulture_ca=True,
            is_ca=True,
            is_external=False,
            status=X509Certificate.X509CertificateStatus.VALID,
            cert=self.cacert_pem.decode(),
            key=self.cakey_pem.decode(),
            serial=x509_random_serial_number()
        )
        internal_ca.name = internal_ca.explose_dn()['CN']
        internal_ca.save()

        node_cert = X509Certificate(name=self.node.name, cn=self.node.name)
        cert_json = node_cert.gen_cert()

        self.assertIsNotNone(cert_json['cert'])
        self.assertIsNotNone(cert_json['key'])
        self.assertEqual(node_cert.status, X509Certificate.X509CertificateStatus.VALID)
        self.assertFalse(node_cert.is_vulture_ca, False)
        self.assertFalse(node_cert.is_external, False)
        self.assertEqual(node_cert.chain, internal_ca.cert)

    def test_verify_cert(self):
        node_cert = X509Certificate.objects.create(
            name=self.node.name,
            cert=self.cert_pem.decode(),
            key=self.key_pem.decode(),
            chain=self.cacert_pem.decode()
        )
        cert_obj = load_pem_x509_certificate(data=node_cert.cert.encode())
        cacert_obj = load_pem_x509_certificate(data=node_cert.chain.encode())

        self.assertIsNone(cert_obj.verify_directly_issued_by(cacert_obj))

    def test_tls_profile(self):
        node_cert = X509Certificate.objects.create(
            name=self.node.name,
            status=X509Certificate.X509CertificateStatus.VALID
        )
        tls_profile = TLSProfile.objects.create(
            name=f"tls_profile_test_{self.TEST_CASE_NAME}",
            x509_certificate=node_cert
        )

        self.assertIsNotNone(tls_profile)
        tls_profiles = node_cert.certificate_of.all()
        self.assertNotEqual(list(tls_profiles), [])

    def test_node_get_certifiate(self):
        internal_ca = X509Certificate(
            is_vulture_ca=True,
            is_ca=True,
            is_external=False,
            status=X509Certificate.X509CertificateStatus.VALID,
            cert=self.cacert_pem.decode(),
            key=self.cakey_pem.decode(),
            serial=x509_random_serial_number()
        )
        internal_ca.name = internal_ca.explose_dn()['CN']
        internal_ca.save()

        X509Certificate.objects.create(
            name=self.node.name,
            status=X509Certificate.X509CertificateStatus.VALID,
            cert=self.cert_pem.decode(),
            key=self.key_pem.decode(),
            chain=self.cacert_pem.decode(),
        )
        node_cert = self.node.get_certificate()

        self.assertIsNotNone(node_cert)
        # self.assertIsNotNone(node_cert.logomelasticsearch_set.get())
        # self.assertIsNotNone(node_cert.logommongodb_set.get())
        # self.assertIsNotNone(node_cert.logomrelp_set.get())
