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

__author__ = "Théo BERTIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Tests for Workflows'

from django.test import TestCase
from django.utils.crypto import get_random_string
from workflow.models import Workflow

from uuid import uuid4

class WorkflowTestCase(TestCase):
    TEST_CASE_NAME=f"{__name__}"
    def setUp(self):
        from services.frontend.models import Frontend, Listener
        from system.cluster.models import NetworkAddress, NetworkInterfaceCard, NetworkAddressNIC
        from applications.backend.models import Backend, Server
        from authentication.user_portal.form import UserAuthenticationForm
        from authentication.openid.form import OpenIDRepositoryForm
        from system.pki.models import X509Certificate, TLSProfile
        from system.cluster.models import Node
        from toolkit.system.x509 import mk_ca_cert_files, mk_signed_cert_files

        self.node = Node.objects.create(
            name=f"node_test_{self.TEST_CASE_NAME}",
        )
        self.nic = NetworkInterfaceCard.objects.create(
            dev = "vtnet0",
            node=self.node,
        )
        self.netaddr = NetworkAddress.objects.create(
            name=f"network_address_test_{self.TEST_CASE_NAME}",
            type="alias",
            ip="127.127.127.127",
            prefix_or_netmask="24",
        )
        NetworkAddressNIC.objects.create(
            nic=self.nic,
            network_address=self.netaddr,
        )

        cacert_pem, cakey_pem = mk_ca_cert_files(
            "Vulture_PKI_" + get_random_string(16, 'abcdef0123456789'),
            "FR",
            "59",
            "Lille",
            "VultureProject.ORG",
            "Internal PKI"
        )
        cert_pem, key_pem = mk_signed_cert_files(
            "vulture-test",
            "FR",
            "59",
            "Lille",
            "VultureProject.ORG",
            "Internal PKI",
            2,
            cacert_pem,
            cakey_pem
        )

        self.node_cert = X509Certificate.objects.create(
            is_vulture_ca=False,
            is_ca=False,
            is_external=False,
            status='V',
            cert=cert_pem.decode(),
            key=key_pem.decode(),
            chain=cacert_pem.decode(),
            serial=1
        )
        self.tls_profile = TLSProfile.objects.create(
            name=f"tls_profile_test_{self.TEST_CASE_NAME}",
            x509_certificate=self.node_cert,

        )
        self.frontend_tcp = Frontend.objects.create(
            name=f"frontend_tcp_test_{self.TEST_CASE_NAME}",
            mode="tcp",
        )
        self.frontend_http = Frontend.objects.create(
            name=f"frontend_http_test_{self.TEST_CASE_NAME}",
            mode="http",
        )
        self.listener_tcp = Listener.objects.create(
            network_address=self.netaddr,
            port=1234,
            frontend=self.frontend_tcp
        )
        self.listener_http = Listener.objects.create(
            network_address=self.netaddr,
            port=80,
            frontend=self.frontend_http,
        )
        self.listener_https = Listener.objects.create(
            network_address=self.netaddr,
            port=443,
            frontend=self.frontend_http,
        )
        self.backend_tcp = Backend.objects.create(
            name=f"backend_tcp_test_{self.TEST_CASE_NAME}",
            mode="tcp",
        )
        self.backend_http = Backend.objects.create(
            name=f"backend_http_test_{self.TEST_CASE_NAME}",
            mode="http",
        )
        self.serv_tcp = Server.objects.create(
            mode="net",
            target="10.10.10.10",
            port=1234,
            backend=self.backend_tcp
        )
        self.serv_http = Server.objects.create(
            mode="net",
            target="10.10.10.10",
            port=443,
            backend=self.backend_http,
            tls_profile=self.tls_profile,
        )

        # Don't 
        repo_form = OpenIDRepositoryForm({
            'name': f"openid_test_{self.TEST_CASE_NAME}",
            'provider': 'openid',
            'provider_url': 'https://openid.test.fr',
            'client_id': uuid4(),
            'client_secret': uuid4(),
            'scopes': ['openid']
        })
        self.openid = repo_form.save()

        # Need to create through Form for djongo's f***ing ArrayReferenceField to work!
        portal_form = UserAuthenticationForm({
            'name': f"portal_with_openid_test_{self.TEST_CASE_NAME}",
            'auth_type': 'form',
            'lookup_ldap_attr': 'cn',
            'lookup_claim_attr': 'username',
            'auth_timeout': 900,
            'disconnect_url': 'test/disconnect',
            'external_fqdn': 'test',
            'oauth_client_id': uuid4(),
            'oauth_client_secret': uuid4(),
            'oauth_redirect_uris': 'https://www.test.fr',
            'oauth_timeout': 600,
            'repositories': [self.openid.pk]
        })
        self.portal = portal_form.save()


#######
# TCP #
#######
    def test_create_workflow_tcp(self):
        Workflow.objects.create(
            name=f"workflow_tcp_test_{self.TEST_CASE_NAME}",
            frontend=self.frontend_tcp,
            backend=self.backend_tcp,
        )

    def test_generate_workflow_tcp_conf(self):
        workflow = Workflow.objects.create(
            name=f"workflow_tcp_test_{self.TEST_CASE_NAME}",
            frontend=self.frontend_tcp,
            backend=self.backend_tcp,
        )
        self.assertIsNotNone(workflow)
        self.assertIsNotNone(workflow.generate_conf())

########
# HTTP #
########
    def test_create_workflow_http(self):
        Workflow.objects.create(
            name=f"workflow_http_test_{self.TEST_CASE_NAME}",
            frontend=self.frontend_http,
            backend=self.backend_http,
            fqdn="workflow.vulture.test",
            public_dir="/",
        )

    def test_generate_workflow_http_filename(self):
        workflow = Workflow.objects.create(
            name=f"workflow_http_test_{self.TEST_CASE_NAME}",
            frontend=self.frontend_http,
            backend=self.backend_http,
            fqdn="workflow.vulture.test",
            public_dir="/",
        )
        self.assertIsNotNone(workflow)
        self.assertIsInstance(workflow.get_filename(), str)
        self.assertIsNot(workflow.get_filename(), "")

    def test_generate_workflow_http_conf(self):
        workflow = Workflow.objects.create(
            name=f"workflow_http_test_{self.TEST_CASE_NAME}",
            frontend=self.frontend_http,
            backend=self.backend_http,
            fqdn="workflow.vulture.test",
            public_dir="/",
        )
        self.assertIsNotNone(workflow)
        self.assertIsNotNone(workflow.generate_conf())


#########################
# HTTP + AUTHENTICATION #
#########################
    def test_create_workflow_http_auth(self):
        workflow = Workflow.objects.create(
            name=f"workflow_http_auth_test_{self.TEST_CASE_NAME}",
            frontend=self.frontend_http,
            backend=self.backend_http,
            fqdn="workflow.vulture.test",
            public_dir="/",
            authentication=self.portal,
        )
        self.assertIsNotNone(workflow.authentication)

    def test_generate_workflow_http_auth_filename(self):
        workflow = Workflow.objects.create(
            name=f"workflow_http_auth_test_{self.TEST_CASE_NAME}",
            frontend=self.frontend_http,
            backend=self.backend_http,
            fqdn="workflow.vulture.test",
            public_dir="/",
            authentication=self.portal,
        )
        self.assertIsNotNone(workflow)
        self.assertIsInstance(workflow.get_filename(), str)
        self.assertIsNot(workflow.get_filename(), "")

    def test_generate_workflow_http_auth_conf(self):
        workflow = Workflow.objects.create(
            name=f"workflow_http_auth_test_{self.TEST_CASE_NAME}",
            frontend=self.frontend_http,
            backend=self.backend_http,
            fqdn="workflow.vulture.test",
            public_dir="/",
            authentication=self.portal,
        )
        self.assertIsNotNone(workflow)
        self.assertIsNotNone(workflow.to_template())
