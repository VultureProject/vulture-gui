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

__author__ = "Fabien Amelinck"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Tests for Portal'

from django.http import HttpResponse
from django.test import TestCase, Client
from authentication.user_portal.models import get_random_cookie_name
from portal.views.responses import set_portal_cookie, split_domain
from unittest.mock import patch
from uuid import uuid4

class TestSetPortalCookie(TestCase):
    TEST_CASE_NAME=f"{__name__}"
    def setUp(self):
        from applications.backend.models import Backend, Server
        from authentication.openid.form import OpenIDRepositoryForm
        from authentication.portal_template.models import PortalTemplate
        from authentication.user_portal.form import UserAuthenticationForm
        from services.frontend.models import Frontend, Listener
        from system.cluster.models import Config, Node, NetworkAddress, NetworkInterfaceCard, NetworkAddressNIC
        from workflow.models import Workflow

        self.global_config = Config.objects.create(
            portal_cookie_name=get_random_cookie_name()
        )
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
        self.frontend_http = Frontend.objects.create(
            name=f"frontend_http_test_{self.TEST_CASE_NAME}",
            mode="http",
        )
        self.listener_http = Listener.objects.create(
            network_address=self.netaddr,
            port=80,
            frontend=self.frontend_http,
        )
        self.backend_http = Backend.objects.create(
            name=f"backend_http_test_{self.TEST_CASE_NAME}",
            mode="http",
        )
        self.serv_http = Server.objects.create(
            mode="net",
            target="10.10.10.10",
            port=443,
            backend=self.backend_http,
        )
        repo_form = OpenIDRepositoryForm({
            'name': f"openid_test_{self.TEST_CASE_NAME}",
            'provider': 'openid',
            'provider_url': 'https://openid.example.com',
            'client_id': uuid4(),
            'client_secret': uuid4(),
            'scopes': ['openid']
        })
        self.openid = repo_form.save()
        self.portal_template = PortalTemplate.objects.create(
            name=f"portal_template_test_{self.TEST_CASE_NAME}",
        )
        portal_form = UserAuthenticationForm({
            'name': f"portal_with_openid_test_{self.TEST_CASE_NAME}",
            'auth_type': 'form',
            'lookup_ldap_attr': 'cn',
            'lookup_claim_attr': 'username',
            'auth_timeout': 900,
            'disconnect_url': 'test/disconnect',
            # 'enable_external': True,
            # 'external_listener': self.frontend_http,
            'external_fqdn': 'openid.example.com',
            'auth_cookie_name': get_random_cookie_name(),
            'portal_template': self.portal_template,
            'oauth_client_id': self.openid.client_id,
            'oauth_client_secret': self.openid.client_secret,
            'oauth_redirect_uris': f'https://www.example.com/oauth2/callback/{self.openid.id_alea}',
            'oauth_timeout': 600,
            'repositories': [self.openid.pk]
        })
        self.portal = portal_form.save()
        self.workflow = Workflow.objects.create(
            name=f"workflow_http_test_{self.TEST_CASE_NAME}",
            frontend=self.frontend_http,
            backend=self.backend_http,
            fqdn="www.example.com",
            public_dir="/",
            authentication=self.portal,
        )


    def test_split_domain(self):
        url = "https://example.com"
        url2 = "http://test.example.com"
        url3 = "https://test.example.com:8000"
        fqdn = "sub.test.example.com:443"

        self.assertEqual(split_domain(url), ".example.com")
        self.assertEqual(split_domain(url2), ".example.com")
        self.assertEqual(split_domain(url3), ".example.com")
        self.assertEqual(split_domain(fqdn), ".test.example.com")


    def test_set_portal_cookie(self):
        response = HttpResponse()
        cookie_name = get_random_cookie_name()
        cookie_value = "test_value"
        url = "http://example.com"
        set_portal_cookie(response, cookie_name, cookie_value, url)

        self.assertIsNotNone(response.cookies)
        cookie = response.cookies[cookie_name]

        self.assertEqual(cookie.value, cookie_value)
        self.assertEqual(cookie["domain"], ".example.com")
        self.assertEqual(cookie["httponly"], True)
        self.assertEqual(cookie["secure"], "")
        self.assertEqual(cookie["samesite"], "Lax")


    def test_set_portal_cookie_https(self):
        response = HttpResponse()
        url = "https://example.com"
        set_portal_cookie(response, "test_cookie", "test_value", url)

        self.assertIsNotNone(response.cookies)
        cookie = response.cookies["test_cookie"]
        self.assertEqual(cookie["secure"], True)


    def test_set_portal_cookie_regressions(self):
        response1 = HttpResponse()
        response2 = HttpResponse()
        cookie_name = get_random_cookie_name()
        cookie_value = "test_value"
        scheme = "https" if self.frontend_http.has_tls() else "http"
        fqdn = self.workflow.fqdn

        response1.set_cookie(cookie_name, cookie_value, domain=split_domain(fqdn), httponly=True, secure=scheme=="https", samesite="Lax")
        set_portal_cookie(response2, cookie_name, cookie_value, f"{scheme}://{fqdn}")

        self.assertIsNotNone(response1.cookies)
        self.assertIsNotNone(response2.cookies)
        self.assertEqual(response1.cookies[cookie_name].value, response2.cookies[cookie_name].value)
        self.assertEqual(response1.cookies[cookie_name]["domain"], response2.cookies[cookie_name]["domain"])
        self.assertEqual(response1.cookies[cookie_name]["httponly"], response2.cookies[cookie_name]["httponly"])
        self.assertEqual(response1.cookies[cookie_name]["secure"], response2.cookies[cookie_name]["secure"])
        self.assertEqual(response1.cookies[cookie_name]["samesite"], response2.cookies[cookie_name]["samesite"])


    @patch('portal.system.redis_sessions.REDISPortalSession.delete_key')
    @patch('portal.system.redis_sessions.Redis.execute_command')
    def test_portal_url(self, mocked_execute_command, mocked_write_in_redis):
        mocked_execute_command.return_value = {}
        mocked_write_in_redis.return_value = True
        cookie_name = self.global_config.portal_cookie_name

        c = Client(headers={"host": self.workflow.fqdn, "x-forwarded-proto": "https"})
        response = c.get(f"/portal/{self.workflow.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.cookies)
        self.assertIn(cookie_name, response.cookies.keys())
        self.assertEqual(response.cookies[cookie_name]["domain"], split_domain(self.workflow.fqdn))
        self.assertEqual(response.cookies[cookie_name]["httponly"], True)
        self.assertEqual(response.cookies[cookie_name]["secure"], True)
        self.assertEqual(response.cookies[cookie_name]["samesite"], "Lax")


    def test_retrieve_start_url_from_portal(self):
        repo = self.workflow.authentication.repositories.first()
        scheme = "https" if self.frontend_http.has_tls() else "http"
        fqdn = self.workflow.fqdn
        port = self.workflow.frontend.listener_set.first().port

        auth_start_url = self.workflow.authentication.get_openid_start_url(
            req_scheme=scheme,
            workflow_host=f"{fqdn}:{port}" if port not in (443, 80) else fqdn,
            workflow_path=self.workflow.public_dir,
            repo_id=repo.id
        )

        self.assertEqual(auth_start_url, f"{scheme}://{fqdn}/oauth2/start/?repo={repo.id}")


    def test_retrieve_start_url_from_repo(self):
        self.assertIsNot(self.workflow.authentication.openid_repos, [])
        repo = self.workflow.authentication.openid_repos[0]
        scheme = "https" if self.frontend_http.has_tls() else "http"
        fqdn = self.workflow.fqdn

        self.assertEqual(f"{scheme}://{fqdn}/{self.openid.start_url}", f"{scheme}://{fqdn}/oauth2/start?repo={repo.id}")


    @patch('portal.system.redis_sessions.REDISPortalSession.write_in_redis')
    @patch('portal.system.redis_sessions.Redis.execute_command')
    @patch('portal.views.logon.OpenIDRepository.retrieve_config')
    def test_start_url(self, mocked_retrieve_config, mocked_execute_command, mocked_write_in_redis):
        mocked_execute_command.return_value = {}
        mocked_write_in_redis.return_value = True

        self.assertIsNot(self.workflow.authentication.openid_repos, [])
        repo = self.workflow.authentication.openid_repos[0]
        scheme = "https" # Forced to https due to InsecureTransportError
        fqdn = self.workflow.fqdn
        cookie_name = self.global_config.portal_cookie_name
        mocked_retrieve_config.return_value = self.portal.generate_openid_config(f"{scheme}://{fqdn}")

        c = Client(headers={"host": self.workflow.fqdn, "x-forwarded-proto": "https"})
        response = c.get(f"/portal/{self.workflow.id}/oauth2/start/{repo.id}?repo={repo.id}")
        self.assertEqual(response.status_code, 302)
        self.assertIsNotNone(response.cookies)
        self.assertIn(cookie_name, response.cookies.keys())
        self.assertEqual(response.cookies[cookie_name]["domain"], split_domain(fqdn))
        self.assertEqual(response.cookies[cookie_name]["httponly"], True)
        self.assertEqual(response.cookies[cookie_name]["secure"], True)
        self.assertEqual(response.cookies[cookie_name]["samesite"], "Lax")


    @patch('portal.system.redis_sessions.Redis.execute_command')
    @patch('portal.views.logon.OpenIDRepository.retrieve_config')
    def test_authorize_url(self, mocked_retrieve_config, mocked_execute_command):
        mocked_execute_command.return_value = {}

        self.assertIsNot(self.workflow.authentication.openid_repos, [])
        repo = self.workflow.authentication.openid_repos[0]
        scheme = "https" # Forced to https due to InsecureTransportError
        fqdn = self.workflow.fqdn
        cookie_name = self.global_config.portal_cookie_name

        callback_url = self.workflow.authentication.get_openid_callback_url(scheme, fqdn, self.workflow.public_dir, repo.id_alea)
        oauth2_session = repo.get_oauth2_session(callback_url)

        mocked_retrieve_config.return_value = self.portal.generate_openid_config(f"{scheme}://{fqdn}")
        authorization_url, state = repo.get_authorization_url(oauth2_session)

        c = Client(headers={"x-forwarded-proto": "https"})
        response = c.get(f"/portal/portal_{self.workflow.id}/oauth2/{authorization_url.split('oauth2/')[1]}")
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.cookies)
        self.assertIn(cookie_name, response.cookies.keys())
        self.assertEqual(response.cookies[cookie_name]["domain"], split_domain(fqdn))
        self.assertEqual(response.cookies[cookie_name]["httponly"], True)
        self.assertEqual(response.cookies[cookie_name]["secure"], True)
        self.assertEqual(response.cookies[cookie_name]["samesite"], "Lax")
