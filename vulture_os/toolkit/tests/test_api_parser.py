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
__doc__ = 'Tests for the main ApiParser class in api_parser'

import secrets
import signal
import string

from django.test import TestCase
from django.utils import timezone
from unittest.mock import patch, Mock
from threading import current_thread, main_thread

from services.frontend.models import Frontend
from system.config.models import Config
from system.pki.models import X509Certificate
from system.tenants.models import Tenants
from toolkit.api_parser.api_parser import ApiParser
from toolkit.network.network import JAIL_ADDRESSES
from toolkit.system.x509 import mk_ca_cert_files, mk_signed_cert_files
from vulture_os.settings import REDISIP, REDISPORT


class ApiParserTestCase(TestCase):
    TEST_CASE_NAME=f"{__name__}"
    def setUp(self):
        # Prevent logger from printing logs to stdout during tests
        self.logger_patcher = patch('toolkit.api_parser.api_parser.logger')
        self.logger_patcher.start()
        self.timetest = timezone.now()

        self.config = Config.objects.create(
            redis_password=''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(15)),
        )

        self.tenant = Tenants.objects.create(
            name=f"tenant_test_{self.TEST_CASE_NAME}",
        )

        self.frontend = Frontend.objects.create(
            name=f"frontend_test_{self.TEST_CASE_NAME}",
            mode="log",
            listening_mode="api",
            api_parser_type="",
            api_parser_use_proxy=False,
            api_parser_custom_proxy="",
            api_parser_verify_ssl=True,
            api_parser_custom_certificate=None,
            tenants_config=self.tenant,
            last_api_call=self.timetest,
            last_collected_timestamps={
                "test_timestamp_1": self.timetest.isoformat()
            }
        )

        cacert_pem, cakey_pem = mk_ca_cert_files(
            "Vulture_PKI_" + ''.join(secrets.choice('abcdef0123456789') for i in range(16)),
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

        return super().setUp()


    def tearDown(self) -> None:
        # Cleanly remove the logger patch
        self.logger_patcher.stop()
        return super().tearDown()


##################
# CREATION TESTS #
##################
    @patch.object(ApiParser, 'connect')
    def test_creation_connect_called(self, mocked_connect):
        _ = ApiParser(self.frontend.to_dict())

        mocked_connect.assert_called()


    @patch('socket.socket')
    def test_creation_redis_settings_set(self, _):
        collector = ApiParser(self.frontend.to_dict())

        self.assertIsNotNone(collector.redis_cli)
        self.assertEqual(collector.redis_cli.node, REDISIP)
        self.assertEqual(collector.redis_cli.port, REDISPORT)
        self.assertEqual(collector.redis_cli.password, self.config.redis_password)


    @patch('socket.socket')
    def test_creation_no_custom_certificate(self, _):
        collector = ApiParser(self.frontend.to_dict())

        self.assertTrue(collector.api_parser_verify_ssl)
        self.assertIsNone(collector.api_parser_custom_certificate)


    @patch('socket.socket')
    def test_creation_with_custom_certificate(self, _):
        self.frontend.api_parser_custom_certificate = self.node_cert
        collector = ApiParser(self.frontend.to_dict())

        self.assertTrue(collector.api_parser_verify_ssl)
        self.assertEqual(collector.api_parser_custom_certificate, self.node_cert.bundle_filename)


    @patch('socket.socket')
    def test_creation_no_verify_ssl(self, _):
        self.frontend.api_parser_verify_ssl = False
        self.frontend.api_parser_custom_certificate = self.node_cert # This certificate should not be set in the collector
        collector = ApiParser(self.frontend.to_dict())

        self.assertFalse(collector.api_parser_verify_ssl)
        self.assertIsNone(collector.api_parser_custom_certificate)


    @patch('socket.socket')
    def test_creation_frontend_info(self, _):
        collector = ApiParser(self.frontend.to_dict())

        self.assertIsNotNone(collector.frontend)
        self.assertEqual(collector.frontend.pk, self.frontend.pk)


    @patch('socket.socket')
    def test_creation_no_frontend(self, _):
        data = self.frontend.to_dict()
        del data['id']

        # should not raise
        collector = ApiParser(data)
        self.assertIsNone(collector.frontend)


    @patch('socket.socket')
    def test_creation_converted_last_collected_timestamps(self, _):
        collector = ApiParser(self.frontend.to_dict())

        self.assertDictEqual(
            {"test_timestamp_1": self.timetest},
            collector.last_collected_timestamps
        )
        for _, timestamp_value in collector.last_collected_timestamps.items():
            self.assertIsInstance(timestamp_value, timezone.datetime)
            self.assertEqual(timestamp_value.tzinfo, timezone.utc)


    @patch('socket.socket')
    def test_creation_redis_key_name(self, _):
        collector = ApiParser(self.frontend.to_dict())

        self.assertEqual(collector.key_redis, f"api_parser_{self.frontend.pk}_running")


    @patch.object(ApiParser, 'get_system_proxy')
    @patch('socket.socket')
    def test_creation_use_proxy_system(self, _, mocked_get_system_proxy):
        self.frontend.api_parser_use_proxy = True
        self.frontend.api_parser_custom_proxy = False
        proxy = {
            'http_proxy': 'http://test:3128',
            'https_proxy': 'http://test:3128',
            'ftp_proxy': 'http://test:3128',
        }
        # get_system_proxy() is not tested here, see below for its unit test
        mocked_get_system_proxy.return_value = proxy
        collector = ApiParser(self.frontend.to_dict())

        mocked_get_system_proxy.assert_called()
        self.assertDictEqual(
            proxy,
            collector.proxies
        )


    @patch.object(ApiParser, 'get_custom_proxy')
    @patch('socket.socket')
    def test_creation_use_proxy_custom(self, _, mocked_get_custom_proxy):
        custom_proxy = "http://test:3128"
        self.frontend.api_parser_use_proxy = True
        self.frontend.api_parser_custom_proxy = custom_proxy
        proxy_result = {
            'http_proxy': custom_proxy,
            'https_proxy': custom_proxy,
            'ftp_proxy': custom_proxy,
        }
        # get_system_proxy() is not tested here, see below for its unit test
        mocked_get_custom_proxy.return_value = proxy_result

        collector = ApiParser(self.frontend.to_dict())

        mocked_get_custom_proxy.assert_called()
        self.assertDictEqual(
            proxy_result,
            collector.proxies
        )


#################
# METHODS TESTS #
#################
    @patch('socket.socket')
    def test_connect(self, mocked_socket):
        collector = ApiParser(self.frontend.to_dict())
        collector.connect()

        mocked_socket.assert_called()
        self.assertIsInstance(collector.socket, Mock)
        collector.socket.connect.assert_called_with((JAIL_ADDRESSES['rsyslog']['inet'], self.frontend.api_rsyslog_port))


    @patch('socket.socket')
    def test_connect_no_frontend(self, mocked_socket):
        data = self.frontend.to_dict()
        # No frontend object will be set
        del data['id']

        collector = ApiParser(data)
        collector.connect()

        mocked_socket.assert_not_called()
        self.assertIsNone(collector.socket)


    @patch('socket.socket')
    def test_connect_handles_exceptions(self, mocked_socket):
        collector = ApiParser(self.frontend.to_dict())
        mocked_socket.side_effect = Exception('failed')

        self.assertFalse(collector.connect())


    @patch('toolkit.api_parser.api_parser.get_proxy')
    @patch('socket.socket')
    def test_get_system_proxy(self, _, mocked_get_proxy):
        proxy = {
            'http_proxy': 'http://test:3128',
            'https_proxy': 'http://test:3128',
            'ftp_proxy': 'http://test:3128',
        }
        mocked_get_proxy.return_value = proxy

        collector = ApiParser(self.frontend.to_dict())

        self.assertDictEqual(
            proxy,
            collector.get_system_proxy(),
        )
        mocked_get_proxy.assert_called()


    @patch('toolkit.api_parser.api_parser.get_proxy')
    @patch('socket.socket')
    def test_get_system_proxy_no_proxy(self, _, mocked_get_proxy):
        proxy = {}
        mocked_get_proxy.return_value = proxy

        collector = ApiParser(self.frontend.to_dict())

        self.assertIsNone(collector.get_system_proxy())
        mocked_get_proxy.assert_called()


    @patch('socket.socket')
    def test_get_custom_proxy(self, _):
        data = self.frontend.to_dict()
        test_proxy = 'http://test:3128'
        data['api_parser_custom_proxy'] = test_proxy
        collector = ApiParser(data)

        self.assertDictEqual(
            {
                'http': test_proxy,
                'https': test_proxy,
                'ftp': test_proxy,
            },
            collector.get_custom_proxy()
        )


    @patch('socket.socket')
    def test_get_custom_proxy_no_proxy(self, _):
        data = self.frontend.to_dict()
        data['api_parser_custom_proxy'] = None
        collector = ApiParser(data)

        self.assertDictEqual(
            {},
            collector.get_custom_proxy()
        )


    @patch('socket.socket')
    def test_can_run_no_key(self, _):
        collector = ApiParser(self.frontend.to_dict())
        collector.redis_cli = Mock()
        collector.redis_cli.redis.get.return_value = False

        self.assertTrue(collector.can_run())
        collector.redis_cli.redis.get.assert_called()
        collector.redis_cli.redis.setex.assert_called_with(collector.key_redis, 300, 1)


    @patch('socket.socket')
    def test_can_run_key_exists(self, _):
        collector = ApiParser(self.frontend.to_dict())
        collector.redis_cli = Mock()
        collector.redis_cli.redis.get.return_value = True

        self.assertFalse(collector.can_run())
        collector.redis_cli.redis.get.assert_called()
        collector.redis_cli.redis.setex.assert_not_called()


    @patch('socket.socket')
    def test_can_run_redis_error(self, _):
        from redis import ReadOnlyError
        collector = ApiParser(self.frontend.to_dict())
        collector.redis_cli = Mock()
        collector.redis_cli.redis.get.return_value = False
        collector.redis_cli.redis.setex.side_effect = ReadOnlyError('failed')

        self.assertFalse(collector.can_run())


    @patch('socket.socket')
    def test_update_lock(self, _):
        collector = ApiParser(self.frontend.to_dict())
        collector.redis_cli = Mock()

        collector.update_lock()
        collector.redis_cli.redis.setex.ensure_called_with(collector.key_redis, 300, 1)


    @patch('socket.socket')
    def test_write_to_file_no_lines(self, _):
        collector = ApiParser(self.frontend.to_dict())
        collector.socket = Mock()

        collector.write_to_file([])
        collector.socket.ensure_not_called()


    @patch('socket.socket')
    def test_write_to_file_several_lines(self, _):
        lines = [
            "This is a test line",
            "This is a second test line with a carriage return \n",
            "This is a third test line, encoded",
        ]
        collector = ApiParser(self.frontend.to_dict())
        collector.socket = Mock()
        collector.update_lock = Mock()

        collector.write_to_file(lines)
        collector.update_lock.assert_called_once()
        for line in lines:
            collector.socket.sendall.assert_any_call(f"{line}\n".encode('utf8'))
        self.assertEqual(collector.socket.sendall.call_count, 3)


    @patch('socket.socket')
    def test_write_to_file_more_than_500_lines(self, _):
        lines = [f"This is test line number {i}" for i in range(501)]
        collector = ApiParser(self.frontend.to_dict())
        collector.socket = Mock()
        collector.update_lock = Mock()

        collector.write_to_file(lines)
        self.assertEqual(collector.update_lock.call_count, 2)
        self.assertEqual(collector.socket.sendall.call_count, len(lines))


    @patch('socket.socket')
    @patch('signal.signal')
    def test__handle_stop(self, mocked_signal, _):
        collector = ApiParser(self.frontend.to_dict())

        self.assertIsNotNone(collector.evt_stop)
        self.assertFalse(collector.evt_stop.is_set(), "evt_stop should not be set by default")

        if current_thread() is main_thread():
            mocked_signal.assert_called()

        collector._handle_stop(signal.SIGINT, None)

        self.assertTrue(collector.evt_stop.is_set(), "After call to _handle_stop(), evt_stop attribute should be set")


    @patch('socket.socket')
    def test_finish_deletes_redis_key(self, _):
        collector = ApiParser(self.frontend.to_dict())
        collector.redis_cli = Mock()

        collector.finish()
        collector.redis_cli.redis.delete.assert_called_once()
        collector.redis_cli.redis.delete.assert_called_with(collector.key_redis)


    @patch('socket.socket')
    def test_finish_updates_last_collected_timestamps(self, _):
        timenow = timezone.now()
        collector = ApiParser(self.frontend.to_dict())
        collector.redis_cli = Mock()
        collector.last_collected_timestamps = {
            "test_timestamp_1" : timenow
        }


        self.assertDictEqual(
            {
                'test_timestamp_1': self.timetest.isoformat()
            },
            self.frontend.last_collected_timestamps,
        )
        collector.finish()
        collector.redis_cli.redis.delete.assert_called_once()
        collector.redis_cli.redis.delete.assert_called_with(collector.key_redis)
        self.frontend.refresh_from_db()
        self.assertDictEqual(
            {
                'test_timestamp_1': timenow.isoformat()
            },
            self.frontend.last_collected_timestamps,
        )


####################
# BEHAVIOURS TESTS #
####################
    @patch('socket.socket')
    def test_finish_only_updates_frontend_last_collected_timestamps(self, _):
        timenow = timezone.now()
        self.assertListEqual(self.frontend.tags, [], "prerequisite failed: Frontend already has tags, please check tests!")
        collector = ApiParser(self.frontend.to_dict())
        collector.redis_cli = Mock()
        collector.last_collected_timestamps = {
            "test_timestamp_1" : timenow
        }

        # Add tags to frontend object while collector is 'running'
        self.frontend.tags = [1, 2, 3]
        self.frontend.save()

        # Collector is stopping, and updated frontend attributes
        collector.finish()
        self.frontend.refresh_from_db()

        # tags should still be there
        self.assertListEqual(self.frontend.tags, [1, 2, 3], "Frontend changes were overriden by collector!")
