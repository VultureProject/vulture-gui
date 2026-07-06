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
__doc__ = 'Tests for LogOM App'

from django.test import TestCase
from unittest.mock import patch

from applications.logfwd.models import LogOM, LogOMFWD

class LogOMFWDTestCase(TestCase):
    TEST_CASE_NAME=f"{__name__}"

    def setUp(self):
        from services.frontend.models import Frontend, Listener
        from system.cluster.models import Node, NetworkAddress, NetworkInterfaceCard, NetworkAddressNIC
        from system.tenants.models import Tenants

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
        self.tenant = Tenants.objects.create(
            name=f"tenant_test_{self.TEST_CASE_NAME}"
        )
        self.logfwd = LogOMFWD.objects.create(
            name=f"syslog_forwarder_test_{self.TEST_CASE_NAME.replace('.','_')}",
            target="127.127.127.127",
            port=514,
            protocol="tcp",
            zip_level=6,
            compression_mode="stream:always",
            flush_on_txend=True,
        )
        self.frontend_log = Frontend.objects.create(
            name=f"frontend_log_test_{self.TEST_CASE_NAME}",
            mode="log",
            enabled=True,
            listening_mode="tcp",
            enable_logging=True,
            ruleset="raw_to_json",
            log_condition="{{" + self.logfwd.name + "}}",
            tenants_config=self.tenant
        )
        self.frontend_log.log_forwarders = LogOM.objects.filter(pk=self.logfwd.pk)
        self.frontend_log.save()
        self.listener_tcp = Listener.objects.create(
            network_address=self.netaddr,
            port=1234,
            frontend=self.frontend_log
        )

    def tearDown(self) -> None:
        return super().tearDown()

    @patch('applications.logfwd.form.logger')
    def test_invalid_compression_mode(self, logger_patcher):
        from applications.logfwd.form import LogOMFWDForm

        logfwd_form = LogOMFWDForm({
            'name': f"syslog_forwarder_invalid_compression_mode_test_{self.TEST_CASE_NAME}",
            'target': "127.127.127.127",
            'port': 514,
            'protocol': "tcp",
            'compression_mode': "toto"
        })
        self.assertFalse(logfwd_form.is_valid())

    @patch('applications.logfwd.form.logger')
    def test_invalid_zip_level(self, logger_patcher):
        from applications.logfwd.form import LogOMFWDForm

        logfwd_form = LogOMFWDForm({
            'name': f"syslog_forwarder_invalid_zip_level_test_{self.TEST_CASE_NAME}",
            'target': "127.127.127.127",
            'port': 514,
            'protocol': "tcp",
            'zip_level': -10
        })
        self.assertFalse(logfwd_form.is_valid())

    @patch('applications.logfwd.form.logger')
    def test_invalid_flush_on_txend(self, logger_patcher):
        from applications.logfwd.form import LogOMFWDForm

        logfwd_form = LogOMFWDForm({
            'name': f"syslog_forwarder_invalid_flush_on_txend_test_{self.TEST_CASE_NAME}",
            'target': "127.127.127.127",
            'port': 514,
            'protocol': "tcp",
            'flush_on_txend': "on"
        })
        self.assertFalse(logfwd_form.is_valid())

    def test_present_settings(self):
        logfwd_rsyslog_config = LogOM.generate_conf(self.logfwd, "raw_to_json", frontend="dummy")

        self.assertIn('compression.mode="stream:always"', logfwd_rsyslog_config)
        self.assertIn('ZipLevel="6"', logfwd_rsyslog_config)
        self.assertIn('compression.stream.flushOnTXEnd="on"', logfwd_rsyslog_config)

    def test_flushontxend_absence(self):
        self.logfwd_single_compression = LogOMFWD.objects.create(
            name=f"syslog_forwarder_flushontxend_absence_test_{self.TEST_CASE_NAME.replace('.','_')}",
            target="127.127.127.127",
            port=514,
            protocol="tcp",
            zip_level=6,
            compression_mode="single",
            flush_on_txend=False,
        )
        logfwd_rsyslog_config = LogOM.generate_conf(self.logfwd_single_compression, "raw_to_json", frontend="dummy")

        self.assertIn('compression.mode="single"', logfwd_rsyslog_config)
        self.assertNotIn('compression.stream.flushOnTXEnd', logfwd_rsyslog_config)

    def test_flushontxend_on(self):
        self.logfwd_flushontxend_on = LogOMFWD.objects.create(
            name=f"syslog_forwarder_flushontxend_on_test_{self.TEST_CASE_NAME.replace('.','_')}",
            target="127.127.127.127",
            port=514,
            protocol="tcp",
            zip_level=6,
            compression_mode="stream:always",
            flush_on_txend=True,
        )
        logfwd_rsyslog_config = LogOM.generate_conf(self.logfwd_flushontxend_on, "raw_to_json", frontend="dummy")

        self.assertIn('compression.mode="stream:always"', logfwd_rsyslog_config)
        self.assertIn('compression.stream.flushOnTXEnd="on"', logfwd_rsyslog_config)

    def test_flushontxend_off(self):
        self.logfwd_flushontxend_off = LogOMFWD.objects.create(
            name=f"syslog_forwarder_flushontxend_off_test_{self.TEST_CASE_NAME.replace('.','_')}",
            target="127.127.127.127",
            port=514,
            protocol="tcp",
            zip_level=6,
            compression_mode="stream:always",
            flush_on_txend=False,
        )
        logfwd_rsyslog_config = LogOM.generate_conf(self.logfwd_flushontxend_off, "raw_to_json", frontend="dummy")

        self.assertIn('compression.mode="stream:always"', logfwd_rsyslog_config)
        self.assertIn('compression.stream.flushOnTXEnd="off"', logfwd_rsyslog_config)

    @patch('services.frontend.models.logger')
    def test_absent_settings(self, logger_patcher):
        from services.frontend.models import Frontend, Listener

        self.logfwd_uncompressed = LogOMFWD.objects.create(
            name=f"syslog_forwarder_uncompressed_test_{self.TEST_CASE_NAME.replace('.','_')}",
            target="127.127.127.127",
            port=514,
            protocol="tcp",
            compression_mode="none"
        )
        self.frontend_log_uncompressed = Frontend.objects.create(
            name=f"frontend_log_uncompressed_test_{self.TEST_CASE_NAME}",
            mode="log",
            enabled=True,
            listening_mode="tcp",
            enable_logging=True,
            ruleset="raw_to_json",
            log_condition="{{" + self.logfwd_uncompressed.name + "}}",
            tenants_config=self.tenant
        )
        self.frontend_log_uncompressed.log_forwarders = LogOM.objects.filter(pk=self.logfwd_uncompressed.pk)
        self.frontend_log_uncompressed.save()
        self.listener_tcp_uncompressed = Listener.objects.create(
            network_address=self.netaddr,
            port=1235,
            frontend=self.frontend_log_uncompressed
        )

        logfwd_rsyslog_config = self.frontend_log_uncompressed.render_log_condition()

        self.assertNotIn("compression.mode", logfwd_rsyslog_config)
        self.assertNotIn("ZipLevel", logfwd_rsyslog_config)
        self.assertNotIn("compression.stream.flushOnTXEnd", logfwd_rsyslog_config)

    @patch('services.frontend.models.logger')
    @patch('applications.logfwd.models.LogOM.generate_conf')
    def test_render_log_condition(self, patched_render_log_condition, logger_patcher):
        patched_render_log_condition.return_value = (True, "Success")
        self.frontend_log.render_log_condition()
        patched_render_log_condition.assert_called()

    @patch('system.cluster.models.logger')
    @patch('services.frontend.models.logger')
    @patch('applications.logfwd.models.LogOM.generate_conf')
    def test_generate_frontend_conf(self, patched_render_log_condition, logger_patcher, logger_patcher2):
        patched_render_log_condition.return_value = (True, "Success")
        self.frontend_log.generate_rsyslog_conf()
        patched_render_log_condition.assert_called()
