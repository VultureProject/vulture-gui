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
from applications.logfwd.form import LogOMFWDForm

class LogOMFWDTestCase(TestCase):
    """Test mechanics of LogOMFwd models"""
    TEST_CASE_NAME=f"{__name__}"

    def setUp(self):
        # Prevent logger from printing logs to stdout during tests
        self.system_logger_patcher = patch('system.cluster.models.logger')
        self.frontend_logger_patcher = patch('services.frontend.models.logger')
        self.system_logger_patcher.start()
        self.frontend_logger_patcher.start()

    def tearDown(self) -> None:
        # Cleanly remove the logger patch
        self.system_logger_patcher.stop()
        self.frontend_logger_patcher.stop()
        return super().tearDown()

#################################
# generated configuration tests #
#################################

    def test_generated_conf_without_compression(self):
        logfwd = LogOMFWD.objects.create(
            name=f"syslog_forwarder_test_{self.TEST_CASE_NAME.replace('.','_')}",
            target="127.127.127.127",
            port=514,
            protocol="tcp",
            compression_mode="none",
        )
        logfwd_rsyslog_config = LogOM.generate_conf(logfwd, "raw_to_json", frontend="dummy")

        self.assertNotIn('compression.mode', logfwd_rsyslog_config)
        self.assertNotIn('ZipLevel', logfwd_rsyslog_config)
        self.assertNotIn('compression.stream.flushOnTXEnd', logfwd_rsyslog_config)

    def test_generated_conf_with_compression(self):
        logfwd = LogOMFWD.objects.create(
            name=f"syslog_forwarder_test_{self.TEST_CASE_NAME.replace('.','_')}",
            target="127.127.127.127",
            port=514,
            protocol="tcp",
            compression_mode="stream:always",
            zip_level=6,
            flush_on_txend=True,
        )
        logfwd_rsyslog_config = LogOM.generate_conf(logfwd, "raw_to_json", frontend="dummy")

        self.assertIn('compression.mode="stream:always"', logfwd_rsyslog_config)
        self.assertIn('ZipLevel="6"', logfwd_rsyslog_config)
        self.assertIn('compression.stream.flushOnTXEnd="on"', logfwd_rsyslog_config)

    def test_generated_conf_no_flushontxend_on_single_compression(self):
        logfwd_single_compression = LogOMFWD.objects.create(
            name=f"syslog_forwarder_flushontxend_absence_test_{self.TEST_CASE_NAME.replace('.','_')}",
            target="127.127.127.127",
            port=514,
            protocol="tcp",
            compression_mode="single",
            zip_level=6,
            flush_on_txend=True,
        )
        logfwd_rsyslog_config = LogOM.generate_conf(logfwd_single_compression, "raw_to_json", frontend="dummy")

        self.assertIn('compression.mode="single"', logfwd_rsyslog_config)
        self.assertNotIn('compression.stream.flushOnTXEnd', logfwd_rsyslog_config)

    def test_generated_conf_flushontxend_on_stream_always(self):
        logfwd_flushontxend_on = LogOMFWD.objects.create(
            name=f"syslog_forwarder_flushontxend_on_test_{self.TEST_CASE_NAME.replace('.','_')}",
            target="127.127.127.127",
            port=514,
            protocol="tcp",
            zip_level=6,
            compression_mode="stream:always",
            flush_on_txend=True,
        )
        logfwd_rsyslog_config = LogOM.generate_conf(logfwd_flushontxend_on, "raw_to_json", frontend="dummy")

        self.assertIn('compression.mode="stream:always"', logfwd_rsyslog_config)
        self.assertIn('compression.stream.flushOnTXEnd="on"', logfwd_rsyslog_config)

    def test_generated_conf_flushontxend_off_on_stream_always(self):
        logfwd_flushontxend_off = LogOMFWD.objects.create(
            name=f"syslog_forwarder_flushontxend_off_test_{self.TEST_CASE_NAME.replace('.','_')}",
            target="127.127.127.127",
            port=514,
            protocol="tcp",
            zip_level=6,
            compression_mode="stream:always",
            flush_on_txend=False,
        )
        logfwd_rsyslog_config = LogOM.generate_conf(logfwd_flushontxend_off, "raw_to_json", frontend="dummy")

        self.assertIn('compression.mode="stream:always"', logfwd_rsyslog_config)
        self.assertIn('compression.stream.flushOnTXEnd="off"', logfwd_rsyslog_config)


class LogOMFWDFormTestCase(TestCase):
    """Test custom clean() mechanics for LogOMFwd forms"""
    TEST_CASE_NAME=f"{__name__}"

    def setUp(self):
        # Prevent logger from printing logs to stdout during tests
        self.system_logger_patcher = patch('system.cluster.models.logger')
        self.frontend_logger_patcher = patch('services.frontend.models.logger')
        self.system_logger_patcher.start()
        self.frontend_logger_patcher.start()

    def tearDown(self) -> None:
        # Cleanly remove the logger patch
        self.system_logger_patcher.stop()
        self.frontend_logger_patcher.stop()
        return super().tearDown()

#################
# clean() tests #
#################

    def test_udp_protocol_no_stream_compression(self):
        logfwd_form = LogOMFWDForm({
            "name": f"syslog_forwarder_{self.TEST_CASE_NAME}",
            "target": "127.127.127.127",
            "port": 514,
            "protocol": "udp",
            "compression_mode": "stream:always",
        })

        self.assertFalse(logfwd_form.is_valid())
        self.assertListEqual(list(logfwd_form.errors.keys()), ['compression_mode'])

    def test_ratelimit_burst_without_ratelimit_interval(self):
        logfwd_form = LogOMFWDForm({
            "name": f"syslog_forwarder_{self.TEST_CASE_NAME}",
            "target": "127.127.127.127",
            "port": 514,
            "protocol": "tcp",
            "ratelimit_burst": 200,
        })

        self.assertFalse(logfwd_form.is_valid())
        self.assertListEqual(list(logfwd_form.errors.keys()), ['ratelimit_interval'])

    def test_ratelimit_interval_without_ratelimit_burst(self):
        logfwd_form = LogOMFWDForm({
            "name": f"syslog_forwarder_{self.TEST_CASE_NAME}",
            "target": "127.127.127.127",
            "port": 514,
            "protocol": "tcp",
            "ratelimit_interval": 100,
        })

        self.assertFalse(logfwd_form.is_valid())
        self.assertListEqual(list(logfwd_form.errors.keys()), ['ratelimit_burst'])
