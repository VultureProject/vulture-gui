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
__doc__ = 'Tests for System API Requests'

from django.test import TestCase
from django.utils import timezone
from unittest.mock import patch
from datetime import timedelta
from time import sleep

from system.cluster.models import Cluster, Node, MessageQueue

class APIRequestCase(TestCase):
    TEST_CASE_NAME=f"{__name__}"
    def setUp(self):
        # Prevent logger from printing logs to stdout during tests
        self.logger_patcher = patch('system.cluster.models.logger')
        self.logger_patcher.start()

        self.node1 = Node.objects.create(
            name=f"node_test_{self.TEST_CASE_NAME}1",
            management_ip="127.0.0.1"
        )
        self.node2 = Node.objects.create(
            name=f"node_test_{self.TEST_CASE_NAME}2",
            management_ip="127.0.0.2"
        )


    def tearDown(self) -> None:
        # Cleanly remove the logger patch
        self.logger_patcher.stop()
        return super().tearDown()


    def test_cluster_api_request(self):
        api_res = Cluster.api_request("services.rsyslogd.rsyslog.restart_service")

        self.assertEqual(MessageQueue.objects.count(), 2)
        self.assertIn("status", api_res)
        self.assertIn("message", api_res)
        self.assertIn("instances", api_res)
        self.assertTrue(api_res['status'])
        MessageQueue.objects.all().delete()


    def test_node_api_request(self):
        self.node1.api_request("services.rsyslogd.rsyslog.restart_service")
        self.node2.api_request("services.rsyslogd.rsyslog.restart_service")
        message1 = MessageQueue.objects.first()
        message2 = MessageQueue.objects.last()

        self.assertEqual(MessageQueue.objects.count(), 2)
        self.assertIsNotNone(message1)
        self.assertIsNotNone(message2)
        self.assertEqual(message1.node, self.node1)
        self.assertEqual(message2.node, self.node2)

        MessageQueue.objects.all().delete()


    @patch('system.cluster.models.MessageQueue.await_result')
    def test_cluster_await_api_request(self, patched_await_result):
        patched_await_result.return_value = (True, "Success")
        Cluster.api_request("services.rsyslogd.rsyslog.restart_service")
        patched_await_result.assert_not_called()

        Cluster.await_api_request("services.rsyslogd.rsyslog.restart_service", interval=2, tries=2)
        patched_await_result.assert_called_with(2, 2)
        self.assertEqual(patched_await_result.call_count, 2)

        MessageQueue.objects.all().delete()


    def test_node_get_pending_messages(self):
        result = self.node1.api_request("services.rsyslogd.rsyslog.restart_service")
        message1 = result['instances'][0]
        result = self.node1.api_request("services.haproxy.haproxy.reload_service")
        message2 = result['instances'][0]
        result = self.node1.api_request("services.pf.pf.reload_service")
        message3 = result['instances'][0]

        messages = self.node1.get_pending_messages()

        self.assertEqual(len(messages), 3)
        self.assertEqual(messages[0], message1)
        MessageQueue.objects.all().delete()


    def test_node_get_pending_messages_with_count(self):
        result = self.node2.api_request("services.rsyslogd.rsyslog.restart_service")
        message1 = result['instances'][0]
        result = self.node1.api_request("services.rsyslogd.rsyslog.restart_service")
        message2 = result['instances'][0]
        result = self.node1.api_request("services.haproxy.haproxy.reload_service")
        message3 = result['instances'][0]
        result = self.node1.api_request("services.pf.pf.reload_service")
        message4 = result['instances'][0]

        messages = self.node1.get_pending_messages(count=2)

        self.assertEqual(MessageQueue.objects.count(), 4)
        self.assertEqual(len(messages), 2)
        self.assertListEqual(list(messages), [message2, message3])
        MessageQueue.objects.all().delete()


    def test_node_get_pending_messages_empty(self):

        self.assertEqual(MessageQueue.objects.count(), 0)
        self.assertEqual(list(self.node1.get_pending_messages()), [])
        MessageQueue.objects.all().delete()


    def test_node_delayed_api_request(self):
        self.node1.api_request("services.rsyslogd.rsyslog.restart_service", run_delay=5)

        message = MessageQueue.objects.get()
        self.assertIsNotNone(message)
        self.assertAlmostEqual(message.run_at, timezone.now() + timedelta(seconds=5), delta=timedelta(seconds=1))

        MessageQueue.objects.all().delete()


    def test_node_updated_api_request(self):
        creation_time = timezone.now()
        self.node2.api_request("services.rsyslogd.rsyslog.restart_service", run_delay=5)
        sleep(2)
        self.node2.api_request("services.rsyslogd.rsyslog.restart_service", run_delay=5)

        message = MessageQueue.objects.last()
        self.assertIsNotNone(message)
        self.assertAlmostEqual(creation_time, message.date_add, delta=timedelta(seconds=1))
        self.assertAlmostEqual(creation_time + timedelta(seconds=2), message.modified, delta=timedelta(seconds=1))
        self.assertAlmostEqual(creation_time + timedelta(seconds=2 + 5), message.run_at, delta=timedelta(seconds=1))

        MessageQueue.objects.all().delete()


    def test_new_api_request_after_completion(self):
        Cluster.api_request("services.rsyslogd.rsyslog.restart_service")
        message1 = MessageQueue.objects.filter(node=self.node1).last()
        self.assertIsNotNone(message1)
        message2 = MessageQueue.objects.filter(node=self.node2).last()
        self.assertIsNotNone(message2)

        message1.status = MessageQueue.MessageQueueStatus.DONE
        message1.save()
        Cluster.api_request("services.rsyslogd.rsyslog.restart_service")

        self.assertEqual(MessageQueue.objects.filter(node=self.node1).count(), 2)
        self.assertEqual(MessageQueue.objects.filter(node=self.node2).count(), 1)

        MessageQueue.objects.all().delete()
