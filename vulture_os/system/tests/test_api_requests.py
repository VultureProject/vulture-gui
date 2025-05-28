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

from system.cluster.models import Cluster, Node, MessageQueue

class APIRequestCase(TestCase):
    TEST_CASE_NAME=f"{__name__}"
    def setUp(self):
        self.node = Node.objects.create(
            name=f"node_test_{self.TEST_CASE_NAME}",
            management_ip="127.0.0.1"
        )

    def test_get_node(self):
        self.assertTrue(Node.objects.get(name=f"node_test_{self.TEST_CASE_NAME}"))

    def test_api_request(self):
        api_res = Cluster.api_request("services.rsyslogd.rsyslog.restart_service")

        self.assertIsNotNone(MessageQueue.objects.get())
        self.assertTrue(api_res.get('status'))
        MessageQueue.objects.get().delete()

    def test_await_api_request(self):
        Cluster.await_api_request("services.rsyslogd.rsyslog.restart_service", interval=2, tries=2)

        self.assertIsNotNone(MessageQueue.objects.get())
        MessageQueue.objects.get().delete()

    def test_get_pending_messages(self):
        Cluster.api_request("services.rsyslogd.rsyslog.restart_service")

        self.assertIsNotNone(MessageQueue.objects.get())
        self.assertIsNotNone(self.node.get_pending_messages())
        MessageQueue.objects.get().delete()

    def test_delayed_api_request(self):
        Cluster.api_request("services.rsyslogd.rsyslog.restart_service", run_delay=5)

        message = MessageQueue.objects.get()
        self.assertIsNotNone(message)
        self.assertGreater(message.run_at, timezone.now())
        message.delete()

    def test_multiple_delayed_api_request(self):
        api_res = Cluster.api_request("services.rsyslogd.rsyslog.restart_service", run_delay=5)
        api_res.get("instances")[0].refresh_from_db()
        Cluster.api_request("services.rsyslogd.rsyslog.restart_service", run_delay=5)
        Cluster.api_request("services.rsyslogd.rsyslog.restart_service", run_delay=5)

        message = MessageQueue.objects.get()
        self.assertIsNotNone(message)
        self.assertEqual(message.date_add, api_res.get("instances")[0].date_add)
        self.assertNotEqual(message.run_at, api_res.get("instances")[0].run_at)
        message.delete()

    def test_check_empty_pending_messages(self):
        Cluster.api_request("services.rsyslogd.rsyslog.restart_service", run_delay=5)

        self.assertIsNotNone(MessageQueue.objects.get())
        self.assertQuerySetEqual(self.node.get_pending_messages(), [])
        MessageQueue.objects.get().delete()

    def test_api_request_with_node(self):
        Cluster.api_request("services.rsyslogd.rsyslog.restart_service", node=self.node)

        message = MessageQueue.objects.get()
        self.assertIsNotNone(message)
        self.assertEqual(message.node, self.node)
        message.delete()
