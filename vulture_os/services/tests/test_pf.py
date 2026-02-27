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
__doc__ = 'Tests for PF service and configuration generation'

from django.test import TestCase
from unittest.mock import patch

from django.conf import settings
from system.cluster.models import Cluster, Node, NetworkAddress, NetworkAddressNIC, NetworkInterfaceCard
from services.pf.models import PFSettings
from services.pf.pf import PFService

from .pf_expected_results import (
    EXPECTED_EMPTY_CONFIGURATION,
    EXPECTED_TWO_NODES_CONFIGURATION,
)


class PFServiceTestCase(TestCase):
    TEST_CASE_NAME=f"{__name__}"
    def setUp(self):
        self.maxDiff = None
        # Create a default Cluster object
        self.cluster = Cluster()
        self.cluster.save()

        # Create a local Node object
        self.node = Node.objects.create(
            name=settings.HOSTNAME,
            management_ip="192.168.1.1",
            internet_ip="192.168.1.2",
            backends_outgoing_ip="192.168.1.3",
            logom_outgoing_ip="192.168.1.4",
        )
        self.node.save()

        # Create a default PFSettings object
        pf_settings = PFSettings()
        pf_settings.save()


    def test_pf_config_generation_empty(self):
        pf_service = PFService()

        generated_conf = pf_service.get_conf()
        self.assertEqual(generated_conf, EXPECTED_EMPTY_CONFIGURATION)


    def test_pf_config_generation_two_nodes(self):
        pf_service = PFService()
        second_node = Node.objects.create(
            name=f"second_node_{self.TEST_CASE_NAME}",
            management_ip="192.168.1.5",
            internet_ip="192.168.1.6",
            backends_outgoing_ip="192.168.1.7",
            logom_outgoing_ip="192.168.1.8",
        )
        second_node.save()

        generated_conf = pf_service.get_conf()
        self.assertEqual(generated_conf, EXPECTED_TWO_NODES_CONFIGURATION)


    def test_pf_config_generation_with_interface(self):
        pf_service = PFService()

        nic = NetworkInterfaceCard.objects.create(
                dev = "em0",
                node=self.node,
            )
        nic.save()

        generated_conf = pf_service.get_conf()
        self.assertEqual(generated_conf, EXPECTED_EMPTY_CONFIGURATION)


    # def test_pf_config_generation_with_carp(self):
    #     pf_service = PFService()
    #     net_addr_with_carp = NetworkAddress.objects.create(
    #         name = f"net_addr_with_carp_{self.TEST_CASE_NAME}",
    #         type="system",
    #         ip="192.168.1.10",
    #         prefix_or_netmask="24",
    #         carp_vhid=42
    #     )
    #     net_addr_with_carp.save()
    #     nic = NetworkInterfaceCard.objects.create(
    #             dev = "vtnet0",
    #             node=self.node,
    #         )
    #     nic.save()
    #     nic_addr = NetworkAddressNIC.objects.create(
    #         nic=nic,
    #         network_address=net_addr_with_carp
    #     )
    #     nic_addr.save()

    #     generated_conf = pf_service.get_conf()
    #     self.assertEqual(generated_conf, EXPECTED_EMPTY_CONFIGURATION)

