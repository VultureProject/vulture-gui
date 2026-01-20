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
__doc__ = 'Tests for System App'

from django.test import TestCase
from unittest.mock import patch

from system.cluster.models import NetworkInterfaceCard, NetworkAddress, NetworkAddressNIC

class NetworkInterfaceCardTestCase(TestCase):
    TEST_CASE_NAME=f"{__name__}"
    def setUp(self):
        from system.cluster.models import Node
        self.node = Node.objects.create(
            name=f"node_test_{self.TEST_CASE_NAME}",
        )

    def test_nic_creation(self):
        self.assertIsNotNone(
            NetworkInterfaceCard.objects.create(
                dev = "vtnet0",
                node=self.node,
            )
        )

    @patch('subprocess.check_output')
    def test_get_list(self, mocked_check_output):
        mocked_check_output.return_value = b"vtnet0 lo0 lo1 lo2 em1 lo3 lo4 lo5 lo6 tun0 pflog0"
        nic = NetworkInterfaceCard.objects.create(
                dev = "vtnet0",
                node=self.node,
            )

        interface_list = nic.get_list()
        self.assertIsInstance(interface_list, list)
        self.assertEqual(set(["vtnet0", "em1"]), set(interface_list))

    def test_has_ipv4_simple(self):
        nic = NetworkInterfaceCard.objects.create(
                dev = "vtnet0",
                node=self.node,
            )
        net_addr_ipv4 = NetworkAddress.objects.create(
            name = f"net_addr_ipv4_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="127.0.0.1",
            prefix_or_netmask="24",
        )
        nic_addr = NetworkAddressNIC.objects.create(
            nic=nic,
            network_address=net_addr_ipv4
        )
        self.assertIsNotNone(nic)
        self.assertIsNotNone(net_addr_ipv4)
        self.assertIsNotNone(nic_addr)

        self.assertTrue(nic.has_ipv4)
        self.assertFalse(nic.has_ipv6)

    def test_has_ipv4_and_vlanv6(self):
        nic = NetworkInterfaceCard.objects.create(
                dev = "vtnet0",
                node=self.node,
            )
        net_addr_ipv4 = NetworkAddress.objects.create(
            name = f"net_addr_ipv4_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="127.0.0.1",
            prefix_or_netmask="24",
        )
        net_addr_vlan = NetworkAddress.objects.create(
            name = f"net_addr_vlan_test_{self.TEST_CASE_NAME}",
            type="vlan",
            ip="fe80::1",
            prefix_or_netmask="64",
            vlan=123
        )
        nic_addr = NetworkAddressNIC.objects.create(
            nic=nic,
            network_address=net_addr_ipv4
        )
        nic_addr2 = NetworkAddressNIC.objects.create(
            nic=nic,
            network_address=net_addr_vlan
        )
        self.assertIsNotNone(nic)
        self.assertIsNotNone(net_addr_ipv4)
        self.assertIsNotNone(net_addr_vlan)
        self.assertIsNotNone(nic_addr)
        self.assertIsNotNone(nic_addr2)

        self.assertEqual(nic.networkaddress_set.count(), 2)

        self.assertTrue(nic.has_ipv4)
        self.assertFalse(nic.has_ipv6)

    def test_has_ipv6_simple(self):
        nic = NetworkInterfaceCard.objects.create(
                dev = "vtnet0",
                node=self.node,
            )
        net_addr_ipv6 = NetworkAddress.objects.create(
            name = f"net_addr_ipv6_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="fe80::1",
            prefix_or_netmask="64",
        )
        nic_addr = NetworkAddressNIC.objects.create(
            nic=nic,
            network_address=net_addr_ipv6
        )
        self.assertIsNotNone(nic)
        self.assertIsNotNone(net_addr_ipv6)
        self.assertIsNotNone(nic_addr)

        self.assertFalse(nic.has_ipv4)
        self.assertTrue(nic.has_ipv6)


    def test_has_ipv6_and_vlanv4(self):
        nic = NetworkInterfaceCard.objects.create(
                dev = "vtnet0",
                node=self.node,
            )
        net_addr_ipv6 = NetworkAddress.objects.create(
            name = f"net_addr_ipv6_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="fe80::1",
            prefix_or_netmask="64",
        )
        net_addr_vlan = NetworkAddress.objects.create(
            name = f"net_addr_vlan_test_{self.TEST_CASE_NAME}",
            type="vlan",
            ip="127.0.0.1",
            prefix_or_netmask="24",
            vlan=123
        )
        nic_addr = NetworkAddressNIC.objects.create(
            nic=nic,
            network_address=net_addr_ipv6
        )
        nic_addr2 = NetworkAddressNIC.objects.create(
            nic=nic,
            network_address=net_addr_vlan
        )
        self.assertIsNotNone(nic)
        self.assertIsNotNone(net_addr_ipv6)
        self.assertIsNotNone(net_addr_vlan)
        self.assertIsNotNone(nic_addr)
        self.assertIsNotNone(nic_addr2)

        self.assertEqual(nic.networkaddress_set.count(), 2)

        self.assertFalse(nic.has_ipv4)
        self.assertTrue(nic.has_ipv6)


class NetworkAddressTestCase(TestCase):
    TEST_CASE_NAME=f"{__name__}"
    def setUp(self):
        from system.cluster.models import Node
        self.node = Node.objects.create(
            name=f"node_test_{self.TEST_CASE_NAME}",
        )
        self.nic0 = NetworkInterfaceCard.objects.create(
                dev = "vtnet0",
                node=self.node,
            )
        self.nic1 = NetworkInterfaceCard.objects.create(
                dev = "vtnet1",
                node=self.node,
            )

    def test_is_carp(self):
        net_addr_with_carp = NetworkAddress.objects.create(
            name = f"net_addr_with_carp_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="127.0.0.1",
            prefix_or_netmask="24",
            carp_vhid=42
        )
        net_addr_without_carp = NetworkAddress.objects.create(
            name = f"net_addr_without_carp_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="127.0.0.1",
            prefix_or_netmask="24",
            carp_vhid=0
        )

        self.assertIsNotNone(net_addr_with_carp)
        self.assertIsNotNone(net_addr_without_carp)
        self.assertTrue(net_addr_with_carp.is_carp)
        self.assertFalse(net_addr_without_carp.is_carp)

    def test_version(self):
        net_addr_ipv4 = NetworkAddress.objects.create(
            name = f"net_addr_ipv4_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="127.0.0.1",
            prefix_or_netmask="24",
        )
        net_addr_ipv6 = NetworkAddress.objects.create(
            name = f"net_addr_ipv6_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="fe80::1",
            prefix_or_netmask="64",
        )
        net_addr_lagg = NetworkAddress.objects.create(
            name = f"net_addr_lagg_test_{self.TEST_CASE_NAME}",
            type="lagg",
        )

        self.assertIsNotNone(net_addr_ipv4)
        self.assertIsNotNone(net_addr_ipv6)
        self.assertIsNotNone(net_addr_lagg)
        self.assertEqual(net_addr_ipv4.version, 4)
        self.assertEqual(net_addr_ipv6.version, 6)
        # Oh that's ugly...
        self.assertEqual(net_addr_lagg.version, '')

    def test_ip_cidr(self):
        net_addr_ipv4 = NetworkAddress.objects.create(
            name = f"net_addr_ipv4_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="127.0.0.1",
            prefix_or_netmask="24",
        )
        net_addr_ipv6 = NetworkAddress.objects.create(
            name = f"net_addr_ipv6_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="fe80::1",
            prefix_or_netmask="64",
        )
        net_addr_lagg = NetworkAddress.objects.create(
            name = f"net_addr_lagg_test_{self.TEST_CASE_NAME}",
            type="lagg",
        )

        self.assertIsNotNone(net_addr_ipv4)
        self.assertIsNotNone(net_addr_ipv6)
        self.assertIsNotNone(net_addr_lagg)
        self.assertEqual(net_addr_ipv4.ip_cidr, '127.0.0.1/24')
        self.assertEqual(net_addr_ipv6.ip_cidr, 'fe80::1/64')
        self.assertEqual(net_addr_lagg.ip_cidr, '')

    def test_family(self):
        net_addr_ipv4 = NetworkAddress.objects.create(
            name = f"net_addr_ipv4_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="127.0.0.1",
            prefix_or_netmask="24",
        )
        net_addr_ipv6 = NetworkAddress.objects.create(
            name = f"net_addr_ipv6_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="fe80::1",
            prefix_or_netmask="64",
        )
        net_addr_lagg = NetworkAddress.objects.create(
            name = f"net_addr_lagg_test_{self.TEST_CASE_NAME}",
            type="lagg",
        )

        self.assertIsNotNone(net_addr_ipv4)
        self.assertIsNotNone(net_addr_ipv6)
        self.assertIsNotNone(net_addr_lagg)
        self.assertEqual(net_addr_ipv4.family, 'inet')
        self.assertEqual(net_addr_ipv6.family, 'inet6')
        self.assertEqual(net_addr_lagg.family, '')

    def test_main_iface(self):
        net_addr_ipv4 = NetworkAddress.objects.create(
            name = f"net_addr_ipv4_test_{self.TEST_CASE_NAME}",
            type="system",
            ip="127.0.0.1",
            prefix_or_netmask="24",
            iface_id=0
        )
        NetworkAddressNIC.objects.create(
            nic=self.nic0,
            network_address=net_addr_ipv4
        )
        net_addr_ipv6 = NetworkAddress.objects.create(
            name = f"net_addr_ipv6_test_{self.TEST_CASE_NAME}",
            type="alias",
            ip="fe80::1",
            prefix_or_netmask="64",
            iface_id=1
        )
        NetworkAddressNIC.objects.create(
            nic=self.nic1,
            network_address=net_addr_ipv6
        )
        net_addr_lagg = NetworkAddress.objects.create(
            name = f"net_addr_lagg_test_{self.TEST_CASE_NAME}",
            type="lagg",
            iface_id=2,
        )
        NetworkAddressNIC.objects.create(
            nic=self.nic0,
            network_address=net_addr_lagg
        )
        NetworkAddressNIC.objects.create(
            nic=self.nic1,
            network_address=net_addr_lagg
        )
        net_addr_vlan = NetworkAddress.objects.create(
            name = f"net_addr_lagg_test_{self.TEST_CASE_NAME}",
            type="vlan",
            vlan=42,
            iface_id=42,
        )

        self.assertIsNotNone(net_addr_ipv4)
        self.assertIsNotNone(net_addr_ipv6)
        self.assertIsNotNone(net_addr_lagg)
        self.assertIsNotNone(net_addr_vlan)
        self.assertEqual(net_addr_ipv4.main_iface, 'vtnet0')
        self.assertEqual(net_addr_ipv6.main_iface, 'vtnet1_alias1')
        self.assertEqual(net_addr_lagg.main_iface, 'lagg2')
        self.assertEqual(net_addr_vlan.main_iface, 'vlan42')