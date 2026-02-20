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
__doc__ = 'Tests for datetime/timezone.py'

import re

from django.test import SimpleTestCase
from unittest.mock import patch

from toolkit.network.network import (
    parse_ifconfig_key,
    parse_ifconfig_values,
    parse_gateway_config,
    PATTERN_IFCONFIG
)

class NetworkTestCase(SimpleTestCase):
    TEST_CASE_NAME=f"{__name__}"
    def setUp(self):
        # Prevent logger from printing logs to stdout during tests
        self.logger_patcher = patch('toolkit.network.network.logger')
        self.logger_patcher.start()

    def tearDown(self) -> None:
        # Cleanly remove the logger patch
        self.logger_patcher.stop()
        return super().tearDown()


####################
# PATTERN_IFCONFIG #
####################
    def test_PATTERN_IFCONFIG_valid_formats(self):
        for TEST_LINE, EXPECTED_KEY, EXPECTED_VALUE in [
            (
                # valid key and value, double-quotes
                'ifconfig_em0="inet 192.168.1.1/24"',
                'em0',
                'inet 192.168.1.1/24'
            ),
            (
                # valid key and value, single-quotes
                "ifconfig_vtnet1='inet6 2001:db8:0:0:0:1/64'",
                'vtnet1',
                'inet6 2001:db8:0:0:0:1/64'
            ),
            (
                # alias key suffix
                'ifconfig_vmx0_alias0="inet 127.0.10.1/32"',
                'vmx0_alias0',
                'inet 127.0.10.1/32'
            ),
            (
                # value with escaped double-quotes
                'ifconfig_igb1="inet 127.0.10.1/32 vhid 42 advskew 100 pass \\"super secret pass\\""',
                'igb1',
                'inet 127.0.10.1/32 vhid 42 advskew 100 pass \\"super secret pass\\"'
            ),
        ]:
            match = re.search(PATTERN_IFCONFIG, TEST_LINE)
            self.assertIsNotNone(match, f"line '{TEST_LINE}' did not parse successfully")
            key = match.group("key")
            value = match.group("value")
            self.assertEqual(key, EXPECTED_KEY)
            self.assertEqual(value, EXPECTED_VALUE)

    def test_PATTERN_IFCONFIG_invalid_formats(self):
        for TEST_LINE in [
            'ifconfig_em0=inet 192.168.1.1/24', # no quote
            'ifconfig_vmx0_alias0=inet 127.0.10.1/32"', # missing quote before
            'ifconfig_vmx0_alias0="inet 127.0.10.1/32', # missing quote after
            "ifconfig_vtnet1 = 'inet6 2001:db8:0:0:0:1/64'", # missing quote before
            'em0="inet 192.168.1.1/24"', # ifconfig prefix missing (plain variable)
            'IFCONFIG_em0="inet 192.168.1.1/24"', # Uppercase IFCONFIG prefix
            'ifconfig_em-0="inet 192.168.1.1/24"', # Interface name with hyphen (invalid in FreeBSD)
            'ifconfig_0em="inet 192.168.1.1/24"', # Interface name starting with digit
        ]:
            match = re.search(PATTERN_IFCONFIG, TEST_LINE)
            self.assertIsNone(match, f"line '{TEST_LINE}' shouldn't parse successfully")

######################
# parse_ifconfig_key #
######################
    def test_parse_ifconfig_key_no_value(self):
        TEST_LINE = ''
        config = dict()
        self.assertFalse(parse_ifconfig_key(TEST_LINE, config))

    def test_parse_ifconfig_key_wrong_name_format(self):
        TEST_LINE = 'foo'
        config = dict()
        self.assertFalse(parse_ifconfig_key(TEST_LINE, config))

    def test_parse_ifconfig_key_too_many_underscores(self):
        TEST_LINE = 'ifconfig_foo_bar_baz'
        config = dict()
        self.assertFalse(parse_ifconfig_key(TEST_LINE, config))

    def test_parse_ifconfig_key_name_formats(self):
        for TEST_LINE in [
            'em0',
            'vtnet1',
            'vmx2',
            'igb0',
            'gif3',
            'wg2',
            'tun0',
            'bridge5',
            'carp10',
            'vlan128',
            'epair0a',
        ]:
            config = dict()
            self.assertTrue(parse_ifconfig_key(TEST_LINE, config))

    def test_parse_ifconfig_key_ipv4(self):
        TEST_LINE = 'vtnet0'
        config = dict()
        self.assertTrue(parse_ifconfig_key(TEST_LINE, config))
        self.assertDictEqual(
            config,
            {
                'family': 'inet',
                'name': 'vtnet',
                'iface_id': '0',
            })

    def test_parse_ifconfig_key_ipv6(self):
        TEST_LINE = 'em1_ipv6'
        config = dict()
        self.assertTrue(parse_ifconfig_key(TEST_LINE, config))
        self.assertDictEqual(
            config,
            {
                'family': 'inet6',
                'ipv6': True,
                'name': 'em',
                'iface_id': '1',
            })

    def test_parse_ifconfig_key_alias(self):
        TEST_LINE = 'vmx2_alias1'
        config = dict()
        self.assertTrue(parse_ifconfig_key(TEST_LINE, config))
        self.assertDictEqual(
            config,
            {
                'family': 'inet',
                'name': 'alias',
                'iface_id': '1',
                'type': 'alias',
                'nic': ['vmx2'],
            })

    def test_parse_ifconfig_key_ipv6_alias(self):
        TEST_LINE = 'vmx3_ipv6_alias10'
        config = dict()
        self.assertTrue(parse_ifconfig_key(TEST_LINE, config))
        self.assertDictEqual(
            config,
            {
                'family': 'inet6',
                'ipv6': True,
                'name': 'alias',
                'iface_id': '10',
                'type': 'alias',
                'nic': ['vmx3'],
            })

    def test_parse_ifconfig_key_vlan(self):
        TEST_LINE = 'vlan128'
        config = dict()
        self.assertTrue(parse_ifconfig_key(TEST_LINE, config))
        self.assertDictEqual(
            config,
            {
                'family': 'inet',
                'name': 'vlan',
                'iface_id': '128',
                'type': 'vlan',
            })

    def test_parse_ifconfig_key_vlan_ipv6(self):
        TEST_LINE = 'vlan128_ipv6'
        config = dict()
        self.assertTrue(parse_ifconfig_key(TEST_LINE, config))
        self.assertDictEqual(
            config,
            {
                'family': 'inet6',
                'ipv6': True,
                'name': 'vlan',
                'iface_id': '128',
                'type': 'vlan',
            })

    def test_parse_ifconfig_key_lagg(self):
        TEST_LINE = 'lagg2'
        config = dict()
        self.assertTrue(parse_ifconfig_key(TEST_LINE, config))
        self.assertDictEqual(
            config,
            {
                'family': 'inet',
                'name': 'lagg',
                'iface_id': '2',
                'type': 'lagg',
            })


#########################
# parse_ifconfig_values #
#########################
    def test_parse_ifconfig_values_no_value(self):
        TEST_LINE = ''
        config = dict()
        self.assertFalse(parse_ifconfig_values(TEST_LINE, config))

    def test_parse_ifconfig_values_wrong_ipv4(self):
        for TEST_LINE in [
            'foo',
            'inet 256.168.1.1/24', # octet out of range
            'inet 192.168.1.1.1/24', # extra octet/dot
            'inet 192.168.1/24', # too few octets/dots
            'inet 192.168.001.1/24', # ambiguous leading zero(s)
            'inet6 192.168.1.1/24', # wrong 'inet6' use
            'inet /24', # missing IP
        ]:
            config = dict()
            self.assertFalse(parse_ifconfig_values(TEST_LINE, config), f"{TEST_LINE} shouldn't be valid")

    def test_parse_ifconfig_values_wrong_ipv6(self):
        for TEST_LINE in [
            'foo',
            'inet6 2001:db8:0:0:0:0:0:0:1/64', # too many groups
            'inet6 2001:db8:0:0:0:1/64', # too few groups
            'inet6 2001:db8:1:2:3:4::5:6:7/64', # too many groups (with double ':')
            'inet6 2001::db8::1/64', # double ':' used twice
            'inet6 2001:db8:::1/64', # triple ':'
            'inet6 :2001:db8::1/64', # starts with single colon (not ::)
            'inet 2001:db8::1/64', # wrong 'inet' use
            'inet6 2001:db8::1:/64', # ends with single colon (not ::)
            'inet6 :/64', # lone colon
        ]:
            config = {'ipv6': True}
            self.assertFalse(parse_ifconfig_values(TEST_LINE, config), f"{TEST_LINE} shouldn't be valid")

    def test_parse_ifconfig_values_dhcp(self):
        for TEST_LINE in [
            'dhcp',
            'DHCP',
            'syncdhcp',
            'SYNCDHCP',
        ]:
            config = dict()
            self.assertTrue(parse_ifconfig_values(TEST_LINE, config))
            self.assertDictEqual(
                config,
                {
                    'dhcp': True,
                    'type': 'system',
                }
            )

    def test_parse_ifconfig_values_ipv4(self):
        for TEST_LINE in [
            "inet 127.0.0.1/32", # IPv4 with /32 (host route)
            "inet 10.0.0.1/8", # IPv4 with /8 class A
            "inet 172.16.0.1/16", # IPv4 with /16 class B
            "inet 192.168.100.1/30", # IPv4 with /30 (point-to-point)
            "inet 192.168.1.50/24 up", # IPv4 with extra interface flags
            "inet 10.10.0.1/24 mtu 9000", # IPv4 with MTU
            "inet 192.168.1.1/24 media autoselect", # IPv4 with media option
        ]:
            config = dict()
            self.assertTrue(parse_ifconfig_values(TEST_LINE, config))

    def test_parse_ifconfig_values_ipv4_netmask(self):
        for TEST_LINE, EXPECTED_CONF in [
            (
                # Basic IPv4 with prefix length
                "inet 10.0.0.1/8",
                {'ip': '10.0.0.1', 'prefix_or_netmask': '8'}
            ),
            (
                # Basic IPv4 with prefix length
                "inet 172.16.0.1/16",
                {'ip': '172.16.0.1', 'prefix_or_netmask': '16'}
            ),
            (
                # Basic IPv4 with prefix length
                "inet 192.168.1.10/24",
                {'ip': '192.168.1.10', 'prefix_or_netmask': '24'}
            ),
            (
                # IPv4 with dotted netmask
                "inet 192.168.1.10 netmask 255.255.255.0",
                {'ip': '192.168.1.10', 'prefix_or_netmask': '255.255.255.0'}
            ),
            (
                # IPv4 with dotted netmask
                "inet 192.168.1.33 netmask 255.255.255.224",
                {'ip': '192.168.1.33', 'prefix_or_netmask': '255.255.255.224'}
            ),
        ]:
            config = dict()
            self.assertTrue(parse_ifconfig_values(TEST_LINE, config))
            self.assertDictContainsSubset(
                EXPECTED_CONF,
                config,
                f"failure on line '{TEST_LINE}'"
            )

    def test_parse_ifconfig_values_ipv6(self):
        for TEST_LINE in [
            "inet6 2001:0db8:0000:0000:0000:0000:0000:0001/64",  # fully expanded
            "inet6 2001:0db8:85a3:0000:0000:8a2e:0370:7334/64",  # RFC 3849 example
            "inet6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", # all-ones
            "inet6 0000:0000:0000:0000:0000:0000:0000:0001/128", # loopback uncompressed
            "inet6 0000:0000:0000:0000:0000:0000:0000:0000/0",   # default route uncompressed
            "inet6 ::/0",                                        # default route (all zeros)
            "inet6 ::1/128",                                     # loopback
            "inet6 2001:db8::/32",                               # documentation prefix, :: at end
            "inet6 2001:db8::1/64",                              # :: in middle, single trailing group
            "inet6 2001:db8::1:2/64",                            # :: in middle, two trailing groups
            "inet6 2001:db8::1:2:3/64",                          # :: in middle, three trailing groups
            "inet6 2001:db8::1:2:3:4/64",                        # :: in middle, four trailing groups
            "inet6 ::ffff:192.0.2.1/96",                         # IPv4-mapped (::ffff:a.b.c.d)
            "inet6 ::192.0.2.1/96",                              # IPv4-compatible (deprecated but parseable)
            "inet6 fe80::1/64",                                  # link-local, minimal
            "inet6 fe80::dead:beef/64",                          # link-local with hex words
            "inet6 fe80::1%em0/64",                              # link-local with zone ID
            "inet6 fe80::1%vlan10/64",                           # zone ID on VLAN interface
            "inet6 fe80::1%carp0/64",                            # zone ID on CARP interface
            "inet6 ff02::1/128",                                 # all-nodes multicast
            "inet6 ff02::2/128",                                 # all-routers multicast
            "inet6 ff02::1:ff00:1/128",                          # solicited-node multicast
            "inet6 ff05::101/128",                               # site-local NTP multicast
            "inet6 100::1/64",                                   # :: compress in leading position
            "inet6 ::1:2:3:4:5:6:7/128",                         # :: replaces only leading zero group
            "inet6 2001:db8::1/0",                               # default route
            "inet6 2001:db8::1/1",
            "inet6 2001:db8::1/7",                               # just below /8 boundary
            "inet6 2001:db8::1/8",
            "inet6 2001:db8::1/10",                              # link-local prefix boundary
            "inet6 2001:db8::1/16",
            "inet6 2001:db8::1/23",                              # just below /24
            "inet6 2001:db8::1/24",
            "inet6 2001:db8::1/32",                              # typical ISP allocation
            "inet6 2001:db8::1/48",                              # typical site allocation
            "inet6 2001:db8::1/56",                              # typical home allocation
            "inet6 2001:db8::1/63",                              # just below /64
            "inet6 2001:db8::1/64",                              # most common LAN prefix
            "inet6 2001:db8::1/65",                              # just above /64
            "inet6 2001:db8::1/96",                              # IPv4-mapped boundary
            "inet6 2001:db8::1/127",                             # point-to-point (RFC 6164)
            "inet6 2001:db8::1/128",                             # host route
            "inet6 2001:db8:1:2::1/64",                          # Global unicast (2000::/3)
            "inet6 2600:1f14:1234:5678::1/64",                   # AWS-style global unicast
            "inet6 fc00::1/7",                                   # Unique Local: fc (first half of ULA range)
            "inet6 fd00:1:2:3::1/48",                            # Unique Local: fd prefix, common ULA
            "inet6 fdab:cdef:1234:5678::1/64",                   # Unique Local: random ULA global ID
            "inet6 2002:c000:0204::1/16",                        # 6to4: 2002:<IPv4 hex>::/16
            "inet6 2001:0000:4136:e378:8000:63bf:3fff:fdd2/128", # Teredo (2001::/32)
            "inet6 2001:0020::1/28",                             # ORCHID v2 (2001:20::/28)
            "inet6 2001:db8:cafe:babe::1/64",                    # Documentation (2001:db8::/32)
            "inet6 3ffe:1234::1/16",                             # 6bone legacy (3ffe::/16, historical but parseable)
        ]:
            config = {'ipv6': True}
            self.assertTrue(parse_ifconfig_values(TEST_LINE, config), f"line '{TEST_LINE}' did not pass validation")

    def test_parse_ifconfig_values_ipv6_netmask(self):
        for TEST_LINE, EXPECTED_CONF in [
            (   # /0 — Default route (entire IPv6 space)
                "inet6 2001:db8::1/0",
                {'ip': '2001:db8::1', 'prefix_or_netmask': '0'}
            ),
            (   # /1–7 — Extremely large allocations (RIR-level)
                "inet6 2001:db8::1/6",
                {'ip': '2001:db8::1', 'prefix_or_netmask': '6'}
            ),
            (   # /8–15 — Large regional allocations
                "inet6 2001:db8::1/13",
                {'ip': '2001:db8::1', 'prefix_or_netmask': '13'}
            ),
            (   # /65–95 — Unusual subnet sizes (non-standard but valid)
                "inet6 2001:db8::1/78",
                {'ip': '2001:db8::1', 'prefix_or_netmask': '78'}
            ),
            (   # /128 — Host route (single address)
                "inet6 2001:db8::1/128",
                {'ip': '2001:db8::1', 'prefix_or_netmask': '128'}
            ),
            (   # Standard prefix using prefixlen keyword
                "inet6 2001:db8::1 prefixlen 64",
                {'ip': '2001:db8::1', 'prefix_or_netmask': '64'}
            ),
            (   # prefixlen on compressed addresses
                "inet6 ::1 prefixlen 128",
                {'ip': '::1', 'prefix_or_netmask': '128'}
            ),
            (   # prefixlen on link-local with zone
                "inet6 fe80::1%em0 prefixlen 64",
                {'ip': 'fe80::1%em0', 'prefix_or_netmask': '64'}
            ),
        ]:
            config = {'ipv6': True}
            self.assertTrue(parse_ifconfig_values(TEST_LINE, config))
            self.assertDictContainsSubset(
                EXPECTED_CONF,
                config,
                f"failure on line '{TEST_LINE}'"
            )

    def test_parse_ifconfig_values_alias_or_system(self):
        for TEST_LINE, INIT_CONFIG, EXPECTED_CONF in [
            (
                # No type set, no alias in value
                "inet 10.0.0.1/8",
                {},
                {'ip': '10.0.0.1', 'prefix_or_netmask': '8', 'type': 'system'}
            ),
            (
                # No type set, alias in value
                "inet 192.168.100.1/30 alias ",
                {},
                {'ip': '192.168.100.1', 'prefix_or_netmask': '30', 'type': 'alias'}
            ),
            (
                # Alias set already set, no alias value
                "inet 172.16.0.1/16",
                {'type': 'alias'},
                {'ip': '172.16.0.1', 'prefix_or_netmask': '16', 'type': 'alias'}
            ),
            (
                # Alias set already set, no alias value
                "inet 192.168.1.50/24 alias",
                {'type': 'alias'},
                {'ip': '192.168.1.50', 'prefix_or_netmask': '24', 'type': 'alias'}
            ),
        ]:
            self.assertTrue(parse_ifconfig_values(TEST_LINE, INIT_CONFIG), f"line '{TEST_LINE}' hasn't passed validation")
            self.assertDictEqual(
                EXPECTED_CONF,
                INIT_CONFIG,
                f"failure on line '{TEST_LINE}'"
            )

    def test_parse_ifconfig_values_carp_params(self):
        for TEST_LINE, INIT_CONFIG, EXPECTED_CONF in [
            (
                # Basic CARP with vhid and password
                "inet 192.168.1.1/24 vhid 1 pass secretpass",
                {},
                {'ip':'192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system', 'carp_vhid': '1', 'carp_password': 'secretpass'}),
            (
                # CARP with advskew
                "inet 192.168.1.1/24 vhid 1 pass secretpass advskew 100",
                {},
                {'ip':'192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system', 'carp_vhid': '1', 'carp_password': 'secretpass', 'carp_priority': '100'}),
            (
                # CARP as master
                "inet 192.168.1.1/24 vhid 255 pass secretpass advskew 0",
                {},
                {'ip':'192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system', 'carp_vhid': '255', 'carp_password': 'secretpass', 'carp_priority': '0'}),
            (
                # CARP IPv6
                "inet6 2001:db8::1/64 vhid 34 pass secretpass",
                {'ipv6': True},
                {'ip':'2001:db8::1', 'ipv6': True, 'prefix_or_netmask': '64', 'type': 'system', 'carp_vhid': '34', 'carp_password': 'secretpass'}),
            (
                # no VHID value
                "inet 192.168.1.1/24 vhid pass secretpass",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system', 'carp_password': 'secretpass'}),
            (
                # no pass
                "inet 192.168.1.1/24 vhid 1 advskew 100 pass",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system', 'carp_vhid': '1', 'carp_priority': '100'}),
            (
                # wrong advskew value
                "inet 192.168.1.1/24 vhid 255 pass secretpass advskew foo",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system', 'carp_vhid': '255', 'carp_password': 'secretpass'}),
            (
                # wrong vhid value
                "inet6 2001:db8::1/64 vhid bar pass secretpass",
                {'ipv6': True},
                {'ip': '2001:db8::1', 'ipv6': True, 'prefix_or_netmask': '64', 'type': 'system', 'carp_password': 'secretpass'}),
        ]:
            self.assertTrue(parse_ifconfig_values(TEST_LINE, INIT_CONFIG), f"line '{TEST_LINE}' hasn't passed validation")
            self.assertEqual(
                EXPECTED_CONF,
                INIT_CONFIG,
                f"failure on line '{TEST_LINE}'"
            )

    def test_parse_ifconfig_values_fib(self):
        for TEST_LINE, INIT_CONFIG, EXPECTED_CONF in [
            (
                # default FIB, not added to conf
                "inet 192.168.1.1/24",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
            (
                # default FIB, but explicit
                "inet 192.168.1.1/24 fib 0",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system', 'fib': '0'}
            ),
            (
                # non-default FIB, explicit
                "inet 192.168.1.1/24 fib 3",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system', 'fib': '3'}
            ),
            (
                # non-default FIB, IPv6, explicit
                "inet6 2001:db8::1/64 fib 9",
                {'ipv6': True},
                {'ip': '2001:db8::1', 'ipv6': True, 'prefix_or_netmask': '64', 'type': 'system', 'fib': '9'}
            ),
            (
                # invalid FIB (>9)
                "inet 192.168.1.1/24 fib 12",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
            (
                # invalid FIB (<0)
                "inet6 2001:db8::1/64 fib -2",
                {'ipv6': True},
                {'ip': '2001:db8::1', 'ipv6': True, 'prefix_or_netmask': '64', 'type': 'system'}
            ),
            (
                # invalid FIB (not a number)
                "inet 192.168.1.1/24 fib fab",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
        ]:
            self.assertTrue(parse_ifconfig_values(TEST_LINE, INIT_CONFIG), f"line '{TEST_LINE}' hasn't passed validation")
            self.assertDictEqual(
                EXPECTED_CONF,
                INIT_CONFIG,
                f"failure on line '{TEST_LINE}'"
            )

    def test_parse_ifconfig_values_vlan(self):
        for TEST_LINE, INIT_CONFIG, EXPECTED_CONF in [
            (
                # default IP, no vlan
                "inet 192.168.1.1/24",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
            (
                # missing vlandev
                "inet 192.168.1.1/24 vlan 13",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
            (
                # missing vlan
                "inet 192.168.1.1/24 vlandev em0",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
            (
                # valid vlan conf
                "inet 192.168.1.1/24 vlan 13 vlandev em0",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system', 'vlan': '13', 'nic': ['em0']}
            ),
            (
                # valid vlan conf 2
                "inet 192.168.1.1/24 vlandev vtnet1 vlan 24",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system', 'vlan': '24', 'nic': ['vtnet1']}
            ),
            (
                # missing vlandev value
                "inet 192.168.1.1/24 vlan 24 vlandev",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
            (
                # missing vlan value
                "inet 192.168.1.1/24 vlandev igb2 vlan",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
            (
                # wrong vlan value
                "inet 192.168.1.1/24 vlandev vmx0 vlan foo",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
        ]:
            self.assertTrue(parse_ifconfig_values(TEST_LINE, INIT_CONFIG), f"line '{TEST_LINE}' hasn't passed validation")
            self.assertDictEqual(
                EXPECTED_CONF,
                INIT_CONFIG,
                f"failure on line '{TEST_LINE}'"
            )

    def test_parse_ifconfig_values_lagg(self):
        for TEST_LINE, INIT_CONFIG, EXPECTED_CONF in [
            (
                # default IP, no lagg
                "inet 192.168.1.1/24",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
            (
                # missing laggport
                "inet 192.168.1.1/24 laggproto loadbalance",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
            (
                # missing laggproto
                "inet 192.168.1.1/24 laggport em0",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
            (
                # valid lagg conf
                "inet 192.168.1.1/24 laggproto loadbalance laggport em0 laggport em1",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system', 'lagg_proto': 'loadbalance', 'nic': ['em0', 'em1']}
            ),
            (
                # valid lagg conf 2
                "inet 192.168.1.1/24 laggport vtnet1 laggproto roundrobin laggport vtnet2",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system', 'lagg_proto': 'roundrobin', 'nic': ['vtnet1', 'vtnet2']}
            ),
            (
                # missing a laggport
                "inet 192.168.1.1/24 laggproto loadbalance laggport em0",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
            (
                # wrong laggproto value
                "inet 192.168.1.1/24 laggproto 12 laggport em0 laggport em1",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
            (
                # missing laggport value
                "inet 192.168.1.1/24 laggproto loadbalance laggport em0 laggport",
                {},
                {'ip': '192.168.1.1', 'prefix_or_netmask': '24', 'type': 'system'}
            ),
        ]:
            self.assertTrue(parse_ifconfig_values(TEST_LINE, INIT_CONFIG), f"line '{TEST_LINE}' hasn't passed validation")
            self.assertDictEqual(
                EXPECTED_CONF,
                INIT_CONFIG,
                f"failure on line '{TEST_LINE}'"
            )

########################
# parse_gateway_config #
########################
    def test_parse_gateway_config_no_value(self):
        TEST_LINE = ''
        config = dict()
        self.assertFalse(parse_gateway_config(TEST_LINE, config))

    def test_parse_gateway_config_ipv4_matches(self):
        for TEST_LINE, INIT_CONFIG, SHOULD_PASS, EXPECTED_CONF in [
            (
                # default router, with double quotes
                'defaultrouter="192.168.1.1"',
                {},
                True,
                {'defaultgateway': '192.168.1.1'}
            ),
            (
                # default router, with single quotes
                "defaultrouter='192.168.1.1'",
                {},
                True,
                {'defaultgateway': '192.168.1.1'}
            ),
            (
                # no value
                "defaultrouter=''",
                {},
                False,
                {}
            ),
        ]:
            self.assertEquals(parse_gateway_config(TEST_LINE, INIT_CONFIG), SHOULD_PASS, f"line '{TEST_LINE}' hasn't passed validation")
            self.assertDictEqual(
                EXPECTED_CONF,
                INIT_CONFIG,
                f"failure on line '{TEST_LINE}'"
            )

    def test_parse_gateway_config_ipv6_matches(self):
        for TEST_LINE, INIT_CONFIG, SHOULD_PASS, EXPECTED_CONF in [
            (
                # default router, with double quotes
                'ipv6_defaultrouter="fe80::1"',
                {},
                True,
                {'defaultgateway_ipv6': 'fe80::1'}
            ),
            (
                # default router, with single quotes
                "ipv6_defaultrouter='fe80::1'",
                {},
                True,
                {'defaultgateway_ipv6': 'fe80::1'}
            ),
            (
                # no value
                "ipv6_defaultrouter=''",
                {},
                False,
                {}
            ),
        ]:
            self.assertEquals(parse_gateway_config(TEST_LINE, INIT_CONFIG), SHOULD_PASS, f"line '{TEST_LINE}' hasn't passed validation")
            self.assertDictEqual(
                EXPECTED_CONF,
                INIT_CONFIG,
                f"failure on line '{TEST_LINE}'"
            )
