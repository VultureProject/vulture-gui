#!/home/vlt-os/env/bin/python
# -*- coding: utf-8 -*-
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""


"""
    This script reads local "REAL / PHYSICAL" network devices and synchronise with mongoDB
    It is call whenever a sysadmin calls bsdinstall netconfig from the vlt-adm menu
"""

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

from system.cluster.models import (Cluster, NetworkInterfaceCard,
                                NetworkAddress, NetworkAddressNIC)



import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('daemon')

import re
import subprocess

PATTERN_IFCONFIG = re.compile('^ifconfig_(.*)="?\'?([^"\']*)"?\'?')
PATTERN_GATEWAY = re.compile("^defaultrouter=(.*)")
PATTERN_GATEWAY6 = re.compile("^ipv6_defaultrouter=(.*)")
# Handles almost all types of IPv6 formats
PATTERN_INET6 = re.compile(r"(inet6 )?(.* )?(((([0-9A-Fa-f]{1,4}:){1,6}:)|(([0-9A-Fa-f]{1,4}:){7}))([0-9A-Fa-f]{1,4}))(( prefixlen )|(/))([0-9\.]{1,3})")
PATTERN_INET = re.compile(r"(inet )?(.* )?(([0-9]{1,3}\.){3}[0-9]{1,3})(( netmask )|(\/))([0-9\.]{1,2})( .*)?")
# Correct group number for the pattern matches above, to get IP/prefix from it
# WARNING change those groups if you change the patterns above!
PATTERN_INET_IP_GROUP = 3
PATTERN_INET_PREFIX_OR_NETMASK_GROUP = 8
PATTERN_INET6_IP_GROUP = 3
PATTERN_INET6_PREFIX_OR_NETMASK_GROUP = 13
PATTERN_ALIAS = re.compile(r"( |^)alias( |$)")
PATTERN_IFACE_NAME = re.compile("([a-z]+)([0-9]+)")
PATTERN_VLAN = re.compile("vlan ([0-9]+)")
PATTERN_VLANDEV = re.compile("vlandev ([a-z0-9\.]+)")
PATTERN_LAGGPROTO = re.compile("laggproto ([a-z]+)")
PATTERN_LAGGPORT = re.compile("laggport ([a-z0-9]+)")
PATTERN_FIB = re.compile("fib ([0-9])")

def refresh_physical_NICs(node):
    """ Get physical NICs """
    # Remove all 'unused' interfaces (may be reimported with the next for loop)
    deletion_list = NetworkInterfaceCard.objects.filter(networkaddressnic=None, networkaddress=None, node=node)
    for to_delete in deletion_list:
        iface_name_match = re.search(PATTERN_IFACE_NAME, to_delete.dev)
        if iface_name_match:
            name = iface_name_match.group(1)
            iface_id = iface_name_match.group(2)
            # Only remove interfaces that cannot represent a NetworkAddress
            if not NetworkAddress.objects.filter(type=name, iface_id=iface_id).exists():
                logger.info(f"Node::refresh_physical_NICs: Deleting obsolete interface {to_delete.dev}")
                to_delete.delete()

    # Now, (re)import found interfaces
    for nic in NetworkInterfaceCard().get_list():
        """ Check if the Network NIC exists """
        try:
            d, created = NetworkInterfaceCard.objects.get_or_create(
                dev=nic,
                node=node)
            if created:
                logger.debug("Node::refresh_physical_NICs: NIC {} exists in database".format(d.dev))
            else:
                logger.info("Node::refresh_physical_NICs: Creating NIC {}".format(nic))
        except Exception as e:
            logger.error(f"Node::refresh_physical_NICs: Could not create physical NICs ->  {e}")
            logger.exception(e)


def parse_ifconfig_key(line, config):
    split = line.split("_")

    if len(split) > 3:
        logger.error(f"Node::parse_ifconfig_key: could not parse line '{line}',"
                        " problem is on '{tmp}' (too many '_', don't know how to read)")
        return False

    if "ipv6" in split:
        split.remove('ipv6')
        config['ipv6'] = True
        config['family'] = 'inet6'
    else:
        config['family'] = 'inet'

    if "alias" in split[-1]:
        logger.debug("Node::parse_ifconfig_key: line is an alias")
        config['nic'] = [split[0]]
        config['type'] = 'alias'

    iface_name_match = re.search(PATTERN_IFACE_NAME, split[-1])
    if not iface_name_match:
        return False

    config['name'] = iface_name_match.group(1)
    config['iface_id'] = iface_name_match.group(2)
    if config['name'] == 'vlan':
        logger.debug("Node::parse_ifconfig_key: line is a vlan configuration")
        config['type'] = 'vlan'
    if config['name'] == 'lagg':
        logger.debug("Node::parse_ifconfig_key: line is a lagg configuration")
        config['type'] = 'lagg'

    return True


def parse_ifconfig_values(line, config):
    parse_success = False

    if line.upper() in ['DHCP', 'SYNCDHCP']:
        logger.debug("Node::parse_ifconfig_values: interface is configured for DHCP")
        config['dhcp'] = True
        config['type'] = "system"
        return True

    if config.get('ipv6'):
        pattern = PATTERN_INET6
        ip_group = PATTERN_INET_IP_GROUP
        prefix_or_netmask_group = PATTERN_INET6_PREFIX_OR_NETMASK_GROUP
    else:
        pattern = PATTERN_INET
        ip_group = PATTERN_INET6_IP_GROUP
        prefix_or_netmask_group = PATTERN_INET_PREFIX_OR_NETMASK_GROUP

    inet_match = re.search(pattern, line)
    if inet_match:
        logger.debug("Node::parse_ifconfig_values: interface has an IP")
        parse_success = True
        config['ip'] = inet_match.group(ip_group)
        logger.debug(f"Node::parse_ifconfig_values: IP {inet_match.group(ip_group)}")
        config['prefix_or_netmask'] = inet_match.group(prefix_or_netmask_group)
        if 'type' not in config:
            if re.search(PATTERN_ALIAS, line):
                config['type'] = 'alias'
            else:
                config['type'] = 'system'

    fib_match = re.search(PATTERN_FIB, line)
    if fib_match:
        logger.debug("Node::parse_ifconfig_values: interface has specific fib")
        config['fib'] = fib_match.group(1)

    vlan_match = re.search(PATTERN_VLAN, line)
    vlandev_match = re.search(PATTERN_VLANDEV, line)
    if vlan_match and vlandev_match:
        logger.debug("Node::parse_ifconfig_values: interface has vlan parameters")
        parse_success = True
        config['vlan'] = vlan_match.group(1)
        config['nic'] = [vlandev_match.group(1)]

    laggproto_match = re.search(PATTERN_LAGGPROTO, line)
    laggport_matches = re.findall(PATTERN_LAGGPORT, line)
    if laggproto_match and laggport_matches:
        logger.debug("Node::parse_ifconfig_values: interface is a Link Aggregation")
        parse_success = True
        config['lagg_proto'] = laggproto_match.group(1)
        config['nic'] = laggport_matches
        logger.debug("line does not define network configuration: configurations are "
                     f"laggproto = {config['lagg_proto']}, laggports = {config['nic']}")

    return parse_success


def parse_gateway_config(line, config):
    gateway_match = re.search(PATTERN_GATEWAY, line)
    have_gateway = False
    if gateway_match:
        logger.debug("Node::parse_gateway_config: this is a gateway (ipv4) configuration line")
        config['defaultgateway'] = gateway_match.group(1)
        have_gateway = True

    gateway6_match = re.search(PATTERN_GATEWAY6, line)
    if gateway6_match:
        logger.debug("Node::parse_gateway_config: this is a gateway (ipv6) configuration line")
        config['defaultgateway_ipv6'] = gateway6_match.group(1)
        have_gateway = True

    return have_gateway


if __name__ == "__main__":

    this_node = Cluster.get_current_node()

    refresh_physical_NICs(this_node)

    """ Read system configuration """
    with open("/etc/rc.conf", "r") as f:

        defaultgateway = None
        defaultgateway_ipv6 = None

        for line in f:
            config = dict()
            line = line.strip()
            ifconfig_match = re.search(PATTERN_IFCONFIG, line)
            ifconfig_parsed = False

            if ifconfig_match:
                key = ifconfig_match.group(1)
                value = ifconfig_match.group(2)

                key_parsed = parse_ifconfig_key(key, config)

                if not key_parsed:
                    logger.error(f"Node::network_sync: Could not parse interface name/ID in '{key}'")
                    logger.debug(config)
                    continue
                elif config['name'] in ("lo", "pflog"):
                    logger.debug(f"Node::network_sync: Internal NIC ({config['name']}), passing.")
                    continue

                logger.debug(f"Node::network_sync: Detected NIC {config['name']}{config['iface_id']}")

                ifconfig_parsed = parse_ifconfig_values(value, config)
                if not ifconfig_parsed:
                    logger.error("Node::network_sync: Could not read configuration value, ignoring")
                    logger.debug(f"Node::network_sync: line was {value}")
                    continue
                if 'type' not in config:
                    logger.error("Node::network_sync: Could not read interface type, ignoring")
                    logger.debug(f"Node::network_sync: line was {value}")
                    continue
                if 'nic' not in config:
                    config['nic'] = [config['name'] + config['iface_id']]

                if config.get('dhcp'):
                    try:
                        proc = subprocess.Popen([
                            '/usr/local/bin/sudo',
                            '/home/vlt-os/scripts/get_dhcp_address.sh',
                            config['nic'][0]],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        success, error = proc.communicate()
                        if error:
                            logger.error("Node::network_sync: {}".format(str(error)))
                            continue
                        else:
                            tmp = success.rstrip().decode('utf-8')
                            config['ip'], config['prefix_or_netmask'], gw = tmp.split(",")
                            logger.debug("Node::network_sync: Found DHCP ip: {}".format(config['ip']))
                            logger.debug("Node::network_sync: Found DHCP netmask/prefix: {}".format(config['prefix_or_netmask']))
                            logger.debug("Node::network_sync: Found DHCP gateway: {}".format(gw))

                        if ":" in config['ip']:
                            config['ipv6'] = True
                            if not defaultgateway_ipv6:
                                defaultgateway_ipv6 = gw
                        else:
                            if not defaultgateway:
                                defaultgateway = gw

                    except Exception as e:
                        logger.error("Node::network_sync: {}".format(str(e)))
                        continue

            else:
                found_gateway = parse_gateway_config(line, config)

                if not found_gateway:
                    logger.info("Node::network_sync: line does not define network configuration, ignoring")
                    continue

            """ If the current line is interface configuration """
            if ifconfig_parsed:
                interfaces = []
                address = None
                try:
                    for nic in config['nic']:
                        iface, _ = NetworkInterfaceCard.objects.get_or_create(
                            dev=nic,
                            node=this_node
                        )
                        interfaces.append(iface)
                except Exception as e:
                    logger.exception(e)
                    continue

                if config['type'] == "system":
                    logger.info("Node::network_sync: Handling system interface configuration...")
                    link = NetworkAddressNIC.objects.filter(
                        network_address__type='system',
                        nic=interfaces[0]
                    ).first()

                    if not link:
                        logger.info(f"Node::network_sync: Creating new IP address on NIC {interfaces[0].dev} : "
                                    f"{config['ip']}/{config['prefix_or_netmask']}")

                        address = NetworkAddress(
                            name="System",
                            type="system",
                            ip=config.get('ip'),
                            prefix_or_netmask=config.get('prefix_or_netmask'),
                            fib=config.get('fib', 0)
                        )
                        address.save()
                    else:
                        logger.info(f"Node::network_sync: Updating IP address on NIC {interfaces[0].dev} : "
                                    f"{config['ip']}/{config['prefix_or_netmask']}")
                        address = link.network_address
                        address.ip = config.get('ip')
                        address.prefix_or_netmask = config.get('prefix_or_netmask')
                        address.fib = config.get('fib', 0)
                        address.save()
                elif config['type'] in ['alias', 'vlan', 'lagg']:
                    logger.info(f"Node::network_sync: Handling {config['type']}{config['iface_id']} configuration...")
                    address, created = NetworkAddress.objects.update_or_create(
                        type=config['type'],
                        iface_id=config['iface_id'],
                        defaults={
                            'name': config['name'] + config['iface_id'],
                            'ip': config.get('ip'),
                            'prefix_or_netmask': config.get('prefix_or_netmask'),
                            'fib': config.get('fib', 0), 
                            'carp_vhid': config.get('carp_vhid', 0),
                            'vlan': config.get('vlan', 0),
                            'lagg_proto': config.get('lagg_proto', ''),
                        })
                    
                    logger.info("Node::network_sync: {} Network Address configuration {}".format("created" if created else "updated", address))



                for iface in interfaces:
                    try:
                        logger.info(f"Node::network_sync: creating/updating interface {iface}")
                        address_nic, created = NetworkAddressNIC.objects.get_or_create(
                            nic=iface,
                            network_address=address)
                        logger.info("Node::network_sync: {} link {}".format("created" if created else "updated", address_nic))
                    except Exception as e:
                        logger.error(f"Node::network_sync: Could not create link {address} -> {iface}")
                        logger.exception(e)
                        continue

        """ Update node with default gateways, if any """
        if defaultgateway or defaultgateway_ipv6:
            if defaultgateway:
                this_node.gateway = defaultgateway.replace('"', '')

            if defaultgateway_ipv6:
                this_node.gateway_ipv6 = defaultgateway_ipv6.replace('"', '')

            this_node.save()

