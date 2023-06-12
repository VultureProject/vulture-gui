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

from system.cluster.models import (Cluster, Node, NetworkInterfaceCard,
                                NetworkAddress, NetworkAddressNIC)



import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('daemon')

import re
import subprocess

if __name__ == "__main__":

    this_node = Cluster.get_current_node()

    """ Get physical NICs """
    for nic in NetworkInterfaceCard().get_list():
        """ Check if the Network NIC exists """
        try:
            d = NetworkInterfaceCard.objects.get(dev=nic, node=this_node)
            logger.debug("Node::network_sync(): NIC {} exists in database".format(d.dev))
        except NetworkInterfaceCard.DoesNotExist:
            """ New Network NIC: Add it to the system """
            logger.info("Node::network_sync(): Creating NIC {}".format(nic))
            d = NetworkInterfaceCard.objects.create(dev=nic, node=this_node)


    """ Read system configuration """
    with open("/etc/rc.conf", "r") as f:
        # logger.debug(f"reading configuration in {filepath}")
        pattern_ifconfig = re.compile('^ifconfig_(.*)="?\'?([^"\']*)"?\'?')
        pattern_inet6 = re.compile("(inet6 )?(.*)(( prefixlen )|(/))([0-9\.]+)")
        pattern_inet = re.compile("(inet )?(.*)(( netmask )|(/))([0-9\.]+)")
        pattern_gateway = re.compile("^defaultrouter=(.*)")
        pattern_gateway6 = re.compile("^ipv6_defaultrouter=(.*)")
        pattern_vlan = re.compile("vlan ([0-9]+)")
        pattern_vlandev = re.compile("vlandev ([a-z0-9\.]+)")
        pattern_fib = re.compile("fib ([0-9])")

        defaultgateway = None
        defaultgateway_ipv6 = None

        for line in f:
            have_gateway = False
            line = line.rstrip()
            m = re.search(pattern_ifconfig, line)
            nic = None
            ip = None
            vlan = None
            vlandev = None
            fib = None
            prefix_or_netmask = None
            gw = None
            ipv6 = False
            config = None
            family = None

            if m:
                tmp = m.group(1)
                config = m.group(2)
                if "ipv6" in tmp and len(tmp.split("_")) == 2:
                    nic, ipv6 = tmp.split("_")
                    ipv6 = True
                else:
                    nic = tmp
                    if "inet6" in config:
                        ipv6 = True
                    else:
                        ipv6 = False

                if not nic:
                    logger.error("Node::network_sync(): Unable to retrieve config: Unknown NIC !")
                    continue
                elif nic in ("lo0", "pflog0"):
                    logger.debug("Node::network_sync(): Internal NIC ({}), passing.".format(nic))
                    continue
                elif "_alias" in tmp:
                    logger.info(f"Found an alias configuration for interface {nic}, ignoring")
                    continue
                else:
                    logger.debug("Node::network_sync(): Detected NIC {}".format(nic))


            if config and config.upper() in ("SYNCDHCP", "DHCP"):
                try:
                    proc = subprocess.Popen([
                        '/usr/local/bin/sudo',
                        '/home/vlt-os/scripts/get_dhcp_address.sh',
                        nic],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    success, error = proc.communicate()
                    if error:
                        logger.error("Node::network_sync(): {}".format(str(error)))
                        continue
                    else:
                        tmp = success.rstrip().decode('utf-8')
                        ip, prefix_or_netmask, gw = tmp.split(",")
                        logger.debug("Node::network_sync(): Found DHCP ip: {}".format(ip))
                        logger.debug("Node::network_sync(): Found DHCP netmask/prefix: {}".format(prefix_or_netmask))
                        logger.debug("Node::network_sync(): Found DHCP gateway: {}".format(gw))

                    if ":" in ip:
                        ipv6 = True
                        family = "inet6"
                        if not defaultgateway_ipv6:
                            defaultgateway_ipv6 = gw
                    else:
                        ipv6 = False
                        family = "inet"
                        if not defaultgateway:
                            defaultgateway = gw

                except Exception as e:
                    logger.error("Node::network_sync(): {}".format(str(e)))
                    continue

            elif config:

                if ipv6 is True:
                    pattern = pattern_inet6
                    family = "inet6"
                else:
                    pattern = pattern_inet
                    family = "inet"

                m = re.search(pattern, config)
                if m:
                    ip = m.group(2)
                    prefix_or_netmask = m.group(6)

                if not ip:
                    logger.info("Node::network_sync(): Warning: No IP address associated to {}".format(nic))
                    continue

                if not prefix_or_netmask:
                    logger.error("Node::network_sync(): Unable to retrieve prefix_or_netmask !")
                    continue

                m = re.search(pattern_vlan, config)
                if m:
                    vlan = m.group(1)

                m = re.search(pattern_vlandev, config)
                if m:
                    vlandev = m.group(1)

                m = re.search(pattern_fib, config)
                if m:
                    fib = m.group(1)

            else:
                m = re.search(pattern_gateway, line)
                if m:
                    defaultgateway = m.group(1)
                    logger.debug("Node::network_sync(): Found default gateway: {}".format(defaultgateway))
                    have_gateway = True

                m = re.search(pattern_gateway6, line)
                if m:
                    defaultgateway_ipv6 = m.group(1)
                    logger.debug("Node::network_sync(): Found default IPV6 gateway: {}".format(defaultgateway_ipv6))
                    have_gateway = True

                if not have_gateway:
                    logger.info("Node::network_sync(): line does not define gateway configuration, ignoring")
                    continue

            """ If the current line is not a gateway """
            if not have_gateway:
                try:
                    d = NetworkInterfaceCard.objects.get(dev=nic, node=this_node)
                except NetworkInterfaceCard.DoesNotExist as e:
                    continue

                # Prevent None insertion into Mongo
                if not ip:
                    logger.error("Node::network_sync(): IP address found is NULL.")
                    continue

                """ Check if the ip / netmask have changed """
                have_one = False
                for address_nic in NetworkAddressNIC.objects.filter(nic=d):
                    if address_nic.network_address.is_system and address_nic.network_address.family == family:
                        have_one = True
                        existing_address = address_nic.network_address

                """ No existing IP address on this NIC
                    This is a first call => Just create the IP Address
                """

                if not have_one:
                    logger.info("Node::network_sync(): Creating new IP address on NIC {} : {}/{}".format(d.dev, ip, prefix_or_netmask))
                    if vlandev:
                        try:
                            vd = NetworkInterfaceCard.objects.get(dev=str(vlandev), node=this_node)
                        except NetworkInterfaceCard.DoesNotExist as e:
                            logger.error("Node::network_sync(): Unable to find nic related to '{}'".format(vlandev))
                            continue

                        vlandev = vd

                    existing_address = NetworkAddress(
                        name="System",
                        ip=ip,
                        prefix_or_netmask=prefix_or_netmask,
                        is_system=True,
                        carp_vhid=0,
                        vlan=vlan,
                        vlandev=vlandev,
                        fib=fib
                    )
                    existing_address.save()
                    NetworkAddressNIC.objects.create(nic=d, network_address=existing_address)

                elif existing_address.ip != ip or existing_address.prefix_or_netmask != prefix_or_netmask:
                    logger.info("Node::network_sync(): Updating IP address on NIC {} : {}/{} {} {} {}".format(d.dev, ip, prefix_or_netmask, vlan, vlandev, fib))
                    existing_address.ip = ip
                    existing_address.prefix_or_netmask = prefix_or_netmask
                    existing_address.vlan = vlan
                    existing_address.vlandev = vlandev
                    existing_address.fib = fib
                    existing_address.save()

        """ Update node with default gateways, if any """
        if defaultgateway or defaultgateway_ipv6:
            if defaultgateway:
                this_node.gateway = defaultgateway.replace('"', '')

            if defaultgateway_ipv6:
                this_node.gateway_ipv6 = defaultgateway_ipv6.replace('"', '')

            this_node.save()

        """ Garbage collector: Delete from mongodb interfaces that may not exists anymore """
        # FIXME
