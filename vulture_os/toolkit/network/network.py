#!/home/vlt-os/env/bin/python
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
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'System Utils Network Toolkit'


from iptools.ipv4 import netmask2prefix
from ast import literal_eval
import subprocess
import logging
import glob
import os
import re

logger = logging.getLogger('system')


MANAGEMENT_IP_PATH = "/usr/local/etc/management.ip"

JAIL_ADDRESSES = {
    'apache': {
        'inet': "127.0.0.6",
        'inet6': "fd00::206",
    },
    'mongodb': {
        'inet': "127.0.0.2",
        'inet6': "fd00::202",
    },
    'redis': {
        'inet': "127.0.0.3",
        'inet6': "fd00::203",
    },
    'rsyslog': {
        'inet': "127.0.0.4",
        'inet6': "fd00::204",
    },
    'haproxy': {
        'inet': "127.0.0.5",
        'inet6': "fd00::205",
    },
    'portal': {
        'inet': "127.0.0.7",
        'inet6': "fd00::207",
    },
}


def get_hostname():
    """
    This is based on the "hostname" system command from the HOST system (written by write_hostname.sh)

    :return: A String, the hostname of the local node.
    """
    with open("/etc/host-hostname", "r") as f:
        return f.read().strip()


def get_management_ip():
    """

    :return: The Management IP address of the node, as defined during bootstrap
    """

    with open(MANAGEMENT_IP_PATH, "r") as f:
        return f.read().strip()

    return False


def get_proxy(openvpn_format=False):
    """
    return the configured proxy settings from /etc/rc.conf.proxy

    :return: A ready-to-use dict for python request, or
        None in case of no proxy

        if openvpn_format is True, then return https_proxy in the form of a tuple (ip_adress, port)
    """
    proxy = {}
    if os.path.exists("/etc/rc.conf.proxy"):
        http_proxy = None
        https_proxy = None
        ftp_proxy = None
        try:
            with open("/etc/rc.conf.proxy") as tmp:
                buf = tmp.read()
                lst = re.findall('http_proxy=\"?([^\"\n]*)\"?', buf)
                if len(lst):
                    http_proxy = lst[0]
                    if http_proxy == "":
                        http_proxy = lst[1]

                lst = re.findall('https_proxy=\"?([^\"\n]*)\"?', buf)
                if len(lst):
                    https_proxy = lst[0]
                elif http_proxy:
                    https_proxy = http_proxy

                lst = re.findall('ftp_proxy=\"?([^\"\n]*)\"?', buf)
                if len(lst):
                    ftp_proxy = lst[0]
                elif http_proxy:
                    ftp_proxy = http_proxy

                proxy = {
                    "http": http_proxy,
                    "https": https_proxy,
                    "ftp": ftp_proxy
                }

        except Exception:
            pass

        if openvpn_format:
            if https_proxy:
                return https_proxy.split(":")
            elif http_proxy:
                return http_proxy.split(":")
            else:
                return None

    return proxy


def get_sanitized_proxy():
    """
    Return the proxy settings of /etc/rc.conf.proxy (using get_proxy()) after sanitation
    WARNING: DOES NOT CHECK IP VALIDITY, only tries to recover ip and port from an address of the form *ip:port*
    :return: A set of tuples in the form (ip/hostname, port)
    """
    proxy_raws = get_proxy()
    proxy_set = set()
    for key, value in proxy_raws.items():
        if value:
            if "]" in value:
                fields = value.split("[")[-1].split("]")
                ip = fields[-2]
                port = fields[-1]
                ip = re.sub("[^a-fA-F0-9:]", "", ip)
                port = re.sub("[^0-9]", "", port)
                if not ip or not port:
                    logger.error("proxy is incorrect")
                else:
                    proxy_set.add((ip, port))
            else:
                fields = value.split(":")
                ip = fields[-2]
                port = fields[-1]
                ip = re.sub("[^0-9\.]", "", ip)
                port = re.sub("[^0-9]", "", port)
                if not ip or not port:
                    logger.error("proxy is incorrect")
                else:
                    proxy_set.add((ip, port))

    return proxy_set


def ifconfig_call(logger, netif_id):
    """
        Call ifconfig to activate the given NetworkAddress()  on system

    :param logger: A logger handler
    :param netif_id: The _id of the related Network Address we are working on
    :return: True / False
    """

    from system.cluster.models import (Cluster, NetworkInterfaceCard,
                                       NetworkAddressNIC)
    node = Cluster.objects.get().get_current_node()

    ret = True
    for nic in NetworkInterfaceCard.objects.filter(node=node):
        for address_nic in NetworkAddressNIC.objects.filter(nic=nic, network_address_id=netif_id):
            dev = address_nic.nic.dev
            netif = address_nic.network_address
            try:
                if not netif.is_carp:
                    logger.info("Node::ifconfig_call() Creating / Updating network interface: {}:{}".format(
                        dev,
                        netif.ip_cidr
                    ))

                    if netif.is_system:
                        logger.debug(
                            'Node::ifconfig_call() /usr/local/bin/sudo /sbin/ifconfig {} {} {}'.format(
                                dev,
                                netif.family,
                                netif.ip_cidr
                            ))

                        proc = subprocess.Popen(['/usr/local/bin/sudo', '/sbin/ifconfig',
                                                 dev, netif.family, netif.ip_cidr],
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    else:
                        logger.debug(
                            'Node::ifconfig_call() /usr/local/bin/sudo /sbin/ifconfig {} {} {} alias'.format(
                                dev,
                                netif.family,
                                netif.ip_cidr
                            ))
                        proc = subprocess.Popen(['/usr/local/bin/sudo', '/sbin/ifconfig',
                                                 dev, netif.family, netif.ip_cidr, 'alias'],
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                else:
                    logger.info(
                        "Node::ifconfig_call() Creating / Updating CARP network interface: {}:{}".format(
                            dev,
                            netif.ip_cidr
                        ))

                    logger.debug(
                        'Node::ifconfig_call() /usr/local/bin/sudo /sbin/ifconfig {} {} {} vhid {} advskew {} pass {} {}'.format(
                            dev,
                            netif.family,
                            netif.ip_cidr,
                            str(netif.carp_vhid),
                            str(address_nic.carp_priority),
                            str(address_nic.carp_passwd),
                            'alias')
                    )

                    proc = subprocess.Popen([
                        '/usr/local/bin/sudo', '/sbin/ifconfig',
                        dev, netif.family, netif.ip_cidr, 'vhid',
                        str(netif.carp_vhid), 'advskew',
                        str(address_nic.carp_priority), 'pass',
                        str(address_nic.carp_passwd), 'alias'],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                success, error = proc.communicate()
                if error:
                    logger.error("Node::ifconfig_call() Error on '{}' with IP '{}': {}".format(
                        dev, netif.ip_cidr, str(error)))
                    ret = False
                    continue
                else:
                    logger.info("Node::ifconfig_call() {}: IP address {} is UP".format(dev, netif.ip_cidr))
                    continue

            except Exception as e:
                logger.error("Node::ifconfig_call(): {}".format(str(e)))
                ret = False
                continue

    return ret


def address_cleanup(logger):
    """
        Call ifconfig DOWN and delete useless network interfaces

    :param logger: A logger handler
    :return: True / False
    """

    from system.cluster.models import Cluster, NetworkInterfaceCard
    node = Cluster.get_current_node()

    ret = True
    for nic in NetworkInterfaceCard.objects.filter(node=node):

        """ Do an ifconfig delete on running IP Address that
        do not exists anymore """
        for addr in nic.get_running_addresses():
            ip, prefix = addr.split("/")
            if ":" in ip:
                family = "inet6"
            else:
                family = "inet"

            found = False
            for netif in node.addresses(nic):
                if netif.ip == ip:
                    if "/" in netif.prefix_or_netmask:
                        netif.prefix = netif.prefix_or_netmask[1:]
                    else:
                        netif.prefix = netmask2prefix(netif.prefix_or_netmask)
                        if netif.prefix == 0:
                            netif.prefix = netif.prefix_or_netmask

                    if netif.family == "inet" and str(netif.prefix) == str(prefix):
                        logger.debug("Node::address_cleanup(): IPv4 {}/{} has been found on {}".format(
                            ip,
                            prefix,
                            nic.dev
                        ))
                        found = True
                    elif netif.family == "inet6" and str(prefix) == str(netif.prefix_or_netmask):
                        logger.debug("Node::address_cleanup(): IPv6 {}/{} has been found on {}".format(
                            ip,
                            prefix,
                            nic.dev
                        ))
                        found = True

            """ IP Address not found: Delete it """
            if not found:
                logger.info(
                    "Node::address_cleanup(): Deleting {}/{} on {}".format(
                        ip, prefix, nic.dev
                    ))

                logger.debug('Node::address_cleanup() /usr/local/bin/sudo /sbin/ifconfig {} {} {} delete'.format(
                    nic.dev,
                    family, str(ip) + "/" + str(prefix))
                )

                proc = subprocess.Popen([
                    '/usr/local/bin/sudo', '/sbin/ifconfig',
                    nic.dev, family, str(ip) + "/" + str(prefix), 'delete'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                success, error = proc.communicate()
                if error:
                    logger.error(
                        "Node::address_cleanup(): {}".format(str(error)))

                """ Delete the permanent configuration file """
                for conf in glob.glob("/etc/rc.conf.d/netaliases*"):
                    with open(conf, 'r') as f:
                        delete = False
                        for line in f:
                            if nic.dev in line and str(ip) + "/" + str(prefix) in line and family in line:
                                delete = True
                                logger.debug("Node::address_cleanup(): Line to delete {}".format(line))

                    if delete:
                        logger.info("Node::address_cleanup(): Deleting {}".format(conf))
                        proc = subprocess.Popen(['/usr/local/bin/sudo', '/bin/rm', conf],
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        success, error = proc.communicate()
                        if error:
                            logger.error("Node::address_cleanup(): {}".format(str(error)))
                            ret = False
                            continue
                        else:
                            logger.info("Node::address_cleanup() {}: Ok".format(conf))

    return ret


def write_network_config(logger):
    """ Synchronize network configuration on disk

     :param logger: A logger handler
    :param netif_id: The _id of the related Network Address we are working on
    :return: True / False
    """

    from system.cluster.models import (Cluster, NetworkInterfaceCard,
                                       NetworkAddressNIC)
    node = Cluster.get_current_node()

    ret = True

    i = 0
    has_system = False
    for nic in NetworkInterfaceCard.objects.filter(node=node):
        j = 0
        for address_nic in NetworkAddressNIC.objects.filter(nic=nic):
            address = address_nic.network_address

            # Aliases address
            if address.is_system is False:
                config = address.rc_config(nic.dev).format(j)
                args = 'netaliases{}{}'.format(i, j)
                loop = "0"
            else:
                # System address
                config = address.rc_config(nic.dev, True)
                args = 'network'
                if not has_system:
                    loop = "0"
                    has_system = True
                else:
                    loop = str(i + j)

            try:
                proc = subprocess.Popen([
                    '/usr/local/bin/sudo', '/home/vlt-os/scripts/write_netconfig.sh',
                    config,
                    args,
                    loop
                ],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                success, error = proc.communicate()

                if error:
                    logger.error(
                        "Node::write_network_config() {}:{}: {}".format(
                            nic.dev, address.ip_cidr, str(error))
                    )
                    ret = False
                    continue
                else:
                    j = j + 1
                    logger.info(
                        "Node::write_network_config() {}:{}: Ok".format(
                            nic.dev, address.ip_cidr)
                    )
                    continue

            except Exception as e:
                logger.error("Node::write_network_config(): {}".format(str(e)))
                ret = False
                continue

        i = i + 1

    """ Network IP address are configured: Handle routing """
    config = "_EOL"
    config += "gateway_enable=\"NO\" _EOL"
    config += "ipv6_gateway_enable=\"NO\" _EOL"
    if node.gateway:
        config += "defaultrouter=\"{}\" _EOL".format(node.gateway)

    if node.gateway_ipv6:
        config += "ipv6_defaultrouter=\"{}\" _EOL".format(node.gateway_ipv6)

    if node.static_routes:
        config += "{}_EOL".format(node.static_routes.replace("\n", "_EOL"))

    try:
        proc = subprocess.Popen([
            '/usr/local/bin/sudo', '/home/vlt-os/scripts/write_netconfig.sh',
            config,
            'routing',
            str(0)
        ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        success, error = proc.communicate()

        if error:
            logger.error(
                "Node::write_network_config(routing) : {}".format(str(error))
            )
            ret = False
        else:
            logger.info("Node::write_network_config(routing) : Ok")

    except Exception as e:
        logger.error("Node::write_network_config(routing): {}".format(str(e)))
        ret = False

    return ret


def restart_routing(logger):
    """
    Call service routing restart
    :param logger:
    :return: True / False
    """
    try:
        proc = subprocess.Popen([
            '/usr/local/bin/sudo', 'service',
            'routing', 'restart'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate()

    except Exception as e:
        logger.error("Node::restart_routing(): {}".format(str(e)))
        return False
    logger.info("Node::restart_routing(): OK")
    return True


def make_hostname_resolvable(logger, hostname_ip):
    """Add hostname/IP to /etc/hosts in order to make
    hostname resolvable. If hostname is already define, its IP is replaced

    :param logger:        API logger (to be called by an API request)
    :param hostname_ip:   A tuple containing (hostname, ip)
    :return:
    """
    if isinstance(hostname_ip, str):
        hostname, ip = literal_eval(hostname_ip)
    else:
        hostname, ip = hostname_ip

    script = "/home/vlt-os/scripts/add_to_hosts.py"
    proc = subprocess.Popen(['/usr/local/bin/sudo', script, hostname, ip],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res, errors = proc.communicate()
    if not errors:
        return True
    else:
        logger.error("Failed to call script {} : {}".format(script, errors))
        return False


def refresh_nic(logger):
    """
    Used by API calls to update mongodb with new system NIC / addresses
    :param node: node
    :return:
    """

    from system.cluster.models import Cluster
    node = Cluster.get_current_node()
    return node.synchronizeNICs()
