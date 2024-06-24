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

from toolkit.system.rc import get_rc_config, set_rc_config, remove_rc_config

from ipaddress import IPv4Address, IPv6Address, AddressValueError
from iptools.ipv4 import netmask2prefix
from ast import literal_eval
import subprocess
import logging
import os
import platform
import re

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator

logger = logging.getLogger('system')


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


def is_valid_ip4(ip: str) -> bool:
    try:
        IPv4Address(ip)
        return True
    except AddressValueError:
        return False

def is_valid_ip6(ip: str) -> bool:
    try:
        IPv6Address(ip)
        return True
    except AddressValueError:
        return False

def is_valid_ip(ip: str) -> bool:
    return is_valid_ip4(ip) or is_valid_ip6(ip)

def is_loopback(name: str) -> bool:
    return name.startswith("lo")

def is_valid_hostname(hostname: str) -> bool:
    # Solution taken from this SO answer: https://stackoverflow.com/a/33214423
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False
    parts = hostname.split(".")
    # TLD can't be numeric-only
    if re.match(r"[0-9]+$", parts[-1]):
        return False
    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(part) for part in parts)


def get_hostname():
    """
    This is based on the "hostname" system command from the HOST system (written by write_hostname.sh)

    :return: A String, the hostname of the local node.
    """
    if os.path.exists("/etc/host-hostname"):
        with open("/etc/host-hostname", "r") as f:
            return f.read().strip()
    else:
        return platform.node()


def get_management_ip():
    """

    :return: The Management IP address of the node, as defined during bootstrap
    """

    success, management_ip = get_rc_config(filename="network", variable="management_ip")
    logger.debug(f"get_management_ip: result is '{management_ip}'")
    if success:
        return management_ip

    return None


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


def parse_proxy_url(custom_proxy):
    search = re.search("\w+:\/\/", custom_proxy)
    if not search:
        custom_proxy = f"http://{custom_proxy}"

    validate = URLValidator()
    try:
        validate(custom_proxy)
    except ValidationError:
        return None

    return custom_proxy


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
                command = ['/usr/local/bin/sudo', '/sbin/ifconfig', dev, netif.family, netif.ip_cidr]
                if netif.is_carp:
                    command.extend([
                        'vhid', str(netif.carp_vhid),
                        'advskew', str(address_nic.carp_priority),
                        'pass', str(address_nic.carp_passwd)
                    ])

                if netif.type == "alias":
                    command.append("alias")

                logger.debug(f"ifconfig_call:: running {command}")
                proc = subprocess.Popen(command,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                _, error = proc.communicate()
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
                ip = ip.split('%')[0]
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

    return ret


def destroy_virtual_interface(logger, iface_name):
    """ Destroy an interface

    :param logger: A logger handler
    :param interface: a string representing the exact name of the interface (as seen by the system)
    :return: True / False
    """
    ret = True

    logger.info(f"Node::destroy_virtual_interface: destroying interface {iface_name}")
    _, error = subprocess.Popen(['/usr/local/bin/sudo', '/sbin/ifconfig', iface_name, 'destroy']).communicate()
    if error:
        logger.error(f"Node::destroy_virtual_interface: Could not destroy interface -> {str(error)}")
        ret = False

    return ret


def create_virtual_interface(logger, iface_name):
    """ Create an interface

    :param logger: A logger handler
    :param interface: a string representing the exact name of the interface (as seen by the system)
    :return: True / False
    """
    ret = True

    logger.info(f"Node::create_virtual_interface: creating interface {iface_name}")
    _, error = subprocess.Popen(['/usr/local/bin/sudo', '/sbin/ifconfig', iface_name, 'create']).communicate()
    if error:
        logger.error(f"Node::create_virtual_interface: Could not create interface -> {str(error)}")
        ret = False

    return ret


def recreate_virtual_interface(logger, iface_name):
    """ Recreate an interface

    :param logger: A logger handler
    :param iface_name: a string representing the exact name of the interface (as seen by the system)
    :return: True / False
    """
    return destroy_virtual_interface(logger, iface_name) and create_virtual_interface(logger, iface_name)


def write_management_ips(logger):
    """ Synchronize /etc/rc.conf.d/network file with node IPs
    :param logger: A logger handler
    :return: True or False
    """

    from system.cluster.models import Cluster
    node = Cluster.get_current_node()

    for attr in ['management_ip', 'internet_ip', 'logom_outgoing_ip', 'backends_outgoing_ip']:
        status, error = set_rc_config(
            variable=attr,
            value=getattr(node, attr),
            filename='network')
        if not status:
            logger.error(
                f"Node::write_management_ips: Could not update value of {attr} -> {error}")


def write_network_config(logger):
    """ Synchronize network configuration on disk

    :param logger: A logger handler
    :return: True / False
    """

    from system.cluster.models import (Cluster, NetworkAddressNIC)
    node = Cluster.get_current_node()

    ret = True

    for address_nic in NetworkAddressNIC.objects.filter(nic__node=node):
        address = address_nic.network_address
        nic = address_nic.nic

        if address.type in ['vlan', 'lagg']:
            main_iface = address.main_iface
            status, error = set_rc_config(variable="cloned_interfaces",
                                          value=main_iface,
                                          filename="network",
                                          operation="+=")
            if not status:
                logger.error(f"Node::write_network_config: Could not add {main_iface}"
                             f" to the list of cloned interfaces: {error}")
            else:
                logger.info(f"Node::write_network_config: Added {main_iface} to the list of cloned interfaces")

        nodes_configurations = address.rc_config(node_id=node.pk)
        for configuration in nodes_configurations[node.pk]:
            logger.debug(configuration)
            status, error = set_rc_config(**configuration)
            if not status:
                logger.error(
                    "Node::write_network_config() {}:{}: {}".format(
                        nic.dev, address.ip_cidr, str(error))
                )
                ret = False
                continue
            else:
                logger.info(
                    "Node::write_network_config() {}:{}: Ok".format(
                        nic.dev, address.ip_cidr)
                )
                continue


    """ Network IP addresses are configured: Handle routing """
    # Enable gateways
    configs = [
        ("gateway_enable", "YES"),
        ("ipv6_gateway_enable", "YES"),
    ]

    # Set default routers
    if node.gateway:
        configs.append(("defaultrouter", node.gateway))
    if node.gateway_ipv6:
        configs.append(("ipv6_defaultrouter", node.gateway_ipv6))

    # Get parsed static routes
    for static_route in node.parsed_static_routes:
        configs.append(static_route)

    # Remove all past routing config
    status, removed = remove_rc_config(".*route.*")
    logger.info(f"Node::write_network_config(): removed old routing configurations {removed}")

    # Apply configurations
    logger.info(f"Node::write_network_config(): setting new routing configuration {configs}")
    for config in configs:
        status, error = set_rc_config(variable=config[0], value=config[1])
        if not status:
            logger.error(
                f"Node::write_network_config(routing): {config[0]} -> {str(error)}"
            )
            ret = False
            continue
        else:
            logger.info(
                f"Node::write_network_config(routing): {config[0]} -> Ok"
            )
            continue

    return ret


def remove_netif_configs(logger, rc_confs):
    if isinstance(rc_confs, str):
        rc_confs = literal_eval(rc_confs)
    
    from system.cluster.models import Cluster
    node = Cluster.get_current_node()

    message = ""

    node_rc_confs = rc_confs.get(node.id)
    if node_rc_confs:
        for rc_conf in node_rc_confs:
            if rc_conf.get('operation') == "+=":
                rc_conf['operation'] = "-="
                status, tmp = set_rc_config(variable=rc_conf['variable'], value=rc_conf['value'], operation="-=", filename=rc_conf.get('filename', None))
            else:
                status, tmp = remove_rc_config(variable_regexp=rc_conf['variable'], filename=rc_conf.get('filename', None))

            message += str(tmp) + "\n"

            if not status:
                logger.error(f"Node::remove_netif_configs: a problem occurred while trying to remove configuration {rc_conf}")
            else:
                logger.info(f"Node::remove_netif_configs: successfuly removed configuration {rc_conf}")

    return message


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
        logger.error(f"Failed to call script {script} : {errors}")
        return False


def delete_hostname(logger, hostname):
    """Remove hostname/IP from /etc/hosts
    
    :param logger:        API logger (to be called by an API request)
    :param hostname:      String containing the remote hostname to delete
    :return:
    """
    if not is_valid_hostname(hostname):
        return False

    script = "/home/vlt-os/scripts/add_to_hosts.py"
    proc = subprocess.Popen(['/usr/local/bin/sudo', script, hostname, "0.0.0.0", "delete"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res, errors = proc.communicate()
    if not errors:
        return True
    else:
        logger.error(f"Failed to call script {script} : {errors}")
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
