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
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Cluster main models'


from system.config.models import Config

from toolkit.network.network import is_valid_ip4, is_valid_ip6, is_valid_hostname, is_loopback
from toolkit.network.route import get_route_interface
from toolkit.mongodb.mongo_base import MongoBase
from toolkit.redis.redis_base import RedisBase
from toolkit.mongodb.mongo_base import parse_uristr

from django.db.models import Q
from django.db.utils import DatabaseError
from django.utils.translation import gettext as _
from django.utils.module_loading import import_string
from django.utils import timezone
from django.conf import settings
from django.forms.models import model_to_dict
from djongo import models
import subprocess
import ipaddress
from iptools.ipv4 import netmask2prefix
import time

from applications.logfwd.models import LogOM, LogOMRELP, LogOMHIREDIS, LogOMFWD, LogOMElasticSearch, LogOMMongoDB, LogOMKAFKA
from system.pki.models import X509Certificate
from services.exceptions import ServiceExit

from re import findall as re_findall, compile as re_compile

import logging
import logging.config

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


JAILS = ("apache", "mongodb", "redis", "rsyslog", "haproxy")

STATE_CHOICES = (
    ('UP', 'UP'),
    ('DOWN', 'DOWN'),
    ('MAINTENANCE', 'MAINTENANCE')
)

NET_ADDR_TYPES = (
    ('system', 'System'),
    ('alias', 'Alias'),
    ('vlan', 'Vlan'),
    ('lagg', 'Link Aggregation'),
)

LAGG_PROTO_TYPES = (
    ('failover', 'Failover'),
    ('lacp', 'LACP'),
    ('loadbalance', 'Load Balance'),
    ('roundrobin', 'RoundRobin'),
    ('broadcast', 'Broadcast'),
    ('none', 'Disabled'),
)


class APISyncResultTimeOutException(Exception):
    pass


class Node(models.Model):
    """
    A vulture Node
    """

    class Meta:
        app_label = "system"

    name = models.TextField(unique=True)

    pf_limit_states = models.IntegerField(default=500000)
    pf_limit_frags = models.IntegerField(default=25000)
    pf_limit_src = models.IntegerField(default=50000)
    pf_custom_param_config = models.TextField(blank=True, default="### Custom global parameters\n")
    pf_custom_nat_config = models.TextField(blank=True, default="### Custom NAT rules\n")
    pf_custom_rdr_config = models.TextField(blank=True, default="### Custom RDR rules\n")
    pf_custom_config = models.TextField(blank=True, default="")
    gateway = models.TextField(blank=True)
    gateway_ipv6 = models.TextField(blank=True)
    static_routes = models.TextField(
        blank=True,
        default='#static_routes=\"net1 net2\"\n'
        '#route_net1=\"-net 192.168.0.0/24 192.168.0.1\"\n'
        '#route_net2=\"-net 192.168.1.0/24 192.168.1.1\"\n'
    )
    management_ip = models.TextField(unique=True)
    internet_ip = models.GenericIPAddressField(help_text=_("IP used by jails to contact internet"))
    backends_outgoing_ip = models.GenericIPAddressField(default="", help_text=_("IP used for masquerading backends packets"))
    logom_outgoing_ip = models.GenericIPAddressField(default="", help_text=_("IP used for masquerading log forwarders packets"))
    scanner_ip = models.ForeignKey(to="NetworkAddress", null=True, on_delete=models.SET_NULL,
                                   help_text=_("NAT IP used for scanner"),
                                   verbose_name=_("Scanner IP"))
    pstats_forwarders = models.ArrayReferenceField(to="applications.LogOM",
                                                   null=True,
                                                   blank=False,
                                                   verbose_name=_("Send rsyslog pstats logs to"),
                                                   help_text=_("Log forwarders used to send impstats logs"))
    _vstate = models.TextField(
        default=STATE_CHOICES[0][0],
        choices=STATE_CHOICES,
        help_text=_("Node state")
    )
    heartbeat = models.DateTimeField(
        default=timezone.now,
        help_text=_("Last node heartbeat")
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __str__(self):
        return self.name

    def to_small_dict(self):
        """ Return dictionnary of object attributes """
        return {
            "id": str(self.id),
            "name": self.name,
            "management_ip": self.management_ip,
            "internet_ip": self.internet_ip,
            "pf_limit_states": self.pf_limit_states,
            "pf_limit_frags": self.pf_limit_frags,
            "pf_limit_src": self.pf_limit_src,
            "pf_custom_config": self.pf_custom_config,
            "pf_custom_param_config": self.pf_custom_param_config,
            "pf_custom_rdr_config": self.pf_custom_rdr_config,
            "pf_custom_nat_config": self.pf_custom_nat_config,
            "gateway": self.gateway,
            "gateway_ipv6": self.gateway_ipv6,
            "static_routes": self.static_routes
        }

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "id" in fields:
            result['id'] = str(result['id'])
        if not fields or "intfs" in fields:
            excluded_intf = ("lo0", "lo1", "lo2", "lo3", "lo4", "lo5", "lo6", "pflog0", "vm-public", "tap0", "tun0")
            result['intfs'] = [n.to_dict() for n in NetworkInterfaceCard.objects.filter(node=self).exclude(dev__in=excluded_intf)]
        if not fields or "is_master_mongo" in fields:
            result['is_master_mongo'] = self.is_master_mongo
        if not fields or "mongo_state" in fields:
            result['mongo_state'] = self.mongo_state
        if not fields or "mongo_version" in fields:
            result['mongo_version'] = self.mongo_version
        if not fields or "is_standalone" in fields:
            result['is_standalone'] = self.is_standalone
        if not fields or "is_configured" in fields:
            result['is_configured'] = self.is_configured
        if not fields or "is_master_redis" in fields:
            result['is_master_redis'] = self.is_master_redis
        if not fields or "configured_forwarders" in fields:
            result['configured_forwarders'] = len(self.get_forwarders_enabled)
        if not fields or "configured_backends" in fields:
            result['configured_backends'] = len(self.get_backends_enabled)
        if not fields or "unix_timestamp" in fields:
            result['unix_timestamp'] = time.time()
        if not fields or "pstats_forwarders" in fields:
            result['pstats_forwarders'] = [p.to_dict() for p in self.pstats_forwarders.all()]
        return result

    def api_request(self, action, config=None, internal=False):
        """

        :param action:    The requested action
        :param config:    The associated config
        :param internal:  Is this request internal ? Means that it will not be shown to the admin
        :return:
            { 'status': True, 'message': 'A meaningfull message' }
            { 'status': False, 'message': 'A meaningfull message' }
        """

        return Cluster.api_request(action, config, self, internal=internal)

    def synchronizeNICs(self):
        """
        This call the net2mongo.py script in order to read
            system's network configuration and put it in mongodb
         - System wins for "Mains IPs": Mongodb will be overrided
        :return: True / False
        """

        proc = subprocess.Popen(['/home/vlt-os/env/bin/python',
                                 '/home/vlt-os/scripts/net2mongo.py'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        success, error = proc.communicate()
        # Logger are inside the script
        if not error:
            return True
        logger.error("[synchronizeNICs] ERROR :: net2mongo : {}".format(error))
        return False

    def to_template(self):
        """ Dictionary used to create configuration file related to the node
        :return     Dictionnary of configuration parameters
        """

        addresses = list()
        for nic in NetworkInterfaceCard.objects.filter(node=self):
            for address in NetworkAddress.objects.filter(nic=nic):
                data = str(address.ip) + " on " + str(nic.dev)
                if address.is_carp:
                    data = " (CARP vhid = {})".format(address.carp_vhid)

                addresses.append(data)

        conf = {
            'id': str(self.id),
            'name': self.name,
            'state': self.state,
            'pf_limit_states': self.pf_limit_states,
            'pf_limit_frags': self.pf_limit_frags,
            'pf_limit_src': self.pf_limit_src,
            'addresses': addresses,
            'is_master_redis': self.is_master_redis,
            'is_master_mongo': self.is_master_mongo,
            'mongo_state': self.mongo_state,
            'is_standalone': self.is_standalone
        }

        return conf

    @property
    def is_standalone(self):
        """
        Check if the current Node is a member of mongoDB
        :return: True / False, or None in case of a failure
        """
        c = MongoBase()
        if c.connect():
            c.connect_primary()
            config = c.db.admin.command("replSetGetConfig")['config']
            return len(config['members']) == 1

        return True

    @property
    def is_master_mongo(self):
        """
        Check if the current Node is master or not
        :return: True / False, or None in case of a failure
        """
        c = MongoBase()
        ok = c.connect()
        if ok:
            primary_node = c.get_primary()
        else:
            return None

        if ok and primary_node == self.name + ':9091':
            return True
        elif ok:
            return False

        return None

    @property
    def mongo_state(self):
        """
        Check state of the current Node
        :return: state returned by mongo
        """
        c = MongoBase()
        if c.connect():
            members = c.repl_state()
            for member in members:
                if member['name'] == self.name + ':9091':
                    return member.get('stateStr')
        return "UNKNOWN"

    @property
    def mongo_version(self):
        """
        Get version of mongo on the current Node
        :return: string of version number returned by mongo
        """
        c = MongoBase()
        if c.connect():
            return c.get_version()
        return ""

    @property
    def is_master_redis(self):
        """
        Check if the current Node is master or not
        :return: True / False, or None in case of a failure
        """

        if self.management_ip:
            c = RedisBase(password=Cluster.get_global_config().redis_password)
            master_node = c.get_master(self.name)
            if master_node == self.name:
                return True
            elif master_node:
                return False

        return None

    @property
    def is_configured(self):
        if self.management_ip:
            return True

        return False

    @property
    def parsed_static_routes(self):
        rc_pattern = re_compile(r"^([a-zA-Z0-9_-]+)\s?=\s?('|\")([^'\"]+)\2$")
        for line in self.static_routes.split('\n'):
            # Remove all commented parts
            line = line.split('#')[0].strip()
            if not line:
                # Drop empty lines
                continue
            matched = rc_pattern.match(line)
            if matched:
                yield matched.group(1), matched.group(3)


    def addresses(self, nic=None):
        """
        Return the list of network addresses on the current node, or node/nic
        :param nic: Optional NIC
        :return: list
        """
        addresses = list()
        if not nic:
            for nic in NetworkInterfaceCard.objects.filter(node=self):
                addresses.extend(list(NetworkAddress.objects.filter(nic=nic)))
        else:
            addresses.extend(list(NetworkAddress.objects.filter(nic=nic)))

        return addresses

    @property
    def network_interfaces(self):
        return list(NetworkInterfaceCard.objects.filter(node=self))

    @property
    def get_listeners_enabled(self):
        """ Return all listeners used by an enabled Frontend """
        from services.frontend.models import Listener
        """ Retrieve network addresses on the current node """
        addresses = self.addresses()
        """ Retrieve all Listeners that uses those network addresses """
        listeners = Listener.objects.filter(network_address__in=addresses, frontend__enabled=True)
        listeners_enabled = list()
        for l in listeners:
            """ Protocol is tcp in any case,
               except for frontend mode=log => proto will be tcp or udp or tcp,udp
                                                       listening_mode attribute """
            proto = "tcp"
            if l.frontend.mode == "log" and "udp" in l.frontend.listening_mode:
                proto = l.frontend.listening_mode
            elif l.frontend.mode == "filebeat" and l.frontend.filebeat_listening_mode == "udp":
                proto = l.frontend.filebeat_listening_mode
            """ Return (ip, port, interface.family) """
            listeners_enabled.append((l.whitelist_ips, l.network_address.ip, l.port, l.rsyslog_port,
                                      proto, l.network_address.family, l.max_src, l.max_rate))
        return listeners_enabled

    @property
    def get_forwarders_enabled(self):
        """ Return all tuples (family, proto, ip, port) for each LogForwarders """
        output_ips = set()
        """ Retrieve LogForwarders used in enabled Frontends """
        """ First, retrieve LogForwarders that bind to the address of the node """
        addresses = self.addresses()
        """ For each address, retrieve the associated listeners having frontend enabled """
        listener_ids = list()
        for a in addresses:
            listener_ids.extend([l.id for l in a.listener_set.filter(frontend__enabled=True)])

        query_filter = Q(enabled=True) &\
            Q(frontend_set__isnull=False) &\
            (
                Q(frontend_set__listener__in=listener_ids) |
                Q(frontend_set__node=self) |
                Q(frontend_set__node=None)
            )

        logfwds = list()
        """ Retrieve LogForwarder used by the frontend using listeners """
        # Log Forwarder RELP
        logfwds.extend(list(LogOMRELP.objects.filter(query_filter)))

        # Log Forwarder REDIS
        logfwds.extend(list(LogOMHIREDIS.objects.filter(query_filter)))

        # Log Forwarder Syslog
        logfwds.extend(list(LogOMFWD.objects.filter(query_filter)))

        # Log Forwarder ElasticSearch
        logfwds.extend(list(LogOMElasticSearch.objects.filter(query_filter)))

        # Log Forwarder MongoDB
        logfwds.extend(list(LogOMMongoDB.objects.filter(query_filter)))

        # Log Forwarder Kafka
        logfwds.extend(list(LogOMKAFKA.objects.filter(query_filter)))

        """Second, retrieve Log Forwarders directly associated with the node as pstats forwarder(s)"""
        # Test self.pk to prevent M2M errors when object isn't saved in DB
        if self.pk:
            logfwds.extend([LogOM().select_log_om(log_fwd) for log_fwd in self.pstats_forwarders.filter(enabled=True)])

        """Add the protocol, destination ip and port of the log forwarder to the result"""
        for logfwd in logfwds:
            # Log Forwarder RELP
            if hasattr(logfwd, 'logomrelp'):
                output_ips.add(("tcp", logfwd.target, logfwd.port))  # TCP

            # Log Forwarder REDIS
            elif hasattr(logfwd, 'logomhiredis'):
                output_ips.add(("tcp", logfwd.target, logfwd.port))  # TCP

            # Log Forwarder Syslog
            elif hasattr(logfwd, 'logomfwd'):
                output_ips.add((logfwd.protocol, logfwd.target, logfwd.port))  # proto

            # Log Forwarder ElasticSearch
            elif hasattr(logfwd, 'logomelasticsearch'):
                """ For elasticsearch, we need to parse the servers """
                for ip, port in re_findall("https?://([^:]+):(\d+)", logfwd.servers):
                    output_ips.add(("tcp", ip, port))

            # Log Forwarder MongoDB
            elif hasattr(logfwd, 'logommongodb'):
                """ For OMMongoDB - parse uristr """
                for ip, port in parse_uristr(logfwd.uristr):
                    output_ips.add(('tcp', ip, port))

            # Log Forwarder Kafka
            elif hasattr(logfwd, 'logomkafka'):
                """ For kafka, we need to parse the brokers """
                for ip, port in re_findall("([^:\"\']+):(\d+)", logfwd.broker):
                    output_ips.add(("tcp", ip, port))

        results = []
        default_logom_nat_ipv4 = self.logom_outgoing_ip if is_valid_ip4(self.logom_outgoing_ip) else None
        default_logom_nat_ipv6 = self.logom_outgoing_ip if is_valid_ip6(self.logom_outgoing_ip) else None

        for proto, ip, port in output_ips:
            route_ipv4 = None
            route_ipv6 = None
            logger.debug(f"Getting valid routes for ip/hostname {ip}")

            if is_valid_ip4(ip):
                route_ipv4 = default_logom_nat_ipv4
                # Get the facultative IPv4 route for IP
                success, reply = get_route_interface(destination=ip)
                # Don't use loopback interfaces, IPs may not be assigned yet
                if success and not is_loopback(reply):
                    route_ipv4 = f"({reply})"

            if is_valid_ip6(ip):
                route_ipv6 = default_logom_nat_ipv6
                # Get the facultative IPv6 route for IP
                success, reply = get_route_interface(destination=ip, ip6=True)
                # Don't use loopback interfaces, IPs may not be assigned yet
                if success and not is_loopback(reply):
                    # Restrict NAT to global IPv6 (disable round-robin using link-local address)
                    route_ipv6 = f"({reply}:0)"

            # Only add hostname explicit routes, as it needs to be resolved to be present in PF configuration
            if is_valid_hostname(ip):
                success, reply = get_route_interface(ip)
                # Don't use loopback interfaces, IPs may not be assigned yet
                if success and not is_loopback(reply):
                    route_ipv4 = f"({reply})"
                success, reply = get_route_interface(ip, ip6=True)
                if success:
                    # Restrict NAT to global IPv6 (disable round-robin using link-local address)
                    route_ipv6 = f"({reply}:0)"

            results.append((proto, ip, port, route_ipv4, route_ipv6))

        return results

    @property
    def get_backends_enabled(self):
        """ Return all tuples (family, proto, ip, port) for each enabled Backends on this node """
        from applications.backend.models import Backend
        # !!! REQUIRED BY listener_set !
        output_ips = set()
        """ Retrieve Backends used in enabled Frontends """
        addresses = self.addresses()
        """ For each address, retrieve the associated listeners having frontend enabled """
        listener_addr = dict()
        for a in addresses:
            try:
                listener_addr[a].extend([l.id for l in a.listener_set.filter(frontend__enabled=True)])
            except KeyError:
                listener_addr[a] = [l.id for l in a.listener_set.filter(frontend__enabled=True)]

        """ Loop on each NetworkAddress to retrieve Backends associated with (enabled) Frontends """
        for listener_ids in listener_addr.values():
            for backend in Backend.objects.filter(enabled=True, frontend__listener__in=listener_ids):
                for server in backend.server_set.filter(mode="net"):
                    output_ips.add(("tcp", server.target, server.port))

        results = []
        default_logom_nat_ipv4 = self.backends_outgoing_ip if is_valid_ip4(self.backends_outgoing_ip) else None
        default_logom_nat_ipv6 = self.backends_outgoing_ip if is_valid_ip6(self.backends_outgoing_ip) else None
        for proto, ip, port in output_ips:
            route_ipv4 = None
            route_ipv6 = None
            logger.debug(f"Getting valid routes for ip/hostname {ip}")

            if is_valid_ip4(ip):
                route_ipv4 = default_logom_nat_ipv4
                # Get the facultative IPv4 route for IP
                success, reply = get_route_interface(destination=ip)
                # Don't use loopback interfaces, IPs may not be assigned yet
                if success and not is_loopback(reply):
                    route_ipv4 = f"({reply})"

            if is_valid_ip6(ip):
                route_ipv6 = default_logom_nat_ipv6
                # Get the facultative IPv6 route for IP
                success, reply = get_route_interface(destination=ip, ip6=True)
                # Don't use loopback interfaces, IPs may not be assigned yet
                if success and not is_loopback(reply):
                    # Restrict NAT to global IPv6 (disable round-robin using link-local address)
                    route_ipv6 = f"({reply}:0)"

            # Only add hostname explicit routes, as it needs to be resolved to be present in PF configuration
            if is_valid_hostname(ip):
                success, reply = get_route_interface(ip)
                # Don't use loopback interfaces, IPs may not be assigned yet
                if success and not is_loopback(reply):
                    route_ipv4 = f"({reply})"
                success, reply = get_route_interface(ip, ip6=True)
                # Don't use loopback interfaces, IPs may not be assigned yet
                if success and not is_loopback(reply):
                    # Restrict NAT to global IPv6 (disable round-robin using link-local address)
                    route_ipv6 = f"({reply}:0)"

            results.append((proto, ip, port, route_ipv4, route_ipv6))

        return results

    def get_pending_messages(self, count=None):
        try:
            return MessageQueue.objects.filter(
            node=self, status__in=[MessageQueue.MessageQueueStatus.NEW, MessageQueue.MessageQueueStatus.RUNNING]).order_by('modified')[0:count]

        except Exception as e:
            logger.error(f"Could not get list of pending messages: {str(e)}")
            return []

    def process_messages(self):
        """
        Function called from Cluster daemon: read
        queue and process asked functions
        :return:
        """
        logger_daemon = logging.getLogger('daemon')
        messages = MessageQueue.objects.filter(
            node=self, status='new').order_by('modified')

        for message in messages:
            logger.debug("Cluster::process_messages: {},{},{}".format(
                message.action, message.config, message.node)
            )

            message.status = MessageQueue.MessageQueueStatus.RUNNING
            message.save()

            try:
                """ Big try in case of import or execution error """

                # Call the function
                my_function = import_string(message.action)

                args = [logger_daemon]

                if message.config:
                    args.append(message.config)

                message.result = my_function(*args)
                message.status = MessageQueue.MessageQueueStatus.DONE
            except ServiceExit as e:
                """ Service stop asked """
                raise e
            except KeyError as e:
                logger.exception(e)
                message.result = "KeyError {}".format(str(e))
                message.status = MessageQueue.MessageQueueStatus.FAILURE
            except Exception as e:
                logger.exception(e)
                logger.error("Cluster::process_messages: {}".format(str(e)))
                message.status = MessageQueue.MessageQueueStatus.FAILURE
                message.result = str(e)

            message.save()

    def get_certificate(self):
        return X509Certificate.objects.get(name=self.name, status="V", chain=X509Certificate.objects.get(status="V", is_vulture_ca=True, name__startswith="Vulture_PKI").cert)

    def set_state(self, state):
        if state in [state_tmp for state_tmp, choice in STATE_CHOICES] and self._vstate != state:
            logger.warn(f"[NODE SET STATE] State changed to: {state}")
            self._vstate = state
            self.save()

    @property
    def state(self):
        if not self.heartbeat:
            # If initial value isn't set (which COULD happen), set the current value to have a DOWN state
            self.heartbeat = timezone.now() - timezone.timedelta(seconds=60)
        if self._vstate != "MAINTENANCE":
            if timezone.now() - self.heartbeat > timezone.timedelta(seconds=60):
                self.set_state("DOWN")
            elif self._vstate == "DOWN":
                self.set_state("UP")
        return self._vstate


class Cluster(models.Model):
    """
    Vulture Cluster class.

        A Cluster contains Nodes
        This class is essentially a distributed queue
        used to dispatch messages among Nodes

    """
    name = models.TextField(default='VultureOS')

    class Meta:
        app_label = "gui"

    @staticmethod
    def get_current_node():
        try:
            hostname = settings.HOSTNAME
            return Node.objects.get(name=hostname)
        except Node.DoesNotExist:
            logger.error("Cluster:get_current_node: Current node not found. Are we a pending replica ?")
            return False

    @staticmethod
    def is_node_bootstrapped():
        try:
            return True if Cluster.get_current_node() else False
        except DatabaseError as e:
            logger.error(f"Cluster:is_node_bootstrapped: MongoDB error: {e}")
            return False

    @staticmethod
    def get_global_config():
        try:
            global_config = Config.objects.get()
        except Config.DoesNotExist:
            global_config = Config()

        return global_config

    @staticmethod
    def await_api_request(action, config=None, node=None, internal=False, interval=2, tries=10):
        """
        Call the usual api_request(), but wait for some time for a result before returning

        :param action:      The requested action function
        :param config:      The configuration to pass to the function
        :param node:        The node on which to run the action
        :param internal:    Does the action need to be shown on the GUI?
        :param interval:    The interval in seconds between 2 checks on the action status
        :param tries:       The number of checks to do before returning
        :return:
                A tuple representing
                    The status of the request (True for status done, False on error or job failure)
                    the result string of the message (in case of failure, the error details)
            """

        action_cmd = Cluster.api_request(action, config, node, internal)
        if node:
            logger.info(f"Cluster::await_api_request:: waiting for result of {action} on node {node}")
            instance = action_cmd.get('instance')
            try:
                return instance.await_result(interval, tries)
            except APISyncResultTimeOutException:
                logger.error(f"Cluster::await_api_request:: Action didn't return in {interval*tries}s, returning")
                return False, ""
        else:
            results = list()
            status = True
            logger.info(f"Cluster::await_api_request:: waiting for result of {action} on all nodes")
            instances = action_cmd.get('instances')
            for instance in instances:
                try:
                    partial_status, result = instance.await_result(interval, tries)
                except APISyncResultTimeOutException:
                    status = False
                    logger.error(f"Cluster::await_api_request:: Action didn't return in {interval*tries}s, returning")
                    result = ""
                results.append({
                    "status": partial_status,
                    "result": result
                })
                if not partial_status:
                    status = partial_status

            return status, results

    @staticmethod
    def api_request(action, config=None, node=None, internal=False):
        """

        :param node: The node we want to send a message to
        :param action:    The requested action
        :param config:    The associated config
        :param node:      The node to set the action to
        :param internal:  Is this request internal ? Means that it will not be shown to the admin
        :return:
                for no node is specified:
                { 'status': True, 'message': 'A meaningful message' }
                for specific node:
                { 'status': True, 'message': 'A meaningful message', instance: messagequeue_object_created }
            { 'status': False, 'message': 'A meaningful message' }
        """

        if not node:
            instances = list()
            # Ignore pending nodes
            for node in Node.objects.exclude(management_ip__exact=''):
                m, created = MessageQueue.objects.get_or_create(
                    node=node,
                    status="new",
                    action=action,
                    config=config,
                    internal=internal
                )

                try:
                    logger.debug("Cluster::api_request: Calling \"{}\" on node \"{}\". Config is: \"{}\"".format(
                        action, node.name, config))
                    m.save()
                    instances.append(m)
                except Exception as e:
                    logger.error("Cluster::api_request: {}".format(str(e)))
                    return {'status': False, 'message': str(e)}
            return {'status': True, 'message': '', 'instances': instances}
        else:
            m, created = MessageQueue.objects.get_or_create(
                node=node,
                status="new",
                action=action,
                config=config,
                internal=internal
            )

            try:
                logger.debug("Cluster::api_request: Calling \"{}\" on node \"{}\". Config is: \"{}\"".format(
                    action, node.name, config))
                m.save()
            except Exception as e:
                logger.error("Cluster::api_request: {}".format(str(e)))
                return {'status': False, 'message': str(e)}

            return {'status': True, 'message': '', 'instance': m}


class MessageQueue(models.Model):
    """
        Cluster Queue
    """

    class MessageQueueStatus(models.TextChoices):
        NEW = "new", _("New")
        RUNNING = "running", _("Running")
        DONE = "done", _("Done")
        FAILURE = "failure", _("Failure")

    date_add = models.DateTimeField(default=timezone.now)
    node = models.ForeignKey(Node, on_delete=models.CASCADE)

    # status of the action (new/running/done)
    status = models.TextField(
        choices=MessageQueueStatus.choices,
        default=MessageQueueStatus.NEW)

    result = models.TextField(default="")

    # Path to the Django method to call
    action = models.TextField()

    # Configuration to pass to the method
    config = models.TextField(blank=True)

    # Use to sort jobs in the queue
    modified = models.DateTimeField()

    # Report to the admin this object ?
    internal = models.BooleanField(default=False)

    def to_template(self):
        return {
            'date_add': self.date_add,
            'node': str(self.node),
            'status': self.status,
            'action': ' : '.join(self.action.split('.')[-2:]),
            'config': self.config,
            'result': self.result,
            'modified': self.modified,
            'internal': self.internal
        }

    def save(self, *args, **kwargs):
        self.modified = timezone.now()
        return super().save(*args, **kwargs)


    def execute(self):
        self.status = MessageQueue.MessageQueueStatus.RUNNING
        self.save()

        try:
            """ Big try in case of import or execution error """

            # Call the function
            my_function = import_string(self.action)
            args = list()

            args.append(logging.getLogger('daemon'))

            if self.config:
                args.append(self.config)

            self.result = my_function(*args)
            self.status = MessageQueue.MessageQueueStatus.DONE
        except Exception as e:
            logger.exception(e)
            logger.error("MessageQueue::execute: {}".format(str(e)))
            self.status = MessageQueue.MessageQueueStatus.FAILURE
            self.result = str(e)

        self.save()
        return self.status, self.result


    def await_result(self, interval=2, tries=10):
        """

        :param interval:    Time interval to wait before checking status again
        :param max_tries:   The maximum number of times to check status
        :return:
                A tuple representing
                    The status of the request (True for status done, False on error or job failure)
                    the result string of the message (in case of failure, the error details)
        """
        try:
            for _ in range(0, tries):
                self.refresh_from_db()
                if self.status == MessageQueue.MessageQueueStatus.DONE:
                    return True, self.result
                if self.status == MessageQueue.MessageQueueStatus.FAILURE:
                    return False, self.result
                time.sleep(interval)

            raise APISyncResultTimeOutException(f"MessageQueue:: Timeout on the result of {self.action}. "
                                                f"Config is {self.config}")
        except Exception as e:
            logger.exception(e)
            return False, ""


class NetworkInterfaceCard(models.Model):
    """
    This is the "physical" network card on FreeBSD: em0, em1, ...
    """
    dev = models.TextField()
    node = models.ForeignKey(Node, on_delete=models.CASCADE)

    def __str__(self):
        return "{} - {}".format(self.dev, self.node.name)

    def get_list(self):
        """ Retrieve available RUNNING network interface on the node
        :return: ['em0', 'lo0', ...]
        """
        return list(set(subprocess.check_output(['/sbin/ifconfig', '-l']).strip().decode('utf-8').split(' ')) -
                    {'lo0', 'lo1', 'lo2', 'lo3', 'lo4', 'lo5', 'lo6', 'pflog0', 'vm-public', 'tap0', 'tun0'})

    def get_running_addresses(self):
        """ Retrieve available RUNNING IP addresses on the NIC
        :return: A list of ip addresses running on the given
                device: ['::1/128', '127.0.0.1/24', '...']
        """

        p1 = subprocess.Popen([
            "/sbin/ifconfig", "-f", "inet:cidr,inet6:cidr",
            self.dev], stdout=subprocess.PIPE)

        p2 = subprocess.Popen([
            "/usr/bin/grep", "inet"],
            stdin=p1.stdout, stdout=subprocess.PIPE)

        p3 = subprocess.Popen([
            "/usr/bin/awk", '{print $2}'],
            stdin=p2.stdout, stdout=subprocess.PIPE)

        success, error = p3.communicate()
        if success:
            return success.strip().decode('utf-8').split('\n')
        else:
            return []

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "id" in fields:
            result['id'] = str(result['id'])
        if not fields or "addresses" in fields:
            result['addresses'] = []
            for address in NetworkAddress.objects.filter(nic=self):
                result['addresses'].append(address.to_dict())
        return result

    def to_template(self):
        return {
            "id": str(self.id),
            "dev": self.dev
        }

    @property
    def has_ipv4(self):
        """ Check if there is at least one NetworkAddress IPv4 associated to this NetworkInterface
        :return  True if there is, False otherwise
        """
        # NOT IN is not supported by djongo
        # exclude lagg/vlan addresses as NICs do not hold the address
        # Test self.pk to prevent M2M errors when object isn't saved in DB
        if self.pk:
            for addr in self.networkaddress_set.exclude(type__in=["lagg", "vlan"]):
                if addr.ip and ":" not in addr.ip:
                    return True
        return False

    @property
    def has_ipv6(self):
        """ Check if there is at least one NetworkAddress IPv6 associated to this NetworkInterface
        :return True if there is, False otherwise
        """
        # exclude lagg/vlan addresses as NICs do not hold the address
        # Test self.pk to prevent M2M errors when object isn't saved in DB
        if self.pk:
            return self.networkaddress_set.exclude(type__in=["lagg", "vlan"]).filter(ip__contains=":").count() > 0
        else:
            return False


class NetworkAddress(models.Model):
    """
    This is a generic IPv[4|6] Address
    """
    name = models.TextField(default=_('Friendly name'))
    type = models.TextField(
        default="system",
        choices=NET_ADDR_TYPES,
        verbose_name=_("Interface type"),
    )
    nic = models.ManyToManyField(
        NetworkInterfaceCard,
        through='NetworkAddressNIC'
    )

    ip = models.GenericIPAddressField(blank=True, null=True)
    prefix_or_netmask = models.TextField(blank=True)
    carp_vhid = models.PositiveSmallIntegerField(default=0)
    vlan = models.PositiveSmallIntegerField(default=0)
    fib = models.PositiveSmallIntegerField(default=0)
    iface_id = models.SmallIntegerField(
        default=-1,
        null=True,
        verbose_name=_("virtual Interface number (for ALIAS/VLAN/LAGG)"))
    lagg_proto = models.TextField(
        blank=True,
        choices=LAGG_PROTO_TYPES,
        verbose_name=_("Link aggregation protocol type"),
    )

    # Needed to make alambiquate mongodb queries
    objects = models.DjongoManager()

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "id" in fields:
            result['id'] = str(result['id'])
        if not fields or "nic" in fields:
            result['nic'] = list()
            addresses_nic = NetworkAddressNIC.objects.filter(network_address=self)
            for address_nic in addresses_nic:
                nic = address_nic.nic
                result['nic'].append(str(nic.pk))
        return result

    def to_template(self):
        """ Dictionary used to create configuration file related to the interface
        :return     Dictionnary of configuration parameters
        """

        nic_list = list()

        addresses_nic = NetworkAddressNIC.objects.filter(network_address=self)
        for address_nic in addresses_nic:
            nic = address_nic.nic
            nic_list.append(str(nic))

        conf = {
            'id': str(self.id),
            'name': self.name,
            'type': self.type,
            'nic': ', '.join(nic_list),
            'ip': self.ip,
            'prefix_or_netmask': self.prefix_or_netmask,
            'carp_vhid': self.carp_vhid,
            'vlan': self.vlan,
            'fib': self.fib,
            'iface_id': self.iface_id,
            'lagg_proto': self.lagg_proto
        }

        return conf

    @property
    def is_carp(self):
        if self.carp_vhid > 0:
            return True
        return False

    @property
    def version(self):
        """ Return the version of the Ip address

        :return: 4 or 6
        """
        if not self.ip:
            return ''

        if ":" in self.ip:
            return 6
        else:
            return 4

    @property
    def ip_cidr(self):
        """ Return IP/CIDR notation of Listener

        :return: String with ip/cidr notation
        """

        if not self.ip:
            return ''

        ip = ipaddress.ip_address(self.ip)
        if ip.version == 6:
            prefix = self.prefix_or_netmask
        else:
            prefix = netmask2prefix(self.prefix_or_netmask)
            if prefix == 0:
                prefix = self.prefix_or_netmask.replace("/", "")

        return "{}/{}".format(self.ip, prefix)

    @property
    def family(self):
        """
        :return: inet or inet6, depending of the IP address
        """
        if not self.ip:
            return ''

        try:
            ip = ipaddress.ip_address(self.ip)
            if ip.version == 4:
                return "inet"
            else:
                return "inet6"
        except ValueError:
            return ""

    @property
    def main_iface(self):
        """
        :return: A string representing the name of the interface(s) linked with this configuration element
        """
        if self.type in ['vlan', 'lagg']:
            return f"{self.type}{str(self.iface_id)}"
        elif self.type == 'alias':
            return f"{self.nic.first().dev}_alias{str(self.iface_id)}"
        else:
            return self.nic.first().dev


    def rc_config(self, node_id=None):
        """
        :param: node_id: Optional Node id to limit configuration generation
        :return: A Dict containing:
                    - The id of each node (or specified node) as key
                    - A tuple of rc config key and value as value
        :return: if node_id is specified, will simply return:
                    - A tuple of rc config key and value as value
        """

        nodes_config = dict()

        filter = Q()
        if node_id:
            filter = Q(id=node_id)

        for node in Node.objects.filter(filter):
            nodes_config.update(
                {node.id: list()}
            )
            addresses = NetworkAddressNIC.objects.filter(network_address=self, nic__node=node)
            if addresses.exists():
                if self.type == 'vlan':
                    # Add vlan interface to the list of cloned interfaces
                    nodes_config[node.id].append({
                        'variable': "cloned_interfaces",
                        'value': f"vlan{self.iface_id}",
                        'filename': "network",
                        'operation': "+="
                    })
                    key = f"ifconfig_vlan{self.iface_id}"
                    value = f"{self.family} {self.ip_cidr} vlan {str(self.vlan)} vlandev {addresses[0].nic.dev}"
                elif self.type == 'lagg':
                    # Add vlan interface to the list of cloned interfaces
                    nodes_config[node.id].append({
                        'variable': "cloned_interfaces",
                        'value': f"lagg{self.iface_id}",
                        'filename': "network",
                        'operation': "+="
                    })
                    # Add vlan interface to the list of cloned interfaces
                    for address_nic in addresses:
                        nodes_config[node.id].append({
                            'variable': f"ifconfig_{address_nic.nic.dev}",
                            'value': "up",
                        })
                    key = f"ifconfig_lagg{self.iface_id}"
                    value = f"up laggproto {self.lagg_proto}"
                    for address in addresses:
                        value += f" laggport {address.nic.dev}"
                    if self.ip_cidr:
                        value += f" {self.ip_cidr}"
                elif self.type == 'alias':
                    key = f"ifconfig_{addresses[0].nic.dev}_alias{self.iface_id}"
                    value = f"{self.family} {self.ip_cidr}"
                elif self.type == 'system':
                    key = f"ifconfig_{addresses[0].nic.dev}"
                    if self.family == 'inet6':
                        key += "_ipv6"
                    value = f"{self.family} {self.ip_cidr}"

                if self.is_carp:
                    value += f" vhid {self.carp_vhid} advskew {addresses[0].carp_priority} pass {addresses[0].carp_passwd}"
                if self.fib and self.fib !=0:
                    value += f" fib {str(self.fib)}"

                nodes_config[node.id].append({'variable': key, 'value': value})

        return nodes_config


    def __str__(self):
        return "'{}' : {}/{}".format(
            self.name,
            self.ip,
            self.prefix_or_netmask
        )

    @staticmethod
    def str_attrs():
        """ Attributes required by __str__ method """
        return ['name', 'ip', 'prefix_or_netmask']


class NetworkAddressNIC(models.Model):

    nic = models.ForeignKey(
        NetworkInterfaceCard,
        on_delete=models.CASCADE
    )

    network_address = models.ForeignKey(
        NetworkAddress,
        on_delete=models.CASCADE
    )

    # CARP Related stuff
    carp_priority = models.SmallIntegerField(default=0)
    carp_passwd = models.TextField(default='-')
