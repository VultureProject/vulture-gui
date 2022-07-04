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

from toolkit.network.network import get_hostname, MANAGEMENT_IP_PATH
from toolkit.mongodb.mongo_base import MongoBase
from toolkit.redis.redis_base import RedisBase
from toolkit.mongodb.mongo_base import parse_uristr

from django.utils.translation import ugettext as _
from django.utils.module_loading import import_string
from django.utils import timezone
from django.conf import settings
from django.forms.models import model_to_dict
from djongo import models
import subprocess
import ipaddress
from iptools.ipv4 import netmask2prefix
import time

from applications.logfwd.models import LogOMHIREDIS
from system.pki.models import X509Certificate
from services.exceptions import ServiceExit

from re import findall as re_findall, compile as re_compile

import logging
import logging.config

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


JAILS = ("apache", "mongodb", "redis", "rsyslog", "haproxy")


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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.id:
            try:
                dashboard_fwd = LogOMHIREDIS.objects.get(name="Internal_Dashboard")
            except:
                pass
            else:
                self.pstats_forwarders.add(dashboard_fwd)

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
            'pf_limit_states': self.pf_limit_states,
            'pf_limit_frags': self.pf_limit_frags,
            'pf_limit_src': self.pf_limit_src,
            'addresses': addresses,
            'is_master_redis': self.is_master_redis,
            'is_master_mongo': self.is_master_mongo,
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
        ok = c.connect()
        if ok:
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
    def is_master_redis(self):
        """
        Check if the current Node is master or not
        :return: True / False, or None in case of a failure
        """

        if self.management_ip:
            c = RedisBase()
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

    def write_management_ip(self):
        """ Write self.management_ip in management.ip files (jails and host) """
        """ First write on host's file """
        api_res = self.api_request("system.config.models.write_conf",
                                   [MANAGEMENT_IP_PATH, self.management_ip, "root:wheel", "644"])
        """ Then, write into jails same path """
        for jail in JAILS:
            api_res = self.api_request("system.config.models.write_conf",
                                       ["/zroot/{}{}".format(jail, MANAGEMENT_IP_PATH),
                                        self.management_ip, "root:wheel", "644"])
        """ Returns the last api request """
        return api_res

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
        from applications.logfwd.models import LogOM, LogOMRELP, LogOMHIREDIS, LogOMFWD, LogOMElasticSearch, LogOMMongoDB
        # !!! REQUIRED BY listener_set !
        from services.frontend.models import Listener
        result = set()
        """ Retrieve LogForwarders used in enabled Frontends """
        """ First, retrieve LogForwarders that bind to the address of the node """
        addresses = self.addresses()
        """ For each address, retrieve the associated listeners having frontend enabled """
        listener_ids = list()
        for a in addresses:
            listener_ids.extend([l.id for l in a.listener_set.filter(frontend__enabled=True)])

        logfwds = list()
        """ Retrieve LogForwarder used by the frontend using listeners """
        # Log Forwarder RELP
        logfwds.extend(list(LogOMRELP.objects.filter(enabled=True, frontend_set__listener__in=listener_ids).all()))

        # Log Forwarder REDIS
        logfwds.extend(list(LogOMHIREDIS.objects.filter(enabled=True, frontend_set__listener__in=listener_ids).all()))

        # Log Forwarder Syslog
        logfwds.extend(list(LogOMFWD.objects.filter(enabled=True, frontend_set__listener__in=listener_ids).all()))

        # Log Forwarder ElasticSearch
        logfwds.extend(list(LogOMElasticSearch.objects.filter(enabled=True, frontend_set__listener__in=listener_ids).all()))

        # Log Forwarder MongoDB
        logfwds.extend(list(LogOMMongoDB.objects.filter(enabled=True, frontend_set__listener__in=listener_ids).all()))

        """Second, retrieve Log Forwarders directly associated with the node and not a listener eg. KAFKA and REDIS"""
        logfwds.extend([LogOM().select_log_om(log_fwd) for log_fwds in self.frontend_set.values_list('log_forwarders', flat=True) for log_fwd in log_fwds])

        """Add the protocol, destination ip and port of the log forwarder to the result"""
        for logfwd in logfwds:
            # Log Forwarder RELP
            if hasattr(logfwd, 'logomrelp'):
                result.add(("tcp", logfwd.target, logfwd.port))  # TCP

            # Log Forwarder REDIS
            elif hasattr(logfwd, 'logomhiredis'):
                result.add(("tcp", logfwd.target, logfwd.port))  # TCP

            # Log Forwarder Syslog
            elif hasattr(logfwd, 'logomfwd'):
                result.add((logfwd.protocol, logfwd.target, logfwd.port))  # proto

            # Log Forwarder ElasticSearch
            elif hasattr(logfwd, 'logomelasticsearch'):
                """ For elasticsearch, we need to parse the servers """
                for ip, port in re_findall("https?://([^:]+):(\d+)", logfwd.servers):
                    result.add(("tcp", ip, port))

            # Log Forwarder MongoDB
            elif hasattr(logfwd, 'logommongodb'):
                """ For OMMongoDB - parse uristr """
                for ip, port in parse_uristr(logfwd.uristr):
                    result.add(('tcp', ip, port))

        return list(result)

    @property
    def get_backends_enabled(self):
        """ Return all tuples (family, proto, ip, port) for each enabled Backends on this node """
        from applications.backend.models import Backend
        # !!! REQUIRED BY listener_set !
        from services.frontend.models import Listener
        result = set()
        """ Retrieve Backends used in enabled Frontends """
        addresses = self.addresses()
        """ For each address, retrieve the associated listeners having frontend enabled """
        listener_addr = dict()
        for a in addresses:
            try:
                listener_addr[a].append([l.id for l in a.listener_set.filter(frontend__enabled=True)])
            except KeyError:
                listener_addr[a] = [l.id for l in a.listener_set.filter(frontend__enabled=True)]

        """ Loop on each NetworkAddress to retrieve Backends associated with (enabled) Frontends """
        for network_address, listener_ids in listener_addr.items():
            for backend in Backend.objects.filter(enabled=True, frontend__listener__in=listener_ids):
                for server in backend.server_set.filter(mode="net"):
                    result.add((network_address.family, "tcp", server.target, server.port))  # TCP

        return result

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

            message.status = 'running'
            message.save()

            try:
                """ Big try in case of import or execution error """

                # Call the function
                my_function = import_string(message.action)

                args = [logger_daemon]

                if message.config:
                    args.append(message.config)

                message.result = my_function(*args)
                message.status = 'done'
            except ServiceExit as e:
                """ Service stop asked """
                raise e
            except KeyError as e:
                logger.exception(e)
                message.result = "KeyError {}".format(str(e))
                message.status = 'failure'
            except Exception as e:
                logger.exception(e)
                logger.error("Cluster::process_messages: {}".format(str(e)))
                message.status = 'failure'
                message.result = str(e)

            message.save()

    def get_certificate(self):
        return X509Certificate.objects.get(name=self.name, status="V", chain=X509Certificate.objects.get(status="V", is_vulture_ca=True, name__startswith="Vulture_PKI").cert)


class Cluster (models.Model):
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
            hostname = get_hostname()
            return Node.objects.get(name=hostname)
        except Node.DoesNotExist:
            logger.error("Cluster:get_current_node: Current node not found. Are we a pending slave ?")
            return False

    @staticmethod
    def is_node_bootstrapped():
        return True if Cluster.get_current_node() else False

    @staticmethod
    def get_global_config():
        try:
            global_config = Config.objects.get()
        except Config.DoesNotExist:
            global_config = Config()

        return global_config

    @staticmethod
    def api_request(action, config=None, node=None, internal=False):
        """

        :param node: The node we want to send a message to
        :param action:    The requested action
        :param config:    The associated config
        :param node:      The node to set the action to
        :param internal:  Is this request internal ? Means that it will not be shown to the admin
        :return:
            { 'status': True, 'message': 'A meaningful message' }
            { 'status': False, 'message': 'A meaningful message' }
        """

        if not node:
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
                except Exception as e:
                    logger.error("Cluster::api_request: {}".format(str(e)))
                    return {'status': False, 'message': str(e)}

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

        return {'status': True, 'message': ''}


class MessageQueue (models.Model):
    """
        Cluster Queue
    """
    date_add = models.DateTimeField(default=timezone.now)
    node = models.ForeignKey(Node, on_delete=models.CASCADE)

    # status of the action (new/running/done)
    status = models.TextField(default='new')

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
        for addr in self.networkaddress_set.all():
            if ":" not in addr.ip:
                return True
        return False

    @property
    def has_ipv6(self):
        """ Check if there is at least one NetworkAddress IPv6 associated to this NetworkInterface
        :return True if there is, False otherwise
        """
        # self.networkaddress_set.mongo_find({"ip": re_compile(":")}).count() > 0
        return self.networkaddress_set.filter(ip__contains=":").count() > 0


class NetworkAddress(models.Model):
    """
    This is a generic IPv[4|6] Address
    """
    name = models.TextField(default=_('Friendly name'))
    nic = models.ManyToManyField(
        NetworkInterfaceCard,
        through='NetworkAddressNIC'
    )
    ip = models.GenericIPAddressField()
    prefix_or_netmask = models.TextField()
    is_system = models.BooleanField(default=False)
    carp_vhid = models.SmallIntegerField(default=0)
    vlan = models.SmallIntegerField(default=0)
    vlandev = models.ForeignKey(to="NetworkInterfaceCard", null=True, blank=True,
                                related_name='%(class)s_vlandev',
                                on_delete=models.SET_NULL,
                                help_text=_("Underlying NIC for VLAN"),
                                verbose_name=_("Vlan device"))
    fib = models.SmallIntegerField(default=0)

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

        if self.vlandev:
            vlandev = self.vlandev.dev
        else:
            vlandev = None

        conf = {
            'id': str(self.id),
            'name': self.name,
            'nic': ', '.join(nic_list),
            'ip': self.ip,
            'is_system': self.is_system,
            'prefix_or_netmask': self.prefix_or_netmask,
            'carp_vhid': self.carp_vhid,
            'vlan': self.vlan,
            'vlandev': vlandev,
            'fib': self.fib
        }

        return conf

    @property
    def is_carp(self):
        if self.carp_vhid > 0:
            return True
        return False

    @property
    def is_vlan(self):
        if self.is_vlan > 0:
            return True
        return False

    @property
    def version(self):
        """ Return the version of the Ip address

        :return: 4 or 6
        """

        if ":" in self.ip:
            return 6
        else:
            return 4

    @property
    def ip_cidr(self):
        """ Return IP/CIDR notation of Listener

        :return: String with ip/cidr notation
        """

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
        ip = ipaddress.ip_address(self.ip)
        if ip.version == 4:
            return "inet"
        else:
            return "inet6"

    def rc_config(self, force_dev=None, is_system=False):
        """
        :param: force_dev: Optional NIC device. DO NOT USE except
                            you known what you are doing
        :param: is_system: If True, "alias" keyword is not present
        :return: The rc.conf configuration line for this Network Address
        """

        dev = None
        first = True

        addresses = NetworkAddressNIC.objects.filter(network_address=self)
        for address_nic in addresses:
            if first and address_nic.nic.node == Cluster.get_current_node():
                if force_dev:
                    dev = force_dev
                else:
                    dev = address_nic.nic.dev
                    first = False

                carp_priority = address_nic.carp_priority
                carp_passwd = address_nic.carp_passwd

            elif (not force_dev) and (address_nic.nic.node == Cluster.get_current_node()):
                logger.error("Node::NetworkAddress: Inconsistent configuration: SAME IP on MULTIPLE NIC !!! {}".format(self.ip))

        if self.is_carp:
            if is_system:
                device = "{}".format(dev)
            else:
                device = "{}_alias".format(dev)
                device += '{}'
            inet = "{} {} vhid {} advskew {} pass {}".format(
                self.family, self.ip_cidr,
                self.carp_vhid, carp_priority, carp_passwd)
        else:
            if is_system:
                device = "{}".format(dev)
            else:
                device = "{}_alias".format(dev)
                device += '{}'

            inet = "{} {}".format(self.family, self.ip_cidr)
            if self.fib and self.fib !=0:
                inet = inet + " fib " + str(self.fib)
            if self.vlan and self.vlan !=0 and self.vlandev:
                inet = inet + " vlan " + str(self.vlan) + " vlandev " + self.vlandev.dev

        if self.family == 'inet6':
            device += "_ipv6"

        return 'ifconfig_{}="{}"'.format(device, inet)

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
