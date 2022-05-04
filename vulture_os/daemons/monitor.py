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
__author__ = "Olivier de Régis"
__credits__ = ["Kevin GUILLEMOT"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Job for OS Monitoring'


# Django system imports
from django.conf import settings
from django.utils import timezone
from django.utils.timezone import make_aware

# Django project imports
from applications.backend.models import Backend
from darwin.policy.models import FilterPolicy
from gui.models.monitor import Monitor, ServiceStatus
from services.service import Service
from services.strongswan.strongswan import get_ipsec_tunnels_stats, StrongswanService
from services.openvpn.openvpn import get_ssl_tunnels_stats, OpenvpnService
from services.darwin.darwin import monitor_filters as monitor_darwin_filters
from services.haproxy.haproxy import get_stats, HaproxyService
from services.strongswan.models import Strongswan
from services.openvpn.models import Openvpn
from services.pf.pf import PFService
from services.rsyslogd.rsyslog import RsyslogService
from services.filebeat.filebeat import FilebeatService
from services.darwin.darwin import DarwinService
from services.frontend.models import Frontend
from system.cluster.models import Cluster

# Required exceptions imports
from services.exceptions import ServiceError
from django.core.exceptions import ObjectDoesNotExist

# Extern modules imports
from datetime import datetime, timedelta
from threading import Thread, Event
from time import sleep

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('daemon')


def monitor():

    node = Cluster.get_current_node()

    def get_service_status(service_class):
        """ Get a service_class (eg HaproxyService) 
        :return  a dict {'name':service_name, 'status': status} """
        service_inst = service_class()
        service_status = ServiceStatus.objects.filter(name=service_inst.service_name).first() \
                         or ServiceStatus(name=service_inst.service_name)
        service_status.status = service_inst.status()[0]
        service_status.friendly_name = service_inst.friendly_name
        service_status.save()
        return service_status

    """ Initialize date and Monitor object """
    date = datetime.now().strftime('%Y-%m-%d %H:%M:00')
    date = datetime.strptime(date, '%Y-%m-%d %H:%M:00')
    mon = Monitor(
        date=make_aware(date),
        node=node
    )
    mon.services_id = set()

    for service in [HaproxyService, DarwinService, PFService, 
                    StrongswanService, OpenvpnService, RsyslogService, FilebeatService]:

        # Get some statuses outside for reusing variable later
        if service == StrongswanService:
            strongswan_status = get_service_status(StrongswanService)
            mon.services.add(strongswan_status)
        elif service == OpenvpnService:
            openvpn_status = get_service_status(OpenvpnService)
            mon.services.add(openvpn_status)
        elif service == RsyslogService:
            rsyslogd_status = get_service_status(RsyslogService)
            mon.services.add(rsyslogd_status)
        elif service == FilebeatService:
            filebeat_status = get_service_status(FilebeatService)
            mon.services.add(filebeat_status)
        else:
            mon.services.add(get_service_status(service))

    """ Get status of Redis, Mongod and Sshd """
    # Instantiate mother class to get status easily
    service = Service()
    for service_name in ("redis", "mongod", "sshd"):
        service_status = ServiceStatus.objects.filter(name=service_name).first() \
                         or ServiceStatus(name=service_name)
        service_status.status = service.status(service_name)[0]
        mon.services.add(service_status)

    mon.save()

    """ HAPROXY """
    frontends = Frontend.objects.all().only('name', 'status', 'enabled', 'mode', 'listening_mode')
    backends = Backend.objects.all().only('name', 'status', 'enabled')
    if frontends.count() > 0 or backends.count() > 0:
        statuses = {}
        try:
            # Return a dict { frontend_name: frontend_status, backend_name: backend_status, ... }
            statuses = get_stats()

        except ServiceError as e:
            logger.error(str(e))
        except Exception as e:
            logger.error("Failed to retrieve status of HAProxy: {}".format(str(e)))
            logger.exception(e)

        """ FRONTENDS """
        for frontend in frontends:
            if node in frontend.get_nodes():
                if not frontend.enabled:
                    status = "DISABLED"
                elif frontend.rsyslog_only_conf:
                    status = {'UP': "OPEN", 'DOWN': "STOP"}.get(rsyslogd_status.status, rsyslogd_status.status)
                elif frontend.filebeat_only_conf:
                    status = {'UP': "OPEN", 'DOWN': "STOP"}.get(filebeat_status.status, filebeat_status.status)
                else:
                    status = statuses.get("FRONTEND", {}).get(frontend.name, "ERROR")
                logger.debug("Status of frontend '{}': {}".format(frontend.name, status))

                if status != frontend.status.get(node.name):
                    frontend.status[node.name] = status
                    frontend.save()

            elif not (frontend.mode=="log" and frontend.listening_mode=="api") and frontend.status.get(node.name):
                frontend.status.pop(node.name, None)
                frontend.save()

        """ BACKENDS """
        for backend in backends:
            status = "DISABLED" if not backend.enabled else statuses.get("BACKEND", {}).get(backend.name, "ERROR")
            logger.debug("Status of backend '{}': {}".format(backend.name, status))
            if backend.status.get(node.name) != status:
                backend.status[node.name] = status
                backend.save()

    """ STRONGSWAN """
    try:
        strongswan = Strongswan.objects.get(node=node)

    except ObjectDoesNotExist:
        # If there is no IPSEC conf on that node, pass
        pass
    else:
        default = ("STOP", "")

        try:
            statusall, tunnel_statuses, ups, connectings = get_ipsec_tunnels_stats()
        except ServiceError as e:
            logger.exception(e)
            default = ("ERROR", str(e))
            statusall, tunnel_statuses, ups, connectings = "ERROR", {}, 0, 0

        strongswan.tunnels_status = {}
        for network in strongswan.ipsec_rightsubnet.split(','):
            strongswan.tunnels_status[network] = tunnel_statuses.get(network, default)
            logger.debug("Status of IPSEC Tunnel '{}' : {}".format(network, strongswan.tunnels_status[network]))

        strongswan.status = strongswan_status.status
        strongswan.statusall = statusall
        strongswan.tunnels_up = ups
        strongswan.tunnels_connecting = connectings
        strongswan.save()

    """ OPENVPN """
    try:
        openvpn = Openvpn.objects.get(node=node)
    except ObjectDoesNotExist:
        # If there is no VPNSSL conf on that node, pass
        pass
    else:

        openvpn.tunnels_status = get_ssl_tunnels_stats()
        openvpn.status = openvpn_status.status
        openvpn.save()

    """ DARWIN """
    filters = FilterPolicy.objects.all()
    if filters.count() > 0:
        filter_statuses = {}
        default = "ERROR"
        try:
            filter_statuses = monitor_darwin_filters()

        except ServiceError as e:
            logger.error(str(e))
            default = "DOWN"

        for dfilter in filters:
            dfilter.status[node.name] = default

            filter_status = filter_statuses.get(dfilter.name, False)
            if not dfilter.enabled:
                dfilter.status[node.name] = "DISABLED"
            elif filter_status is None or not dfilter.filter_type.is_launchable:
                dfilter.status[node.name] = "DOWN"
            elif filter_statuses.get(dfilter.name, {}).get('status') is not None:
                dfilter.status[node.name] = filter_statuses.get(dfilter.name).get('status').upper()
            dfilter.save()

    # Delete old monitoring
    last_date = (timezone.now() - timedelta(days=30))
    for m in Monitor.objects.filter(date__lte=last_date):
        m.delete()

    return True


class MonitorJob(Thread):

    def __init__(self, delay):
        super().__init__()
        # The shutdown_flag is a threading.Event object that
        # indicates whether the thread should be terminated.
        self.shutdown_flag = Event()
        self.delay = delay

    def run(self):
        logger.info("Monitor job started.")

        # While we are not asked to terminate
        while not self.shutdown_flag.is_set():
            try:
                monitor()
            except Exception as e:
                logger.exception("Monitor job failure: {}".format(e))
                logger.info("Resuming ...")

            # Sleep DELAY time, 2 seconds at a time to prevent long sleep when shutdown_flag is set
            cpt = 0
            while not self.shutdown_flag.is_set() and cpt < self.delay:
                sleep(2)
                cpt += 2

        logger.info("Monitor job stopped.")

    def ask_shutdown(self):
        logger.info("Monitor shutdown asked !")
        self.shutdown_flag.set()
