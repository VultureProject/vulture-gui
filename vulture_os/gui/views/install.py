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
__credits__ = []
__license__ = "GPLv3"
__version__ = "3.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Install View of Vulture OS'

from applications.logfwd.models import LogOMMongoDB
from darwin.policy.models import DarwinPolicy, FilterPolicy
from django.conf import settings
from django.contrib.auth.models import Group
from django.utils.crypto import get_random_string
from system.cluster.models import Cluster, Node
from system.pki.models import X509Certificate, TLSProfile
from system.users.models import User
from toolkit.network.network import get_hostname, get_management_ip
from toolkit.mongodb.mongo_base import MongoBase
from toolkit.redis.redis_base import RedisBase
import logging
import requests
import subprocess
import time

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def cluster_create(admin_user=None, admin_password=None):
    """
    Initialize a new cluster from scratch
    This requires a valid hostname and existing certificates

    :param logger: A valid logger
    :return: True / False
    """

    """ We're comming from CLI: Abort if cluster already exists """
    try:
        Cluster.objects.get()
        logger.error("Error: Cluster already exists")
        return False
    except Exception:
        pass

    """ Create Cluster object in database """
    cluster = Cluster()

    """ Create the local node """
    node, new_node = Node.objects.get_or_create(
        name=get_hostname(),
        management_ip=get_management_ip()
    )

    if new_node:
        logger.info("Registering new node '{}'".format(node.name))
        node.internet_ip = node.management_ip
        node.save()

    """ Read network config and store it into mongo """
    """ No rights to do that in jail - API request """
    node.api_request('toolkit.network.network.refresh_nic')
    """ Read ZFS file systems """
    node.api_request('system.zfs.zfs.refresh')

    """ Obtain Certificates and store it into mongoDB """
    with open("/var/db/pki/ca.pem") as f:
        ca_cert = f.read()

    with open("/var/db/pki/ca.key") as f:
        ca_key = f.read()

    with open("/var/db/pki/node.cert") as f:
        cert = f.read()

    with open("/var/db/pki/node.key") as f:
        key = f.read()

    internal_ca = X509Certificate(
        is_vulture_ca=True,
        is_ca=True,
        is_external=False,
        status='V',
        cert=ca_cert,
        key=ca_key,
        serial=1
    )

    ca_name = internal_ca.explose_dn()['CN']
    internal_ca.name = ca_name
    internal_ca.save()

    node_cert = X509Certificate(
        is_vulture_ca=False,
        is_ca=False,
        is_external=False,
        status='V',
        cert=cert,
        key=key,
        chain=ca_cert,
        serial=2
    )

    node_name = node_cert.explose_dn()['CN']
    node_cert.name = node_name
    node_cert.save()

    """ Save cluster here, in case of error """
    cluster.save()

    """ Generate random API Key for cluster management and NMAP """
    """ Config object can not exists yet """
    system_config = cluster.get_global_config()
    system_config.cluster_api_key = get_random_string(
        16, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.,+')
    system_config.portal_cookie_name = get_random_string(
        8, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    system_config.public_token = get_random_string(16, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    system_config.set_logs_ttl()
    system_config.save()

    for name in ('Administrator', 'Log Viewer'):
        Group.objects.get_or_create(
            name=name
        )

    """ Delete any existing user """
    User.objects.all().delete()

    if admin_user and admin_password:
        user = User.objects.create_superuser(admin_user, 'changeme@localhost', admin_password)
        user.save()

    time.sleep(5)
    """ Tell local sentinel to monitor local redis server """
    c = RedisBase(get_management_ip(), 26379)
    try:
        # It may failed if Redis / Sentinel is already configured
        c.sentinel_monitor()
    except Exception as e:
        logger.error("Install::Sentinel monitor: Error: ")
        logger.exception(e)

    """ Update uri of internal Log Forwarder """
    logfwd = LogOMMongoDB.objects.get()
    logfwd.uristr = "mongodb://{}:9091/?replicaset=Vulture&ssl=true".format(get_hostname())
    logfwd.x509_certificate = node_cert
    logfwd.save()

    """ Create default TLSProfile """
    tls_profile = TLSProfile(name="Default TLS profile", x509_certificate=node_cert)  # All vars by default
    tls_profile.save()

    """ Download reputation databases before crontab """
    node.api_request("gui.crontab.feed.security_update")

    """ And configure + restart netdata """
    logger.debug("API call to netdata configure_node")
    node.api_request('services.netdata.netdata.configure_node')

    logger.debug("API call to restart netdata service")
    node.api_request('services.netdata.netdata.restart_service')

    """ No need to restart rsyslog because the conf is not complete """
    logger.debug("API call to configure rsyslog")
    node.api_request("services.rsyslogd.rsyslog.build_conf")
    node.api_request("services.rsyslogd.rsyslog.configure_node")
    node.api_request("services.rsyslogd.rsyslog.restart_service")

    logger.debug("API call to configure HAProxy")
    node.api_request("services.haproxy.haproxy.configure_node")

    logger.debug("API call to write default Darwin filters conf")
    for policy in DarwinPolicy.objects.all():
        node.api_request("services.darwin.darwin.write_policy_conf", policy.pk)

    logger.debug("API call to configure Darwin default policy")
    node.api_request("services.darwin.darwin.build_conf")

    logger.debug("API call to configure Apache GUI")
    node.api_request("services.apache.apache.reload_conf")


def cluster_join(master_hostname, master_ip, secret_key, ca_cert=None, cert=None, key=None):
    """
    Join an existing cluster

    :param master_hostname: Master hostname
    :param master_ip: Master management Ip address
    :param secret_key: The node's secret key
    :param ca_cert: The CA Certificate (optional: can be retrieved automagically)
    :param cert: The node certificate (optional: can be retrieved automagically)
    :param key: The node private key (optional: can be retrieved automagically)
    :return: True / False
    """

    """ We are coming from the CLI interface """
    try:
        infos = requests.get(
            "https://{}:8000/api/v1/system/cluster/info".format(master_ip),
            headers={'Cluster-api-key': secret_key},
            verify=False
        ).json()

        if not infos['status']:
            raise Exception('Error at API Request Cluster Info: {}'.format(infos['data']))

        time_master = infos['data'][master_hostname]['unix_timestamp']

        time_now = time.time()
        if abs(time_now - time_master) > 60 or abs(time_now + time_master) < 60:
            logger.info('Nodes not at the same date. Please sync with NTP Server')
            print('Nodes not at the same date. Please sync with NTP Server')
            return False

    except Exception as e:
        logger.error("Error at API Request Cluster Info: {} Invalid API KEY ?".format(e))
        return False

    if not ca_cert:
        try:
            infos = requests.post(
                "https://{}:8000/api/system/pki/get_ca".format(master_ip),
                headers={'Cluster-api-key': secret_key},
                verify=False
            ).json()

            ca_cert = infos.get('ca_cert')
        except Exception as e:
            logger.error("Unable to retrieve CA certificate: {}".format(e))
            return False

    """ We are coming from the CLI interface """
    if not cert or not key:
        try:
            infos = requests.post(
                "https://{}:8000/api/system/pki/get_cert/".format(master_ip),
                headers={'Cluster-api-key': secret_key},
                data={'node_name': get_hostname()},
                verify=False
            ).json()

            cert = infos.get('cert')
            key = infos.get('key')
        except Exception as e:
            logger.error("Unable to retrieve Node certificate: {}".format(e))
            return False

    if cert and key:
        bundle = cert + key
    else:
        logger.error("Unable to retrieve Node certificate and key, check secret key")
        return False

    with open("/var/tmp/ca.pem", "w") as f:
        f.write(ca_cert)

    with open("/var/tmp/node.cert", "w") as f:
        f.write(cert)

    with open("/var/tmp/node.key", "w") as f:
        f.write(key)

    with open("/var/tmp/node.pem", "w") as f:
        f.write(bundle)

    """ At this point we should have valid certificates:
    Save them on system """
    subprocess.check_output([
        '/home/vlt-os/scripts/write_cert.sh'
    ])

    """ At this point, certificates have been overwritten
        => We need to destroy replicaset & restart mongoDB
    """
    logger.info("replDestroy: Restart Mongodb with new certificates")
    mongo = MongoBase()
    mongo.repl_destroy()

    """ Ask primary to join us on our management IP """
    # TODO: verify to true
    infos = requests.post(
        "https://{}:8000/api/system/cluster/add/".format(master_ip),
        headers={'Cluster-api-key': secret_key},
        data={'slave_ip': get_management_ip(), 'slave_name': get_hostname()},
        verify=False
    )

    if infos.status_code != 200:
        raise Exception("Error at API Call on /system/cluster/add/  Response code: {}".format(infos.status_code))

    infos = infos.json()

    if not infos.get('status'):
        logger.error("Error during API Call to add node to cluster: {}".format(infos.get('message')))
        return False

    """ Join our redis server to the redis master """
    c = RedisBase()
    redis_master_node = c.get_master(master_ip)
    c.slave_of(redis_master_node, 6379)

    """ Tell local sentinel to monitor local redis server """
    c = RedisBase(get_management_ip(), 26379)
    c.sentinel_monitor()

    """ Sleep a few seconds in order for the replication to occur """
    time.sleep(3)

    """ Create the local node """
    try:
        node = Node.objects.get(
            name=get_hostname(),
            management_ip=get_management_ip()
        )
    except Exception:
        logger.error("cluster_join:: Unable to find slave node !")
        logger.error("cluster_join:: Unable to find slave node !")
        return False

    """ Update uri of internal Log Forwarder """
    logfwd = LogOMMongoDB.objects.get()
    logfwd.uristr = mongo.get_replicaset_uri()
    logfwd.save()

    """ Save certificates on new node """
    for cert in X509Certificate.objects.exclude(is_vulture_ca=True):
        cert.save_conf()

    """ Read network config and store it into mongo """
    """ No rights to do that in jail - API request """
    node.api_request('toolkit.network.network.refresh_nic')
    """ Read ZFS file systems """
    node.api_request('system.zfs.zfs.refresh')

    """ Download reputation databases before crontab """
    node.api_request("gui.crontab.feed.security_update")

    """ And configure + restart netdata """
    logger.debug("API call to netdata configure_node")
    # API call to Cluster - to refresh nodes on each node conf
    Cluster.api_request('services.netdata.netdata.configure_node')

    logger.debug("API call to restart netdata service")
    node.api_request('services.netdata.netdata.restart_service')

    logger.debug("API call to configure HAProxy")
    node.api_request("services.haproxy.haproxy.configure_node")

    logger.debug("API call to write Darwin policies conf")
    for policy in DarwinPolicy.objects.all():
        node.api_request("services.darwin.darwin.write_policy_conf", policy.pk)

    logger.debug("API call to configure Darwin")
    node.api_request("services.darwin.darwin.build_conf")

    # API call to while Cluster - to refresh Nodes list in conf
    logger.debug("API call to update configuration of Apache GUI")
    Cluster.api_request("services.apache.apache.reload_conf")

    """ The method configure restart rsyslog if needed """
    logger.debug("API call to configure rsyslog")
    # API call to whole Cluster - to refresh mongodb uri in pf logs
    Cluster.api_request("services.rsyslogd.rsyslog.configure_node")

    return True
