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
from darwin.policy.models import DarwinPolicy
from django.conf import settings
from django.contrib.auth.models import Group
from django.utils.crypto import get_random_string
from os.path import join as path_join
from system.cluster.models import Cluster, Node
from system.pki.models import X509Certificate, TLSProfile
from system.users.models import User
from toolkit.network.network import get_management_ip
from toolkit.mongodb.mongo_base import MongoBase
from toolkit.redis.redis_base import RedisBase
from toolkit.system.secret_key import set_key
from toolkit.system.rc import get_rc_config
from redis import AuthenticationError, ResponseError
from cryptography.x509 import random_serial_number as x509_random_serial_number
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
        logger.error("Error: Cluster already exist")
        return False
    except Exception:
        pass

    """ Create Cluster object in database """
    cluster = Cluster()

    """ Create the local node """
    RC_NETWORK_CONF = "network"
    node, new_node = Node.objects.get_or_create(
        name=settings.HOSTNAME,
        management_ip=get_management_ip()
    )

    if new_node:
        logger.info("Registering new node '{}'".format(node.name))
        success, internet_ip = get_rc_config(filename=RC_NETWORK_CONF, variable="internet_ip")
        node.internet_ip = internet_ip if success and internet_ip else node.management_ip
        success, backends_outgoing_ip = get_rc_config(filename=RC_NETWORK_CONF, variable="backends_outgoing_ip")
        node.backends_outgoing_ip = backends_outgoing_ip if success and backends_outgoing_ip else node.management_ip
        success, logom_outgoing_ip = get_rc_config(filename=RC_NETWORK_CONF, variable="logom_outgoing_ip")
        node.logom_outgoing_ip = logom_outgoing_ip if success and logom_outgoing_ip else node.management_ip
        node.save()

    """ Read network config and store it into mongo """
    """ No rights to do that in jail - API request """
    node.api_request('toolkit.network.network.refresh_nic')

    """ save Node IPs on disk """
    node.api_request('toolkit.network.network.write_management_ips')

    """ Obtain Certificates and store it into mongoDB """
    with open(path_join(settings.DBS_PATH, "pki/ca.pem")) as f:
        ca_cert = f.read()

    with open(path_join(settings.DBS_PATH, "pki/ca.key")) as f:
        ca_key = f.read()

    with open(path_join(settings.DBS_PATH, "pki/node.cert")) as f:
        cert = f.read()

    with open(path_join(settings.DBS_PATH, "pki/node.key")) as f:
        key = f.read()

    internal_ca = X509Certificate(
        is_vulture_ca=True,
        is_ca=True,
        is_external=False,
        status='V',
        cert=ca_cert,
        key=ca_key,
        serial=x509_random_serial_number(),
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
        serial=x509_random_serial_number(),
    )

    node_name = node_cert.explose_dn()['CN']
    node_cert.name = node_name
    node_cert.save()

    """ Save cluster here, in case of error """
    cluster.save()

    """ Generate random API Key for cluster management and NMAP """
    """ Config object can not exists yet """
    system_config = cluster.get_global_config()
    if not system_config.cluster_api_key:
        system_config.cluster_api_key = get_random_string(
            32, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.,+')
    if not system_config.portal_cookie_name:
        system_config.portal_cookie_name = get_random_string(
            8, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    if not system_config.public_token:
        system_config.public_token = get_random_string(16, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    if not system_config.redis_password:
        system_config.redis_password = get_random_string(64, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    system_config.set_logs_ttl()
    system_config.save()

    # regenerate PF configuration to account for new system configuration
    node.api_request("services.pf.pf.gen_config")

    for name in ('Administrator', 'Log Viewer'):
        Group.objects.get_or_create(
            name=name
        )

    if admin_user and admin_password:
        User.objects.filter(is_superuser=True).delete()
        user = User.objects.create_superuser(admin_user, 'changeme@localhost', admin_password)
        user.save()

    time.sleep(5)
    """ Set local redis server password """
    try:
        redis = RedisBase(get_management_ip(), 6379)
        redis.redis.ping()
    except AuthenticationError:
        redis = RedisBase(get_management_ip(), 6379, password=system_config.redis_password)
    finally:
        redis.set_password(system_config.redis_password)

    """ Tell local sentinel to monitor local redis server """
    sentinel = RedisBase(get_management_ip(), 26379)
    try:
        # It may fail if Sentinel is already configured
        sentinel.sentinel_monitor()
    except ResponseError:
        logger.info("Install::Sentinel monitor: Monitoring cluster already configured")
    sentinel.sentinel_set_announce_ip()
    sentinel.sentinel_set_cluster_password(system_config.redis_password)

    """ Update uri of internal Log Forwarder """
    logfwd = LogOMMongoDB.objects.get()
    logfwd.uristr = "mongodb://{}:9091/?replicaset=Vulture&ssl=true".format(settings.HOSTNAME)
    logfwd.x509_certificate = node_cert
    logfwd.save()

    """ Create default TLSProfile """
    tls_profile = TLSProfile(name="Default TLS profile", x509_certificate=node_cert)  # All vars by default
    tls_profile.save()

    """ Download reputation databases before crontab """
    node.api_request("gui.crontab.feed.security_update")

    """ No need to restart rsyslog because the conf is not complete """
    logger.debug("API call to configure rsyslog")
    node.api_request("services.rsyslogd.rsyslog.build_conf")
    node.api_request("services.rsyslogd.rsyslog.configure_node")
    node.api_request("gui.crontab.generate_tzdbs.generate_timezone_dbs")
    node.api_request("gui.crontab.feed.update_reputation_ctx_now")

    logger.debug("API call to configure HAProxy")
    node.api_request("services.haproxy.haproxy.configure_node")

    logger.debug("API call to reload whole darwin configuration")
    DarwinPolicy.update_buffering()
    node.api_request("services.darwin.darwin.reload_all")

    logger.debug("API call to configure Logrotate")
    node.api_request("services.logrotate.logrotate.reload_conf")

    logger.debug("API call to update PF")
    node.api_request("services.pf.pf.gen_config")


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
        logger.info("[+] Getting distant cluster information")
        response = requests.get(
            "https://{}:8000/api/v1/system/cluster/info/".format(master_ip),
            headers={'Cluster-api-key': secret_key},
            verify=False
        )

        response.raise_for_status()
        cluster_infos = response.json()

        if not cluster_infos['status']:
            raise Exception('Error at API Request Cluster Info: {}'.format(cluster_infos['data']))

        time_master = cluster_infos['data'][master_hostname]['unix_timestamp']

        time_now = time.time()
        if abs(time_now - time_master) > 60 or abs(time_now + time_master) < 60:
            logger.info('Nodes not at the same date. Please sync with NTP Server')
            print('Nodes not at the same date. Please sync with NTP Server')
            return False

        logger.info("[-] OK!")

    except Exception as e:
        logger.error("Error at API Request Cluster Info: {} Invalid API KEY ?".format(e), exc_info=1)
        return False

    try:
        logger.info("[+] Getting cluster existing secret key")
        response = requests.get(
            "https://{}:8000/api/v1/system/cluster/key/".format(master_ip),
            headers={'Cluster-api-key': secret_key},
            verify=False
        )

        response.raise_for_status()
        keys_info = response.json()

        if not keys_info['status']:
            raise Exception('Error at API Request Cluster Key: {}'.format(keys_info['data']))

        encryption_key = keys_info['data']
        set_key(settings.SETTINGS_DIR, secret_key=encryption_key)

        logger.info("[-] OK!")

    except Exception as e:
        logger.error("Error at API Request Cluster Key: {}".format(e), exc_info=1)
        return False

    if not ca_cert:
        logger.info("[+] Getting ca certificate and key")

        try:
            infos = requests.post(
                "https://{}:8000/api/system/pki/get_ca/".format(master_ip),
                headers={'Cluster-api-key': secret_key},
                verify=False
            ).json()

            ca_cert = infos.get('ca_cert')
            ca_key= infos.get('ca_key')
        except Exception as e:
            logger.error("Unable to retrieve CA certificate: {}".format(e))
            return False

        logger.info("[-] OK!")

    """ We are coming from the CLI interface """
    if not cert or not key:
        logger.info("[+] Getting certificate and key")

        try:
            infos = requests.post(
                "https://{}:8000/api/system/pki/get_cert/".format(master_ip),
                headers={'Cluster-api-key': secret_key},
                data={'node_name': settings.HOSTNAME},
                verify=False
            ).json()

            cert = infos.get('cert')
            key = infos.get('key')
        except Exception as e:
            logger.error("Unable to retrieve Node certificate: {}".format(e))
            return False

        logger.info("[-] OK!")

    if cert and key:
        bundle = cert + key
    else:
        logger.error("Unable to retrieve Node certificate and key, check secret key")
        return False

    with open(path_join(settings.TMP_PATH, "ca.pem", "w")) as f:
        f.write(ca_cert)

    with open(path_join(settings.TMP_PATH, "ca.key", "w")) as f:
        f.write(ca_key)

    with open(path_join(settings.TMP_PATH, "node.cert", "w")) as f:
        f.write(cert)

    with open(path_join(settings.TMP_PATH, "node.key", "w")) as f:
        f.write(key)

    with open(path_join(settings.TMP_PATH, "node.pem", "w")) as f:
        f.write(bundle)

    """ At this point we should have valid certificates:
    Save them on system """
    subprocess.check_output([
        '/home/vlt-os/scripts/write_cert.sh'
    ])

    """ At this point, certificates have been overwritten
        => We need to destroy replicaset & restart mongoDB
    """
    logger.info("[+] replDestroy: Restarting Mongodb with new certificates")
    mongo = MongoBase()
    mongo.repl_destroy()
    logger.info("[+] Ok!")

    """ Ask primary to join us on our management IP """
    try:
        logger.info("[+] Asking master to add us in the cluster")

        infos = requests.post(
            "https://{}:8000/api/system/cluster/add/".format(master_ip),
            headers={'Cluster-api-key': secret_key},
            data={'ip': get_management_ip(), 'name': settings.HOSTNAME},
            verify=False
        )

        infos = infos.json()

        if not infos.get('status'):
            logger.error("Error during API Call to add node to cluster: {}".format(infos.get('message')))
            return False

        logger.info("[-] Ok!")

    except Exception:
        logger.error("Error at API Call on /system/cluster/add/ Response code: {}".format(infos.status_code))
        return False

    """ Sleep a few seconds in order for the replication to occur """
    time.sleep(3)
    logger.info("Finished!")

    return True

