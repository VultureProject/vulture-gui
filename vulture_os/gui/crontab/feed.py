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
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Jobs related to various security feed updates'

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()
from django.utils.crypto import get_random_string

from system.cluster.models import Cluster
from django.conf import settings
from django.utils.timezone import make_aware, now as timezone_now
from gui.models.rss import RSS
from toolkit.network.network import get_hostname, get_proxy
from applications.reputation_ctx.models import ReputationContext
from system.tenants.models import Tenants
from system.exceptions import VultureSystemError

import subprocess
import requests
from base64 import b64encode

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


# The slash at the end is mandatory
IPSET_VULTURE = "https://predator.vultureproject.org/ipsets/"

def security_alert(title, level, content):
    """
    Insert an rss to notify an important event
    :return: True / False
    """
    try:
        """ No need to notify if there is already an alert with the same title """
        RSS.objects.get(ack=False, title=title)
    except:
        try:
            RSS.objects.create(
                title=title,
                date=timezone_now().strftime("%Y-%m-%d %H:%M:%S"),
                level=level,
                content=content
            )
        except Exception as e:
            logger.error("Crontab::security_alert: {}".format(e))
            return False

    return True


def security_update(node_logger=None, tenant_id=None):
    """
    :return: Update Vulture's security databases
    """
    # Get proxy first
    proxies = get_proxy()

    """ Every node needs to be up2date """
    try:
        logger.info("Crontab::security_update: calling pkg update...")
        res = subprocess.check_output(["/usr/local/bin/sudo", "/usr/sbin/pkg",
                                       "-ohttp_proxy={}".format(proxies.get('http', "")),
                                       "-ohttps_proxy={}".format(proxies.get('https', "")),
                                       "-oftp_proxy={}".format(proxies.get('ftp', "")),
                                       "update"], stderr=subprocess.PIPE).decode("utf-8")
        if "All repositories are up to date" not in res:
            logger.error("Crontab::security_update: Unable to update pkg")
        else:
            logger.info("Crontab::security_update: All repositories are up to date")
    except subprocess.CalledProcessError as e:
        logger.error("Failed to update pkg packages : {}".format(str(e.stderr.decode('utf8'))))
    except Exception as e:
        logger.error("Failed to update pkg packages : {}".format(str(e)))

    """ Do we have something urgent to update ? """
    try:
        logger.info("Crontab::security_update: calling pkg upgrade...")
        res = subprocess.check_output(["/usr/local/bin/sudo", "/usr/sbin/pkg",
                                 "-ohttp_proxy={}".format(proxies.get('http', "")),
                                 "-ohttps_proxy={}".format(proxies.get('https', "")),
                                 "-oftp_proxy={}".format(proxies.get('ftp', "")),
                                 "audit", "-F"], stderr=subprocess.PIPE).decode('utf8')
        if "0 problem" in res:
            logger.info("Crontab::security_update: No vulnerability found.")
        elif "is vulnerable" in res:
            logger.info("Crontab::security_update: Security problem found : {}".format(res))
            security_alert("Security problem found on node {}".format(get_hostname()), "danger", res)
    except subprocess.CalledProcessError as e:
        if e.stdout.decode("utf-8").startswith("0 problem"):
            logger.info("Crontab::security_update: No vulnerability found.")
        elif "is vulnerable" in e.stdout.decode("utf-8"):
            logger.info("Crontab::security_update: Security problem found : {}".format(e.stdout.decode('utf-8')))
            security_alert("Security problem found on node {}".format(get_hostname()), "danger",
                           e.stdout.decode("utf-8"))
        else:
            logger.error("Crontab::security_update: Failed to retrieve vulnerabilities : "
                         "{}".format(str(e)))
    except Exception as e:
        logger.error("Crontab::security_update: Failed to retrieve vulnerabilities : {}".format(e))

    # If tenant id given, try to retrieve the tenant
    if tenant_id:
        try:
            tenant = Tenants.objects.get(pk=tenant_id)
        except:
            logger.error("Security_update: Failed to retrieve reputation database with asked id {}".format(tenant_id))
            raise Exception("Tenant not found")

    # If it is the master node, retrieve the databases
    if Cluster.get_current_node().is_master_mongo:
        # If tenant id given, retrieve the predator api key
        if tenant_id:
            predator_tokens = [tenant.predator_apikey]
        else:
            predator_tokens = Tenants.objects.mongo_distinct("predator_apikey")
        # Loop over predator api keys configured over Multi-Tenants configs
        for predator_token in predator_tokens:
            """ Download newest reputation databases list """
            try:
                logger.info("Crontab::security_update: get Vulture's ipsets...")
                infos = requests.get(IPSET_VULTURE+"index.json",
                                     headers={'Authorization': predator_token},
                                     proxies=proxies,
                                     timeout=5).json()
            except Exception as e:
                logger.error("Crontab::security_update: Unable to download Vulture's ipsets: {}".format(e))
                return False

            infos.append({
                'filename': "firehol_level1.netset",
                'label': "Firehol Level 1 netset",
                'description': "Firehol IPSET Level 1",
                'type': "ipv4_netset",
                'url': IPSET_VULTURE+"firehol_level1.netset"
            })
            infos.append({
                'filename': "vulture-v4.netset",
                'label': "Vulture Cloud IPv4",
                'description': "Vulture Cloud IPv4",
                'type': "ipv4_netset",
                'url': IPSET_VULTURE + "firehol_level1.netset"
            })
            infos.append({
                'filename': "vulture-v6.netset",
                'label': "Vulture Cloud IPv6",
                'description': "Vulture Cloud IPv6",
                'type': "ipv6_netset",
                'url':  IPSET_VULTURE + "vulture-v6.netset"
            })

            for info in infos:
                label = info['label']
                description = info['description']
                entry_type = info['type']
                url = info.get('url', IPSET_VULTURE+info['filename'])
                nb_netset = info.get('nb_netset', 0)
                nb_unique = info.get('nb_unique', 0)
                # Add predator api key in filename
                encoded_token = b64encode(predator_token.encode('utf8')).decode('utf8')
                filename = ".".join(info['filename'].split('.')[:-1]) + "_" + encoded_token + "." + \
                           info['filename'].split('.')[-1]

                """ Create/update object """
                try:
                    reputation_ctx = ReputationContext.objects.get(filename=filename)
                except Exception as e:
                    reputation_ctx = ReputationContext(filename=filename)
                reputation_ctx.name = label
                reputation_ctx.url = url
                reputation_ctx.db_type = entry_type
                reputation_ctx.label = label
                reputation_ctx.description = description
                reputation_ctx.nb_netset = nb_netset
                reputation_ctx.nb_unique = nb_unique
                reputation_ctx.internal = True
                # Use predator_apikey only for predator requests
                if "predator.vultureproject.org" in reputation_ctx.url:
                    reputation_ctx.custom_headers = {'Authorization': predator_token}
                else:
                    reputation_ctx.custom_headers = {}
                reputation_ctx.save()
                logger.info("Reputation context {} created.".format(label))

    # On ALL nodes, write databases on disk
    # All internal reputation contexts are retrieved and created if needed
    # We can now download and write all reputation contexts
    # If tenant id given, only write on disk related reputation databases
    if tenant_id:
        encoded_token = b64encode(tenant.predator_apikey.encode('utf8')).decode('utf8')
        reputation_ctxs = ReputationContext.mongo_find({"enable_hour_download": "true",
                                                        "filename": {"$regex": ".*_{}.[a-z]+$".format(encoded_token)}})
    else:
        reputation_ctxs = ReputationContext.objects.filter(enable_hour_download=True)
    for reputation_ctx in reputation_ctxs:
        try:
            content = reputation_ctx.download()
        except VultureSystemError as e:
            if "404" in str(e) or "403" in str(e) and reputation_ctx.internal:
                logger.info("Security_update::info: Reputation context '{}' is now unavailable ({}). "
                            "Deleting it.".format(reputation_ctx, str(e)))
                reputation_ctx.delete()
            else:
                logger.error("Security_update::error: Failed to download reputation database '{}' : {}"
                             .format(reputation_ctx.name, e))
            continue
        except Exception as e:
            logger.error("Security_update::error: Failed to download reputation database '{}' : {}"
                         .format(reputation_ctx.name, e))
            continue
        try:
            tmp_filename = "{}{}".format("/tmp/", get_random_string())
            with open(tmp_filename, "wb") as f:
                f.write(content)
            """ Immediatly reload the rsyslog service to prevent crash on MMDB access """
            # Filename is a variable of us (not injectable)
            reload_rsyslog = subprocess.run(['/usr/local/bin/sudo /bin/mv {} {}'
                                             '&& /usr/local/bin/sudo /usr/sbin/jexec '
                                             'rsyslog /usr/sbin/service rsyslogd reload'
                                            .format(tmp_filename, reputation_ctx.absolute_filename)],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            if reload_rsyslog.returncode == 1:
                if "rsyslogd not running" in reload_rsyslog.stderr.decode('utf8'):
                    logger.info("Crontab::security_update: Database written and rsyslogd not runing.")
                else:
                    logger.error("Crontab::security_update: It seems that the database cannot be written : {}".format(e))
            elif reload_rsyslog.returncode == 0:
                logger.info("Crontab::security_update: Database written and rsyslogd reloaded.")
            else:
                logger.error("Crontab::security_update: Database write failure : "
                             "stdout={}, stderr={}".format(reload_rsyslog.stdout.decode('utf8'),
                                                           reload_rsyslog.stderr.decode('utf8')))
            logger.info("Crontab::security_update: Reputation database named '{}' (file '{}') successfully written."
                        .format(reputation_ctx.name, reputation_ctx.absolute_filename))
        except Exception as e:
            logger.error("Security_update::error: Failed to write reputation database '{}' : {}"
                         .format(reputation_ctx.name, e))

    logger.info("Security_update done.")

    return True
