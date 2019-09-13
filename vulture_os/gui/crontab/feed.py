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

from system.cluster.models import Cluster
from django.conf import settings
from django.utils.timezone import make_aware, now as timezone_now
from gui.models.rss import RSS
from gui.models.feed import Feed, DATABASES_PATH
from toolkit.network.network import get_hostname, get_proxy

from gzip import decompress as gzip_decompress
from tarfile import open as tar_open
from io import BytesIO
from datetime import datetime
from os import kill
from signal import SIGHUP
import subprocess
import requests

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


# The slash at the end is mandatory
IPSET_VULTURE = "https://predator.vultureproject.org/ipsets/"
IPSET_GEOIP = "http://geolite.maxmind.com/download/geoip/database/"


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


def security_update(node_logger=None):
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

    if not Cluster.get_current_node().is_master_mongo:
        logger.debug("Crontab::security_update: Not the master node, passing RSS fetch")
        return True

    """ If we are the master node, download newest reputation databases """
    try:
        logger.info("Crontab::security_update: get Vulture's ipsets...")
        infos = requests.get(IPSET_VULTURE+"index.json", proxies=proxies, timeout=5).json()
    except Exception as e:
        logger.error("Crontab::security_update: Unable to download Vulture's ipsets: {}".format(e))
        return False

    """ Add Maxmind's GEOIP databases """
    for filename in ("GeoLite2-Country", "GeoLite2-City"):
        try:
            """ Try to download """
            logger.info("Crontab::security_update: Get MaxmindDB geoip database...")
            data = requests.get("https://updates.maxmind.com/geoip/databases/{}/update".format(filename),
                                proxies=proxies,
                                timeout=5)
            with open("/tmp/{}.mmdb".format(filename), "wb") as f:
                f.write(gzip_decompress(data.content))
            logger.info("Crontab::security_update: Database {} saved.".format(filename))

            """ Immediatly reload the rsyslog service to prevent crash on MMDB access """
            reload_rsyslog = subprocess.run(['/usr/local/bin/sudo /bin/mv /tmp/{}.mmdb {}'
                                             '&& /usr/local/bin/sudo /usr/sbin/jexec '
                                             'rsyslog /usr/sbin/service rsyslogd reload'.format(filename, DATABASES_PATH)],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            if reload_rsyslog.returncode == 1:
                logger.info("Crontab::security_update: Rsyslogd not runing.")
            elif reload_rsyslog.returncode == 0:
                logger.info("Crontab::security_update: Rsyslogd reloaded.")
            else:
                logger.error("Crontab::security_update: Rsyslogd reload error : "
                             "stdout={}, stderr={}".format(reload_rsyslog.stdout.decode('utf8'),
                              reload_rsyslog.stderr.decode('utf8')))

            """ If downloaded - create/update object """
            feed, created = Feed.objects.get_or_create(filename=filename+".mmdb")
            feed.label = filename
            feed.description = "Maxmind DB's Geoip country database"
            feed.last_update = timezone_now()
            feed.nb_netset = 0
            feed.nb_unique = 0
            feed.type = "GeoIP"
            feed.save()
        except Exception as e:
            logger.error("Crontab::security_update: Failed to download GeoIP database : ")
            logger.exception(e)

    infos.append({
        'filename': "firehol_level1.netset",
        'label': "Firehol Level 1 netset",
        'description': "Firehol IPSET Level 1",
        'type': "netset"
    })

    infos.append({
        'filename': "vulture-v4.netset",
        'label': "Vulture Cloud IPv4",
        'description': "Vulture Cloud IPv4",
        'type': "netset"
    })

    infos.append({
        'filename': "vulture-v6.netset",
        'label': "Vulture Cloud IPv6",
        'description': "Vulture Cloud IPv6",
        'type': "netset"
    })

    for info in infos:
        filename = info['filename']
        label = info['label']
        description = info['description']
        last_update = timezone_now()
        entry_type = info['type']
        base_url = info.get('base_url', IPSET_VULTURE)
        nb_netset = info.get('nb_netset', 0)
        nb_unique = info.get('nb_unique', 0)

        """ Update feed on disk """
        try:
            logger.info("Crontab::security_update: Downloading "+base_url+"{}".format(filename))
            data = requests.get(base_url+"{}".format(filename), proxies=proxies, timeout=5)
            logger.debug("Crontab::security_update: File {} downloaded.".format(filename))
            assert data.status_code == 200, "Response code is not 200 ({})".format(data.status_code)
        except Exception as e:
            logger.error("Crontab::security_update: Unable to download Vulture's ipset: {}".format(e))
            continue

        try:
            """ First verify the type of file """
            """ Decompress, if needed """
            # if filename.endswith(".tar.gz"):
            #     try:
            #         tar_dir = tar_open(fileobj=BytesIO(data.content), mode='r:gz')
            #         for tarfile in tar_dir.get_members():
            #             if filename[:-7] in tarfile.name:
            #                 filename = tarfile.name
            #                 content = tar_dir.extractfile(tarfile).read()
            #         if not content:
            #             logger.error("File not found in downloaded archive {}, files : {}".format(filename,
            #                                                                                       tar_dir.getmembers()))
            #     except:
            #         logger.error("Crontab::security_update: Unable to decompress GZIP {}".format(filename))
            #         continue
            #
            # elif filename.endswith(".gz"):
            if filename.endswith(".gz"):
                try:
                    content = gzip_decompress(data.content)
                    filename = filename[:-3]
                except Exception as e:
                    logger.error("Crontab::security_update: Unable to decompress {}".format(filename))
                    logger.exception(e)
                    continue
            else:
                content = data.content

            with open("{}{}".format("/tmp/", filename), "wb") as f:
                f.write(content)

            """ Immediatly reload the rsyslog service to prevent crash on MMDB access """
            reload_rsyslog = subprocess.run(['/usr/local/bin/sudo /bin/mv /tmp/{} {}'
                                             '&& /usr/local/bin/sudo /usr/sbin/jexec '
                                             'rsyslog /usr/sbin/service rsyslogd reload'.format(filename, DATABASES_PATH)],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            if reload_rsyslog.returncode == 1:
                logger.info("Crontab::security_update: Rsyslogd not runing.")
            elif reload_rsyslog.returncode == 0:
                logger.info("Crontab::security_update: Rsyslogd reloaded.")
            else:
                logger.error("Crontab::security_update: Rsyslogd reload error : "
                             "stdout={}, stderr={}".format(reload_rsyslog.stdout.decode('utf8'),
                                                           reload_rsyslog.stderr.decode('utf8')))

            """ If downloaded - create/update object """
            feed, created = Feed.objects.get_or_create(filename=filename)
            feed.label = label
            feed.description = description
            feed.last_update = last_update
            feed.nb_netset = nb_netset
            feed.nb_unique = nb_unique
            feed.type = entry_type
            feed.save()

        except OSError as e:
            logger.error("Failed to open {} : ".format(DATABASES_PATH))
            logger.exception(e)

    logger.info("Security_update done.")

    return True
