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

from django.utils.timezone import now as timezone_now
from gui.models.rss import RSS
from toolkit.network.network import get_hostname, get_proxy
from applications.reputation_ctx.models import ReputationContext
from services.rsyslogd.rsyslog import restart_service as restart_rsyslog_service
from system.exceptions import VultureSystemError

import subprocess
from random import randint
from time import sleep

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


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
    :return: Update security information related to package versions and known vulnerabilities
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

    logger.info("Security_update done.")

    return True


def update_reputation_ctx_now(node_logger=None):
    """
    Update the Reputation Context databases on the machine
    :return: True if the operation executed correctly, False otherwise
    """
    # On ALL nodes, write databases on disk
    # All internal reputation contexts are retrieved and created if needed
    # We can now download and write all reputation contexts
    reputation_ctxs = ReputationContext.objects.filter(enable_hour_download=True)
    for reputation_ctx in reputation_ctxs:
        logger.info(f"Crontab::update_reputation_ctx: Updating '{reputation_ctx.name}' DB")
        try:
            content = reputation_ctx.download()
        except VultureSystemError as e:
            if "404" in str(e) or "403" in str(e) and reputation_ctx.internal:
                logger.info("Crontab::update_reputation_ctx: Reputation context '{}' is now unavailable ({}). "
                            "Deleting it.".format(reputation_ctx, str(e)))
                reputation_ctx.delete()
            else:
                logger.error("Crontab::update_reputation_ctx::error: Failed to download reputation database '{}' : {}"
                             .format(reputation_ctx.name, e))
            continue
        except Exception as e:
            logger.error("Crontab::update_reputation_ctx::error: Failed to download reputation database '{}' : {}"
                         .format(reputation_ctx.name, e))
            continue
        try:
            tmp_filename = "{}{}".format("/tmp/", get_random_string(length=12))
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
                    logger.info("Crontab::update_reputation_ctx: Database written and rsyslogd not runing.")
                else:
                    logger.error("Crontab::update_reputation_ctx: It seems that the database cannot be written : {}".format(e))
            elif reload_rsyslog.returncode == 0:
                logger.info("Crontab::update_reputation_ctx: Database written and rsyslogd reloaded.")
            else:
                logger.error("Crontab::update_reputation_ctx: Database write failure : "
                             "stdout={}, stderr={}".format(reload_rsyslog.stdout.decode('utf8'),
                                                           reload_rsyslog.stderr.decode('utf8')))
            logger.info("Crontab::update_reputation_ctx: Reputation database named '{}' (file '{}') successfully written."
                        .format(reputation_ctx.name, reputation_ctx.absolute_filename))
        except Exception as e:
            logger.error("Crontab::update_reputation_ctx::error: Failed to write reputation database '{}' : {}"
                         .format(reputation_ctx.name, e))

    restart_rsyslog_service(logger)
    logger.info("Crontab::update_reputation_ctx: Task ended.")
    return True


def update_reputation_ctx(node_logger=None):
    logger.info("Crontab::update_reputation_ctx: Starting task")
    delay = randint(1, 1800)
    logger.info(f"Crontab::update_reputation_ctx: Waiting for {delay}s before downloading DBs")
    sleep(delay)

    return update_reputation_ctx_now(node_logger)
