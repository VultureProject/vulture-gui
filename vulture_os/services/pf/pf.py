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
__doc__ = 'PF service wrapper utils'

# Django system imports
from django.conf import settings

# Django project imports
from applications.reputation_ctx.models import DATABASES_PATH, DATABASES_OWNER, DATABASES_PERMS
from system.cluster.models import Cluster
from services.service import Service
from system.config.models import write_conf
from services.pf.models import PFSettings

# Required exceptions imports
from services.exceptions import ServiceReloadError, ServiceStatusError
from subprocess import CalledProcessError

# Extern modules imports
from hashlib import md5
from subprocess import check_output, Popen, PIPE
from os import path as os_path
import re
import subprocess

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


PF_PATH = "/usr/local/etc/"
PF_PERMS = "640"
PF_OWNERS = "root:vlt-os"


class PFService(Service):
    """ PF service class wrapper """

    def __init__(self):
        super().__init__()
        self.model = PFSettings
        self.service_name = "pf"
        self.friendly_name = "Packet Filter"

        self.config_file = "pf.conf"
        self.owners = PF_OWNERS
        self.perms = PF_PERMS
        self.jinja_template = {
            'tpl_name': self.config_file,
            'tpl_path': '{}/{}'.format(PF_PATH, self.config_file),
        }
        self.uptime = 0
        self.nb_rules = 0
        self.counters = dict()

    def __str__(self):
        return "PF Service"

    def reload(self):
        """ Apply PF configuration """
        command = ['/usr/local/bin/sudo', '/sbin/pfctl', '-f', PF_PATH + "pf.conf"]
        proc = Popen(command, stdout=PIPE, stderr=PIPE)
        success, error = proc.communicate()
        stdout, stderr, code = success.decode('utf8'), error.decode('utf8'), proc.returncode

        """ If service never been started """
        if code != 0 and "pfctl: /dev/pf: No such file or directory" in stderr:
            logger.info("Cannot reload service pf because it is not running. Starting-it...")
            return self.start()

        if code != 0 or "pf rules not loaded" in stderr:
            raise ServiceReloadError(stderr, 'pf', traceback=" ")

        return stdout or stderr

    def update_counters(self):
        """
        Call 'service pf onestatus' and update the class attributes with PF statistics
        :return: Status of service ("UP", "DOWN", "UNKNOWN", "ERROR")
        """
        status = "UNKNOWN"

        status_pattern = re.compile(
            r"^Status: (\w+) for ([0-9]+ days [0-9]+:[0-9]+:[0-9]+)",
            re.DOTALL
        )
        entries_pattern = re.compile(
            r"^  current entries.*([0-9]+)",
            re.MULTILINE
        )

        counters_pattern = re.compile(
            r"^\s\s([-a-z]+)\s+([0-9]+)\s+([0-9\.]+)/s",
            re.MULTILINE
        )

        try:
            stats = subprocess.check_output(['/usr/local/bin/sudo',
                                             '/usr/sbin/service',
                                             self.service_name,
                                             'onestatus']).strip().decode('utf-8')
            m = re.search(status_pattern, stats)
            if m:
                status = "UP" if str(m.group(1)) == "Enabled" else "DOWN"
                self.uptime = str(m.group(2))

            m = re.search(entries_pattern, stats)
            if m:
                self.nb_rules = str(m.group(1))

            m = re.findall(counters_pattern, stats)
            if m:
                for (key, total, rate) in m:
                    self.counters[key] = (total, rate)

        except CalledProcessError as e:
            logger.error("PF::Status: Failed to retrieve status : {}".format(e))
            status = "ERROR"
        return status

    def status(self, service_name=""):
        """
        Give status of service, and more if needed
        :param service_name: Service name to use if different than self.service_name
        :return: "DOWN"|"UP"|"UNKNOWN"|"ERROR", message information about status
        """
        status = self.update_counters()
        return status, self.uptime, self.nb_rules, self.counters

    def get_rules(self):
        """ Apply PF configuration """
        command = ['/usr/local/bin/sudo', '/sbin/pfctl', '-sr']
        proc = Popen(command, stdout=PIPE, stderr=PIPE)
        success, error = proc.communicate()
        stdout, stderr, code = success.decode('utf8'), error.decode('utf8'), proc.returncode

        """ If service never been started """
        if code != 0 and "pfctl: /dev/pf: No such file or directory" in stderr:
            logger.info("Cannot reload service pf because it is not running. Starting-it...")
            return self.start()

        if code != 0:
            raise ServiceStatusError(stderr, 'pf', traceback=" ")

        return stdout

    def reload_conf(self):
        """
        Write new PF configuration, if needed
        :return: True / False
        """
        conf_reloaded = super().reload_conf()

        config_model = Cluster.get_global_config()

        """ Check if firehol and vulture netsets exist """
        filepath = DATABASES_PATH + "/firehol_level1.netset"
        if not os_path.isfile(filepath):
            write_conf(logger, [filepath, "", DATABASES_OWNER, DATABASES_PERMS])

        """ Check if Whitelist and Blacklist have changed """
        wl_bl = {
            'pf.whitelist.conf': config_model.pf_whitelist,
            'pf.blacklist.conf': config_model.pf_blacklist,
        }

        for filename, liste in wl_bl.items():
            file_path = '{}{}'.format(PF_PATH, filename)
            config = "\n".join(liste.split(','))
            md5_config = md5(config.encode('utf-8')).hexdigest().strip()
            md5sum = ""

            try:
                result = check_output(['/sbin/md5', file_path], stderr=PIPE).decode('utf8')
                md5sum = result.strip().split('= ')[1]

            except CalledProcessError as e:
                stderr = e.stderr.decode('utf8')
                logger.error("Failed to md5sum file '{}' : {}".format(filename, stderr))

            """ If there was an error, bad permissions on file, rewrite-it with correct ones """
            if md5_config != md5sum:
                conf_reloaded = True
                logger.info('Packet Filter {} need to be rewrite'.format(filename))
                write_conf(logger, [file_path, config, PF_OWNERS, PF_PERMS])

        return conf_reloaded


def test_config(config):
    return check_output(["/sbin/pfctl", "-n", "-f", "-"],
                        stderr=PIPE,
                        input=config.encode('utf8')).decode('utf8')
