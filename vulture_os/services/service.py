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
__credits__ = ["Kevin GUILLEMOT", "Jérémie JOURDIN"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Services main models'

# Django system imports
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext as _

# Django project imports
from system.cluster.models import Cluster
from system.config.models import write_conf

# Required exceptions import
from gui.models.monitor import Monitor
from services.exceptions import (ServiceConfigError, ServiceNoConfigError, ServiceExit, ServiceReloadError,
                                 ServiceRestartError, ServiceStartError)

# Extern modules imports
from jinja2 import Environment, FileSystemLoader
from os import path as os_path
from re import search as re_search
from subprocess import Popen, PIPE, check_output

import datetime

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


RC_CONF_DIR = "/etc/rc.conf.d"
RC_CONF_PERMS = "644"
RC_CONF_OWNERS = "root:wheel"

# service name : jail name
JAIL_SERVICES = {
    'rsyslogd': "rsyslog",
    'filebeat': "rsyslog", # Filebeat is running into rsyslog jail
    'redis': "redis",
    'sentinel': "redis",  # sentinel is running into redis jail
    'mongod': "mongodb",
    'haproxy': "haproxy",
}


class Service:
    """ Base class for all service classes """

    def __init__(self, service_name=""):
        super().__init__()
        self.model = None
        self.service_name = service_name
        self.owners = "root:wheel"
        self.perms = "640"
        self.jinja_template = {
            'tpl_name': "",
            'tpl_path': ""
        }

    def get_conf_path(self, **kwargs):
        return self.jinja_template['tpl_path']

    @property
    def menu(self):
        MENU = {
            'link': 'services',
            'icon': 'fas fa-server',
            'text': _('Services'),
            'url': "#",
            'submenu': [{
                'link': 'frontend',
                'text': 'Listeners',
                'url': '/services/frontend/',
            }, {
                'link': 'strongswan',
                'text': 'IPSEC Client',
                'url': '/services/strongswan/',
            }, {
                'link': 'openvpn',
                'text': 'VPNSSL Client',
                'url': '/services/openvpn/',
            }
            ]
        }

        return MENU

    def _exec_cmd(self, cmd, *args):
        jail_name = JAIL_SERVICES.get(self.service_name)

        if jail_name:
            command = ['/usr/local/bin/sudo', '/usr/sbin/jexec', jail_name, '/usr/sbin/service', self.service_name, cmd, *args]
        else:
            command = ['/usr/local/bin/sudo', '/usr/sbin/service', self.service_name, cmd, *args]

        proc = Popen(command, stdout=PIPE, stderr=PIPE)
        success, error = proc.communicate()
        return success.decode('utf8'), error.decode('utf8'), proc.returncode

    def start(self, *args):
        stdout, stderr, code = self._exec_cmd('start', *args)

        """ Haproxy returns stderr even if no failure - but return code = 0 """
        if stderr and code != 0:
            # Rajouter des cas si besoin
            if "sudo: no tty present and no askpass program specified" in stderr:
                raise ServiceStartError("vlt-os don't have permissions to do so, Check /usr/local/etc/sudoers.",
                                        self.service_name)
            # If the service is already running, do not raise
            if "{} already running?".format(self.service_name) not in stderr:
                raise ServiceStartError(stderr, self.service_name, traceback=" ")
        logger.info("Service {} started: {}".format(self.service_name, stdout or stderr))
        return stdout or stderr

    def stop(self, *args):
        response = self._exec_cmd('stop', *args)
        return response

    def restart(self, *args):
        stdout, stderr, code = self._exec_cmd('restart', *args)

        """ Haproxy returns stderr even if no failure - but return code = 0 """
        if stderr and code != 0:
            # Rajouter des cas si besoin
            if "sudo: no tty present and no askpass program specified" in stderr:
                raise ServiceRestartError("vlt-os don't have permissions to do so, Check /usr/local/etc/sudoers.",
                                          self.service_name)
            raise ServiceRestartError(stderr, self.service_name, traceback=" ")

        """ If enable_service is NO, code=1 & stdout contains error """
        if "Cannot 'restart' {}".format(self.service_name) in stdout:
            raise ServiceRestartError(stdout, self.service_name, traceback=" ")

        logger.info("Service {} restarted: {}".format(self.service_name, stdout or stderr))
        return stdout or stderr

    def reload(self, *args):
        stdout, stderr, code = self._exec_cmd('reload', *args)

        if ("not running" in stdout) or ("not running" in stderr):
            logger.info("Cannot reload service {} cause it is not running. Starting-it...".format(self.service_name))
            return self.start()

        if stderr and code != 0:
            # Rajouter des cas si besoin
            if "sudo: no tty present and no askpass program specified" in stderr:
                raise ServiceReloadError("vlt-os don't have permissions to do so, Check /usr/local/etc/sudoers.",
                                         self.service_name, traceback=" ")
            raise ServiceReloadError(stderr, self.service_name, traceback=" ")
        return stdout or stderr

    def last_status(self, node_name=""):
        """ Give last status of service by using Monitor object """
        # Status is not realtime: We read service's status from mongodb
        # Status has been set by the vultured daemon from the HOST
        # If there is no status for the last minute: Then status is UNKNOWN
        time_threshold = timezone.now() - datetime.timedelta(minutes=1)
        try:
            query = {'date__gt': time_threshold}
            if node_name:
                query['node__name'] = node_name
            status = Monitor.objects.filter(**query).order_by('-date').first()\
                            .services.filter(name=self.service_name).first().status
        except Exception:
            status = "UNKNOWN"

        return status, ""

    def status(self, *args):
        """
        Give status of service, and more if needed
        :return: "DOWN"|"UP"|"UNKNOWN"|"ERROR", message information about status
        """
        # Executing service service_name status as vlt-os sudo
        infos, errors, code = self._exec_cmd('onestatus', *args)

        status = "UNKNOWN"
        if infos:  # STDOUT -> service (not) running
            logger.debug("[{}] Status of service: {}".format(self.service_name.upper(), infos.split('\n')[0]))
            m = re_search('{} is (not )?running'.format(self.service_name), infos)
            if m:
                status = "UP" if not m.group(1) else "DOWN"
                logger.debug("[{}] Status successfully retrieved : {}".format(self.service_name.upper(), status))
            elif self.service_name == "strongswan":
                match = re_search("Security Associations \((\d+) up, (\d+) connecting\)", infos)
                if match:
                    status = "UP"
            elif self.service_name == "filebeat":
                match = re_search("Filebeat \d+ running \d+", infos)
                if match:
                    status = "UP"
                elif re_search("Filebeat \d+ stopped", infos):
                    status = "DOWN"
            else:
                logger.error("[{}] Status unknown, STDOUT='{}', STDERR='{}'".format(self.service_name.upper(), infos,
                                                                                    errors))
        elif errors:  # STDERR
            """ Something were wrong during service call"""
            status = "ERROR"
            # Entry missing in /usr/local/etc/sudoers.d/vulture_sudoers
            if "sudo: no tty present and no askpass program specified" in errors:
                infos = "User vlt-os don't have permissions to do \"service {} status\". " \
                        "Check sudoers file.".format(self.service_name.upper())
            elif "does not exist in /etc/rc.d or the local startup" in errors:
                infos = "It seems that the service {} is not installed (or script not executable)".format(
                    self.service_name)
            elif self.service_name == "strongswan" and code == 1:
                status = "DOWN"
            else:
                infos = "{}".format(str(errors))

            if infos:
                logger.error("[{}] - Error getting status: '{}'".format(self.service_name.upper(), str(infos)))

        else:  # If no stdout nor sterr
            """ Service status is unknown"""
            logger.error("[{}] Status unknown, STDOUT and STDERR are empty.".format(self.service_name.upper(), ))
        logger.debug("[{}] Status of service: {}".format(self.service_name.upper(), status))
        return status, infos

    def set_rc_conf(self, yes_or_no):
        """
        Set service_enable="YES" or "NO"
         in /RC_CONF_DIR/service
        :param  yes_or_no:  True if "YES", False if "NO"
        """
        filename = "{}/{}".format(RC_CONF_DIR, self.service_name)
        write_conf(logger, [filename, "{}_enable=\"{}\"".format(self.service_name, "YES" if yes_or_no else "NO"),
                            RC_CONF_OWNERS, RC_CONF_PERMS])
        return "{} successfully written.".format(filename)

    def process_is_running(self):
        """ Check system service status
        :returns: True if process is running, False otherwise
        """
        output = check_output(['/usr/local/bin/sudo', '/bin/ps', '-A'])
        if re_search(self.service_name, output):
            return True
        return False

    def write_conf(self, content, owners=None, perms=None, **kwargs):
        write_conf(logger, [self.get_conf_path(**kwargs), content, owners or "root:wheel", perms or "644"])

    def read_current_conf(self, **kwargs):
        with open(self.get_conf_path(**kwargs), 'r') as f:
            return f.read()

    def conf_has_changed(self, new_conf, **kwargs):
        """
        Check if configuration has changed
        :param new_conf: Conf as text to compare with disk content
        :return: conf generated if conf has changed, empty string otherwise
                raise ServiceConfigError if error
        """
        try:
            current_conf = self.read_current_conf(**kwargs)

            if current_conf != new_conf:
                return new_conf

            return False
        except ServiceExit:
            raise
        except Exception as e:
            logger.error("Unable to check if conf has changed for {}: {}".format(self.service_name, str(e)))
            #logger.exception(e)
            if "No such file" in str(e):
                raise ServiceNoConfigError(str(e), self.service_name)
            raise ServiceConfigError("Cannot open '{}' : {}".format(self.get_conf_path(**kwargs), str(e)),
                                     self.service_name)

    def get_dict_conf(self):
        """ Retrieve configuration
        :return  Configuration for jinja template as dict
        """
        model_object = self.model.objects.get()
        return model_object.to_template()

    def get_conf(self, **kwargs):
        """ Generate conf from mongo object and Jinja template
        :return     Generated configuration, to write into file
                    If error, raise ServiceConfigError
        """
        try:
            path_config = os_path.join(settings.BASE_DIR, 'services', 'config')
            jinja2_env = Environment(loader=FileSystemLoader(path_config))

            template = jinja2_env.get_template(self.jinja_template['tpl_name'])

            return template.render({
                'node': Cluster.get_current_node(),
                **self.get_dict_conf(),
                **kwargs
            })
        except ServiceExit:
            raise
        except Exception as e:
            raise
            logger.error(e)
            raise ServiceConfigError("Failed to generate jinja template: {}".format(str(e)), self.service_name)

    def reload_conf(self, **kwargs):
        """ Check if generated conf (self.get_conf) has changed and write-it if yes
             If cannot check, write anyway
        :return   False if conf has not changed, True otherwise
        """
        """ Get new conf depending on MongoDB """
        new_conf = self.get_conf(**kwargs)

        """ Try to check if conf has changed compared to disk """
        try:
            if not self.conf_has_changed(new_conf, **kwargs):
                logger.debug("Conf of service {} has not changed.".format(self.service_name))
                return False
            logger.info("Conf of service {} has changed.".format(self.service_name))

        except ServiceExit:
            raise
        except Exception as e:
            logger.error("Failed to check if {} conf has changed: {}".format(self.service_name, str(e)))

        """ If conf has changed or cannot check, write conf """
        logger.debug("Configuration file for service {} need to be updated".format(str(self)))
        self.write_conf(new_conf, owners=self.owners, perms=self.perms, **kwargs)
        logger.info("Configuration of service {} written on disk.".format(self.service_name))

        return True
