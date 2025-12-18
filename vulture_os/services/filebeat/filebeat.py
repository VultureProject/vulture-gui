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
__doc__ = 'Filebeat model classes'

# Django system imports
from django.conf import settings

# Django project imports
from services.service import Service
from services.frontend.models import Frontend
from services.filebeat.models import FilebeatSettings

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from services.exceptions import ServiceError
from subprocess import CalledProcessError
from system.exceptions import VultureSystemError

# Extern modules imports
from os.path import join as path_join
from subprocess import check_output, PIPE

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')

JINJA_PATH = path_join(settings.BASE_DIR, "services/config/")
FILEBEAT_PATH = path_join(settings.LOCALETC_PATH, "beats")
INPUTS_PATH = path_join(FILEBEAT_PATH, "filebeat.yml")

FILEBEAT_OWNER = "root:vlt-os"
FILEBEAT_PERMS = "640"

class FilebeatService(Service):
    """ Filebeat service class wrapper """

    def __init__(self):
        super().__init__("filebeat", "rsyslog")
        self.model = FilebeatSettings
        self.friendly_name = "F-Logging"

        self.config_file = "filebeat_inputs.conf"
        self.owners = FILEBEAT_OWNER
        self.perms = FILEBEAT_PERMS
        self.jinja_template = {
            'tpl_name': self.config_file,
            'tpl_path': INPUTS_PATH,
        }

    def __str__(self):
        return "Filebeat Service"

    def get_conf_path(self, frontend=None):
        return frontend.get_filebeat_filename()

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
            if code == 0:
                status = "UP"
            else:
                # having a code other than 0 AND stdout means at least 1 process is failing
                status = "ERROR"
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
            else:
                infos = "{}".format(str(errors))

            logger.error("[{}] - Error getting status: '{}'".format(self.service_name.upper(), str(infos)))

        else:  # If no stdout nor sterr
            """ Service status is DOWN"""
            status = "DOWN"
        logger.debug("[{}] Status of service: {}".format(self.service_name.upper(), status))
        return status, infos


def build_conf(node_logger, frontend_id):
    """ Generate conf of filebeat inputs, based on all frontends LOG
    config of frontend
    outputs to internal REDIS
    :param node_logger: Logger sent to all API requests
    :param frontend_id: The name of the frontend in conf file
    :return:
    """
    result = ""
    service = FilebeatService()
    try:
        frontend = Frontend.objects.get(pk=frontend_id)
        """ Generate filebeat conf for frontend + write-it if changed """
        if service.reload_conf(frontend=frontend):
            result += "Frontend '{}' filebeat conf written.\n".format(frontend_id)
        else:
            result += f"Filebeat conf of frontend {frontend} hasn't changed."
    except ObjectDoesNotExist:
        raise VultureSystemError("Frontend with id {} not found, failed to generate conf.".format(frontend_id),
                                 "build rsyslog conf", traceback=" ")

    return result


def reload_service(node_logger):
    raise NotImplementedError


def stop_service(node_logger, *args):
    """ Stop Filebeat service """
    # Do not handle exceptions here, they are handled by process_message
    service = FilebeatService()

    # Warning : can raise ServiceError
    result = service.stop(*args)
    node_logger.info(f"Filebeat service stopped : {result}")

    return result


def restart_service(node_logger, *args):
    """ Only way (for the moment) to reload config """
    # Do not handle exceptions here, they are handled by process_message
    service = FilebeatService()

    # Warning : can raise ServiceError
    result = service.restart(*args)
    node_logger.info(f"Filebeat service restarted : {result}")

    return result


def start_service(node_logger, *args):
    """ Only way (for the moment) to reload config """
    # Do not handle exceptions here, they are handled by process_message
    service = FilebeatService()

    # Warning : can raise ServiceError
    result = service.start(*args)
    node_logger.info(f"Filebeat service started : {result}")

    return result


def delete_conf(node_logger, filename):
    try:
        check_output(["/usr/local/bin/sudo", "/bin/rm", "-f", "{}/{}".format(FILEBEAT_PATH, filename)], stderr=PIPE).decode('utf8')
        # Return message to API request, that will be saved into MessageQueue result
        return "'{}' successfully deleted.".format(filename)

    except CalledProcessError as e:
        """ Command raise if permission denied or file does not exists """
        stdout = e.stdout.decode('utf8')
        stderr = e.stderr.decode('utf8')
        logger.exception("Failed to delete frontend filename '{}': {}".format(filename, stderr or stdout))
        raise ServiceError("'{}' : {}".format(filename, (stderr or stdout)), "filebeat",
                           "delete filebeat conf file")
