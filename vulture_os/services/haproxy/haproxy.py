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

__author__ = "Kevin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Haproxy service wrapper utils'

# Django system imports
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

# Django project imports
from services.haproxy.models import HAProxySettings
from services.service import Service

# Local imports
from system.cluster.models import Cluster
from system.config.models import write_conf
from system.exceptions import VultureSystemError
# Required exceptions imports
from services.exceptions import ServiceError, ServiceStatusError, ServiceTestConfigError
from subprocess import CalledProcessError

# Extern modules imports
from subprocess import check_output, PIPE

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


HAPROXY_PATH = "/usr/local/etc/haproxy.d"
TEST_CONF_PATH = "/var/tmp/haproxy"

HAPROXY_OWNER = "vlt-os:vlt-web"
HAPROXY_PERMS = "644"
MANAGEMENT_SOCKET = "/var/sockets/haproxy/haproxy.sock"

JINJA_PATH = "/home/vlt-os/vulture_os/services/haproxy/config/"
JINJA_TEMPLATE = "spoe_session.txt"


class HaproxyService(Service):
    """ HAProxy service class wrapper """

    def __init__(self):
        super().__init__()
        self.model = HAProxySettings
        self.service_name = "haproxy"
        self.friendly_name = "Frontend"

        self.config_file = JINJA_TEMPLATE
        self.owners = HAPROXY_OWNER
        self.perms = HAPROXY_PERMS
        self.jinja_template = {
            'tpl_name': self.config_file,
            'tpl_path': "{}/{}".format(HAPROXY_PATH, self.config_file),
        }

    def __str__(self):
        return "HAProxy Service"

    # Status inherited from Service class


def configure_node(node_logger):
    """ Generate and write HAProxy conf file, depending on node conf
    :return    A string, what has beeen done
    """
    result = ""

    """ Generate configuration """
    service = HaproxyService()

    if service.reload_conf():
        result += "HAProxy conf updated.\n"
        result += service.reload()
    else:
        result += "HAProxy conf hasn't changed.\n"

    return result


def test_haproxy_conf(filename, conf, disabled=False):
    """ Launch HAProxy configuration verification
    :return String result of check_call command or raise
    """
    """ First open the file and write the conf """
    test_filename = "{}/{}".format(TEST_CONF_PATH, filename)

    try:
        with open(test_filename, 'w') as fd:
            fd.write(conf)
    except FileNotFoundError:
        raise ServiceTestConfigError("Directory '{}' does not seem to exist, "
                                     "cannot write file {}".format(TEST_CONF_PATH, test_filename), "haproxy")
    except PermissionError:
        raise ServiceTestConfigError("Incorrect permissions on '{}' directory, "
                                     "cannot write file {}".format(test_filename, TEST_CONF_PATH), "haproxy")
    except Exception as e:
        raise ServiceTestConfigError("Unknown error writing file {} : {}".format(test_filename, str(e)), "haproxy")

    """ Then test the conf with HAProxy command """
    try:
        """ Test haproxy config file with -c option """
        # check_call raise CallProcessError if return code is not 0
        return check_output(['/usr/local/sbin/haproxy', '-c', '-f', HAPROXY_PATH,
                             '-f', "{}/{}".format(TEST_CONF_PATH, filename)],
                            stderr=PIPE).decode('utf8')

    except CalledProcessError as e:
        stdout = e.stdout.decode('utf8')
        stderr = e.stderr.decode('utf8')
        """ If the frontend|backend is disabled, return code 2 is OK """
        if disabled and e.returncode == 2 and ("configuration file has no error" in stdout.lower()
                                               or "configuration file is valid" in stdout.lower()):
            return stdout

        logger.exception("The haproxy testing command failed with the following results: {}".format(stderr or stdout))
        raise ServiceTestConfigError("Invalid configuration.", "haproxy", traceback=(stderr + "\n" + stdout))


def get_stats():
    """ Connect to HAProxy admin socket, and retrieve stats of frontends

    :return Status of frontends as dict {frontend_name: frontend_status, ...}
    """
    try:
        cmd_res = check_output(["/usr/bin/nc", "-U", MANAGEMENT_SOCKET],
                               stderr=PIPE, input="show stat\n".encode('utf-8')).decode('utf8')

        statuses = {"FRONTEND": {}, "BACKEND": {}}
        """ cmd_res will be the form : <frontend_name> <status> """
        """ One frontend per line """
        for line in cmd_res.split("\n"):
            if not line:
                continue
            try:
                states = line.split(",")
                kind = states[1]
                if kind in ["FRONTEND", "BACKEND"]:
                    name = states[0]
                    status = states[17]
                    statuses[kind][name] = status
                    logger.debug("Status of HAProxy {} '{}' : {}".format(kind, name, status))
            except Exception as e:
                logger.error("Cannot retrieve status from '{}' line: {}".format(line, str(e)))
                continue

        return statuses

    except CalledProcessError as e:
        """ Return code != 0 """
        stdout = e.stdout.decode('utf8')
        stderr = e.stderr.decode('utf8')
        raise ServiceStatusError("Failed to connect to haproxy admin socket.", "haproxy", traceback=(stderr or stdout))


# TODO : Merge this function with hot_action_frontend !
def hot_action_backend(backend_name, action):
    """ Connect to HAProxy admin socket, and enable frontend <frontend_name>
        This is a hot modification of HAProxy conf
        :param frontend_name:   The name of the frontend in conf file
        :param action:          Action to do : enable or disable
        :return:
        """
    raise NotImplementedError()


def hot_action_frontend(frontend_name, action):
    """ Connect to HAProxy admin socket, and enable frontend <frontend_name>
    This is a hot modification of HAProxy conf
    :param frontend_name:   The name of the frontend in conf file
    :param action:          Action to do : enable or disable
    :return:
    """
    error_msg = "Failed to {} frontend '{}'".format(action, frontend_name)
    if action not in ["enable", "disable"]:
        raise ServiceError(error_msg, "haproxy", "do something not permitted",
                           traceback="Action not allowed. Allowed actions are 'enable' or 'disable'")

    try:
        cmd_res = check_output(["/usr/bin/nc", "-U", MANAGEMENT_SOCKET],
                               stderr=PIPE,
                               input="{} frontend {}\n".format(action, frontend_name).encode('utf8')
                               ).decode('utf8')

        """ If no return (or just a \n) : command has normally succeed """
        if not cmd_res.strip():
            return "Frontend named '{}' {}d.".format(frontend_name, action)

        """ If return, "frontend already enabled" or error message """
        if "is already enabled" in cmd_res:
            return cmd_res

        logger.info("Error while trying to enable frontend: {}".format(cmd_res))

        if "No such frontend" in cmd_res:
            raise ServiceError(error_msg, "haproxy", "{} frontend".format(frontend_name),
                               traceback="Frontend '{}' not found in configuration. \n"
                                          "Maybe it is disable or file not written on disk.".format(frontend_name))

        raise ServiceError(error_msg, "haproxy", "{} frontend".format(frontend_name), traceback=cmd_res)

    except CalledProcessError as e:
        stdout = e.stdout.decode('utf8')
        stderr = e.stderr.decode('utf8')
        """ The command must not raise - if no permissions stdout=null and stderr=null """
        if not stdout and not stderr:
            logger.error("The haproxy enable command failed due to insufficient rights.")
            raise ServiceError(error_msg, "haproxy", "{} frontend".format(frontend_name),
                               traceback="Connection failure to {}\n"
                                         "Insufficient rights.\n"
                                         "Make sure vlt-os is in vlt-web group and this socket has group vlt-web.".format(MANAGEMENT_SOCKET))
        else:
            logger.error("The haproxy enable command failed with the following results: {}".format(stderr or stdout))
        raise ServiceError(error_msg, "haproxy", "{} frontend".format(frontend_name), traceback=stderr or stdout)


def host_start_frontend(node_logger, frontend_name):
    node_logger.debug("Try to enable frontend '{}'".format(frontend_name))
    res = hot_action_frontend(frontend_name, "enable")
    node_logger.info("Frontend '{}' enabled : {}".format(frontend_name, res))
    return res


def host_stop_frontend(node_logger, frontend_name):
    node_logger.debug("Try to disable frontend '{}'".format(frontend_name))
    res = hot_action_frontend(frontend_name, "disable")
    node_logger.info("Frontend '{}' disabled : {}".format(frontend_name, res))
    return res


def reload_service(node_logger):
    # Do not handle exceptions here, they are handled by process_message
    service = HaproxyService()

    # Warning : can raise ServiceError
    result = service.reload()
    node_logger.info("HAProxy service reloaded : {}".format(result))

    return result


def restart_service(node_logger):
    # Do not handle exceptions here, they are handled by process_message
    service = HaproxyService()

    # Warning : can raise ServiceError
    result = service.restart()
    node_logger.info("HAProxy service restarted : {}".format(result))
    return result


def delete_conf(node_logger, filename):
    try:
        cmd_res = check_output(["/bin/rm", "{}/{}".format(HAPROXY_PATH, filename)], stderr=PIPE).decode('utf8')

        if cmd_res:
            if "sudo: no tty present and no askpass program specified" in cmd_res:
                raise ServiceError("'{}' : {}".format(filename, cmd_res.strip()), "haproxy",
                                   "delete conf file", traceback="vlt-os don't have permissions to do so, "
                                   "Check /usr/local/etc/sudoers.")

        return "'{}' successfully deleted.".format(filename)

    except CalledProcessError as e:
        """ Command raise if permission denied or file does not exists """
        stdout = e.stdout.decode('utf8')
        stderr = e.stderr.decode('utf8')
        # logger.exception("Failed to delete frontend filename '{}': {}".format(frontend_filename, stderr or stdout))
        raise ServiceError("'{}' : {}".format(filename, (stderr or stdout)), "haproxy", "delete haproxy conf file")


def build_conf(node_logger, frontend_id):
    """ Generate conf of haproxy frontend
    with it's ID
    :param node_logger: Logger sent to all API requests
    :param frontend_id: The name of the frontend in conf file
    :return:
    """
    result = ""
    node = Cluster.get_current_node()
    reload = False
    """ Firstly, try to retrieve Frontend with given id """
    from services.frontend import models  # because of circular imports

    try:
        frontend = models.Frontend.objects.get(pk=frontend_id)
        """ Generate ruleset conf of asked frontend """
        tmp = frontend.generate_conf()
        if frontend.configuration[node.name] != tmp:
            frontend.configuration[node.name] = tmp
            frontend.save()
            reload = True
        """ And write-it """

        write_conf(node_logger, [frontend.get_filename(), frontend.configuration[node.name],
                                 models.FRONTEND_OWNER, models.FRONTEND_PERMS])
        result += "Frontend '{}' conf written.\n".format(frontend_id)
    except ObjectDoesNotExist:
        raise VultureSystemError("Frontend with id {} not found, failed to generate conf.".format(frontend_id),
                                 "build HAProxy conf", traceback=" ")

    """ Restart service if needed (conf has changed) """
    service = HaproxyService()
    """ If frontend was given we cannot check if its conf has changed to restart service
     and if reload_conf is True, conf has changed so restart service
    """
    if reload:
        result = "HAProxy conf updated. Restarting service."
        result += service.restart()
    else:
        result += "HAProxy conf hasn't changed."
    return result
