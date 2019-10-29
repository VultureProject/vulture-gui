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
__doc__ = 'Rsyslog service wrapper utils'

# Django system imports
from django.conf import settings

# Django project imports
from darwin.policy.models import FilterPolicy
from services.service import Service
from services.darwin.models import DarwinSettings
from system.config.models import write_conf, delete_conf as delete_conf_file

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from json import JSONDecodeError, dumps as json_dumps
from services.exceptions import ServiceStatusError, ServiceDarwinUpdateFilterError
from subprocess import CalledProcessError

# Extern modules imports
from json import loads as json_loads
from subprocess import check_output, PIPE

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


DARWIN_PATH = "/home/darwin/conf"
DARWIN_PERMS = "640"
DARWIN_OWNERS = "darwin:vlt-conf"
MANAGEMENT_SOCKET = "/var/sockets/darwin/darwin.sock"


class DarwinService(Service):
    """ Darwin service class wrapper """

    def __init__(self):
        super().__init__()
        self.model = DarwinSettings
        self.service_name = "darwin"
        self.friendly_name = "AI Framework"

        self.config_file = "darwin.conf"
        self.owners = DARWIN_OWNERS
        self.perms = DARWIN_PERMS
        self.jinja_template = {
            'tpl_name': self.config_file,
            'tpl_path': "{}/{}".format(DARWIN_PATH, self.config_file),
        }

    def __str__(self):
        return "Darwin Service"


def delete_policy_conf(node_logger, policy_conf_path):
    return delete_conf_file(
        node_logger,
        policy_conf_path
    )


def write_policy_conf(node_logger, policy_id):
    logger.info("writing policy conf for filterpolicy id {}".format(policy_id))
    policy = FilterPolicy.objects.get(pk=policy_id)

    logger.info("writing policy '{}' conf".format(policy.filter.name))

    conf_path = "{darwin_path}/f{filter_name}/f{filter_name}_{darwin_policy_id}.conf".format(
        darwin_path=DARWIN_PATH, filter_name=policy.filter.name, darwin_policy_id=policy.policy.pk
    )

    write_conf(
        node_logger,
        [
            conf_path,
            "{}\n".format(json_dumps(policy.config, sort_keys=True, indent=4)),
            DARWIN_OWNERS, DARWIN_PERMS
        ]
    )

    return "{} successfully written.".format(conf_path)


def build_conf(node_logger):
    """ Method used by vultured API to build conf 
            & write if has changed
            and restart the service if needed
        Only used when a filter is added or deleted
    """
    service = DarwinService()
    node_logger.debug("Reloading conf of service Darwin.")
    conf_changed = service.reload_conf()

    result = "Darwin configuration has not changed."
    # Restart service only if conf has changed
    if conf_changed:
        node_logger.debug("Conf has changed. Restarting Darwin service.")
        result = "Conf has changed. Restarting Darwin service."
        result += service.restart()
    return result


def update_filter(node_logger, filter_id):
    """ Hot update of Darwin filter with management unix socket 
         Only used when an attribute of a filter has been modified
          (for example the log level)
    """
    try:
        darwin_filter = FilterPolicy.objects.get(pk=filter_id)
    except ObjectDoesNotExist:
        raise ServiceDarwinUpdateFilterError("FilterPolicy with id {} not found, ".format(filter_id), traceback=" ")
    try:
        """ Connect to Darwin manager and try to update filter """
        cmd_res = check_output(["/usr/bin/nc", "-U", MANAGEMENT_SOCKET],
                               stderr=PIPE,
                               input="{{\"type\": \"update_filters\", " \
                                     "\"filters\": [\"{}\"]}}\n".format(darwin_filter.name).encode('utf8')
                               ).decode('utf8')
        node_logger.info("Connection to darwin management socket succeed.")
        """ Darwin manager always answer in JSON """
        try:
            json_res = json_loads(cmd_res)
        except JSONDecodeError:
            # Do NOT set traceback, it will be retrieved from JSON exception
            raise ServiceDarwinUpdateFilterError("Darwin manager response is not a valid JSON : '{}'".format(cmd_res))

        node_logger.info("Darwin manager response decoded : {}".format(json_res))
        """ Retrieve status (and error) """
        if json_res.get('status') == "KO":
            raise ServiceDarwinUpdateFilterError("Darwin manager returned error: {}.".format(json_res.get('errors')))
        elif json_res.get('status') != "OK":
            raise ServiceDarwinUpdateFilterError("Darwin manager returned unknown response: {}.".format(json_res),
                                                 traceback=json_res.get('errors'))
        node_logger.info("Darwin filter '{}' hotly updated.".format(darwin_filter.name))
        return "Darwin filter '{}' hotly updated.".format(darwin_filter.name)

    except CalledProcessError as e:
        """ Return code != 0 """
        stdout = e.stdout.decode('utf8')
        stderr = e.stderr.decode('utf8')
        raise ServiceDarwinUpdateFilterError("Failed to connect to darwin management socket.",
                                             traceback=(stderr or stdout))


def monitor_filters():
    """ Connect to darwin management socket and ask monitor of the filters
    :return     The json response of darwin : {'filter1': , 'filter2': ...}
    """
    try:
        """ Connect to Darwin manager and try to monitor filters """
        cmd_res = check_output(["/usr/bin/nc", "-U", MANAGEMENT_SOCKET],
                               stderr=PIPE, input="{\"type\": \"monitor\"}\n".encode('utf8')).decode('utf8')
        logger.debug("Connection to darwin management socket succeed.")
        """ Darwin manager always answer in JSON """
        try:
            json_res = json_loads(cmd_res)
        except JSONDecodeError:
            # Do NOT set traceback, it will be retrieved from JSON exception
            raise ServiceStatusError("Darwin manager response is not a valid JSON : '{}'".format(cmd_res), "darwin")

        logger.debug("Darwin manager response decoded.")
        return json_res

    except CalledProcessError as e:
        """ Return code != 0 """
        stdout = e.stdout.decode('utf8')
        stderr = e.stderr.decode('utf8')
        raise ServiceStatusError("Failed to connect to darwin management socket.",
                                 "darwin", traceback=(stderr or stdout))


def restart_service(node_logger):
    """ Method used by vultured API to restart darwin service """
    # Do not handle exceptions here, they are handled by process_message
    service = DarwinService()

    # Warning : can raise ServiceError
    result = service.restart()
    node_logger.info("Darwin service restarted : {}".format(result))

    return result


def start_service(node_logger):
    """ Method used by vultured API to start darwin service """
    # Do not handle exceptions here, they are handled by process_message
    service = DarwinService()

    # Warning : can raise ServiceError
    result = service.start()
    node_logger.info("Darwin service started : {}".format(result))

    return result
