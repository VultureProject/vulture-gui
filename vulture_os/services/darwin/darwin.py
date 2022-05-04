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
from applications.reputation_ctx.models import ReputationContext
from darwin.policy.models import DarwinPolicy, FilterPolicy, DarwinFilter
from django.utils.translation import ugettext_lazy as _
from services.rsyslogd.rsyslog import build_conf as rsyslog_build_conf
from services.service import Service
from services.darwin.models import DarwinSettings
from system.cluster.models import Cluster
from system.config.models import write_conf, delete_conf as delete_conf_file

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from json import JSONDecodeError, dumps as json_dumps
from services.exceptions import ServiceStatusError, ServiceReloadError, ServiceExit
from system.exceptions import VultureSystemError
from subprocess import CalledProcessError

# Extern modules imports
from glob import glob as file_glob
from json import loads as json_loads
from os import walk as os_walk
from re import compile as re_compile
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


def _send_command(node_logger, command):
    logger.info("sending command to darwin manager: '{}'".format(command))
    try:
        """ Try to connect and send command to Darwin manager """
        cmd_res = check_output(["/usr/bin/nc", "-U", MANAGEMENT_SOCKET],
                               stderr=PIPE,
                               input=command.encode('utf8'),
                               timeout=60).decode('utf8')
        node_logger.info("Connection to darwin management socket succeed.")
        """ Darwin manager always answer in JSON """
        try:
            json_res = json_loads(cmd_res)
        except JSONDecodeError:
            raise ServiceReloadError("Darwin manager response is not a valid JSON", "Darwin",
                                        traceback=cmd_res)

        return json_res

    except CalledProcessError as e:
        """ Return code != 0 """
        stdout = e.stdout.decode('utf8')
        stderr = e.stderr.decode('utf8')
        raise ServiceReloadError("Failed to connect to darwin management socket.", "Darwin",
                                    traceback=(stderr or stdout))



def get_darwin_sockets():
    return [obj.socket_path for obj in FilterPolicy.objects.all()]


def _reload_filters(node_logger):
    reply = _send_command(node_logger, "{\"type\": \"update_filters\"}\n")
    if reply.get('status') == "KO":
            raise ServiceReloadError("Darwin manager failed to update some filter(s): {}".format(reply.get('errors', '')), "Darwin")
    elif reply.get('status') != "OK":
        raise ServiceReloadError("Darwin manager returned an unexpected result: {}".format(reply.get('errors', '')), "Darwin")
    return "Darwin reloaded successfully"



def reload_conf(node_logger):
    result = "Configuration has not changed"
    service = DarwinService()
    node_logger.debug("Reloading conf of service Darwin.")

    conf_changed = service.reload_conf()

    if conf_changed:
        result = "Configuration has changed, reloading Darwin.\n"
        result += _reload_filters(node_logger)
    return result


def reload_policy_filters(node_logger, policy_id):
    """ Triggers a reload of all filters related to a policy
    """
    try:
        policy = DarwinPolicy.objects.get(pk=policy_id)
    except DarwinPolicy.DoesNotExist:
        raise VultureSystemError("Could not get policy with id {}".format(policy_id), "write Darwin configuration files for a policy")
    logger.info("writing policy conf '{}'".format(policy.name))

    filters = [f.name for f in policy.filterpolicy_set.all()]
    reply = _send_command(node_logger, "{{\"type\": \"update_filters\", \"filters\": {}}}".format(str(list(filters)).replace("'", '"')))
    # Do not raise an exception if the status is KO -> that could be disabled or not-yet-existing filters in darwin.conf
    return reply


def reload_all(node_logger):
    """ Triggers a rewrite of all filters' configuration file, main configuration file and reload all filters
    """
    logger.info("Darwin::reload_all:: Reloading all Darwin configuration")
    this_node = Cluster.get_current_node()

    # Reload every filter's config file
    for policy in DarwinPolicy.objects.all().only("id"):
        try:
            logger.debug("Darwin::reload_all:: updating configuration files for policy {}".format(policy.id))
            write_policy_conf(node_logger, policy.id)
            logger.info("Darwin::reload_all:: Regenerating configuration for associated Listeners...")
            # SHOULD always be the case (should is key here)
            if this_node is not None:
                for frontend in policy.frontend_set.all():
                    if this_node in frontend.get_nodes():
                        rsyslog_build_conf(node_logger, frontend.pk)
                logger.info("Darwin::reload_all:: Successfully updated configuration files")
            else:
                logger.error("Darwin::reload_all:: Couldn't get current node, cannot update Rsyslog configuration files")
        except VultureSystemError as e:
            logger.error("Darwin::reload_all:: error while reloading policy {} : {}".format(policy.id, e))
            continue

    # Reload the main Darwin configuration (don't update filters yet)
    logger.info("Darwin::reload_all:: rewriting main configuration file")
    reload_conf(node_logger)

    return restart_service(node_logger)


def delete_filter_conf(node_logger, filter_conf_path):
    """ Deletes all policy filters' configuration file
    """
    logger.info("deleting policy filter configuration '{}'".format(filter_conf_path))
    error = False
    result = ""

    try:
        delete_conf_file(
            node_logger,
            filter_conf_path
        )
        result += "Configuration file '{}' deleted\n".format(filter_conf_path)
    except ServiceExit as e: # DO NOT REMOVE IT - Needed to stop Vultured service !
        raise
    except Exception as e:
        if "No such file or directory" in str(e):
            node_logger.info("File '{}' already deleted".format(filter_conf_path))
        else:
            result += "Failed to delete configuration file '{}' : {}\n".format(filter_conf_path, e)
            error = True

    if error:
        raise VultureSystemError(result, "delete Darwin filter configuration {}".format(filter_conf_path))
    return result


def write_policy_conf(node_logger, policy_id):
    """ Writes all enabled filters' configuration in a policy
        Also deletes configuration files of all previously enabled filters in the policy
    """
    error = False
    result = ""
    try:
        policy = DarwinPolicy.objects.get(pk=policy_id)
    except DarwinPolicy.DoesNotExist:
        raise VultureSystemError("Could not get policy with id {}".format(policy_id), "write Darwin configuration files for a policy")
    logger.info("writing policy conf '{}'".format(policy.name))

    for filter_instance in policy.filterpolicy_set.all():

        if filter_instance.enabled and filter_instance.filter_type.is_launchable:
            logger.info("writing filter '{}' conf".format(filter_instance.name))

            try:
                write_conf(
                    node_logger,
                    [
                        filter_instance.conf_path,
                        "{}\n".format(filter_instance.conf_to_json()),
                        DARWIN_OWNERS, DARWIN_PERMS
                    ]
                )
            except ServiceExit:
                raise
            except Exception as e:
                logger.error("Darwin::write_policy_conf:: error while writing conf: {}".format(e))
                logger.critical(e, exc_info=1)
                result += "error while writing file '{}': {}\n".format(filter_instance.conf_path, e)
                error = True
                continue

            result += "\nSuccessfully wrote file '{}'".format(filter_instance.conf_path)

        else:
            logger.info("filter '{}' not enabled, deleting conf".format(filter_instance.name))

            try:
                delete_conf_file(
                    node_logger,
                    filter_instance.conf_path
                )
            except ServiceExit:
                raise
            except Exception as e:
                if "No such file or directory" in str(e):
                    node_logger.info("File '{}' already deleted".format(filter_instance.conf_path))
                else:
                    result += "Failed to delete configuration file '{}' : {}\n".format(filter_instance.conf_path, e)
                    error = True

    if error:
        raise VultureSystemError(result, "write Darwin configuration files for policy {}".format(policy_id))
    return result


def update_filter(node_logger, filter_id):
    """ Hot update of Darwin filter with management unix socket
         Only used when an attribute of a filter has been modified
          (for example the log level)
    """
    try:
        darwin_filter = FilterPolicy.objects.get(pk=filter_id)
    except ObjectDoesNotExist:
        raise ServiceReloadError("DarwinFilter with id {} not found".format(filter_id), "Darwin")

    reply = _send_command(node_logger, "{{\"type\": \"update_filters\", " \
        "\"filters\": [\"{}\"]}}\n".format(darwin_filter.name))
    if reply.get('status') == "KO":
            raise ServiceReloadError("Darwin manager failed to update filter '{}': {}".format(darwin_filter.name, reply.get('errors', '')), "Darwin")
    elif reply.get('status') != "OK":
        raise ServiceReloadError("Darwin manager returned an unexpected result: {}".format(reply.get('errors', ''), "Darwin"))
    node_logger.info("Darwin filter '{}' hot update successful.".format(darwin_filter.name))
    return "Darwin filter '{}' hot update successful.".format(darwin_filter.name)


def monitor_filters():
    """ Connect to darwin management socket and ask monitor of the filters
    :return     The json response of darwin : {'filter1': , 'filter2': ...}
    """
    try:
        """ Connect to Darwin manager and try to monitor filters """
        cmd_res = check_output(["/usr/bin/nc", "-U", MANAGEMENT_SOCKET],
                               stderr=PIPE,
                               input="{\"type\": \"monitor\"}\n".encode('utf8'),
                               timeout=20).decode('utf8')
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


def init_default_ioc_policy(node_logger):
    try:
        lkup_filter_type = DarwinFilter.objects.get(name="lkup")
    except DarwinFilter.DoesNotExist:
        raise VultureSystemError("filter type 'lkup' does not exist", "create default Darwin IOC detection policy")

    try:
        policy, created = DarwinPolicy.objects.get_or_create(
            name="Default Detect IOCs",
            defaults={
                "description": "This policy is an example of possible lookups for IOC detection in data from logs, network...",
                "is_internal": False
            }
        )
    except Exception as e:
        node_logger.error("darwin::init_default_ioc_policy:: error while get_or_creat'ing ioc detection policy: {}".format(e))
        raise VultureSystemError("could not get or create policy", "create default Darwin IOC detection policy")

    if created:
        node_logger.info("darwin::init_default_ioc_policy:: policy was created, adding filters")
        for rep_context in ReputationContext.objects.filter(db_type="lookup"):
            try:
                dfilter = FilterPolicy.objects.create(
                    enabled=True,
                    filter_type=lkup_filter_type,
                    policy=policy,
                    config = {
                        "reputation_ctx_id": rep_context.id,
                        "db_type": "rsyslog"
                    }
                )
                dfilter.save()
            except Exception as e:
                node_logger.error("darwin::init_default_ioc_policy:: error while creating filter for default IOC detection Darwin policy: {}".format(e))
                raise VultureSystemError("could not create a filter", "create default Darwin IOC detection policy")

    if not policy.filterpolicy_set.exists():
        logger.warning("darwin::init_default_ioc_policy:: no filter in policy, removing policy")
        policy.delete()
        return "no context tags, not creating Darwin policy"

    return "Darwin policy created successfuly"