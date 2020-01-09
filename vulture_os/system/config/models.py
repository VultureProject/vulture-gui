#!/home/vlt-os/env/bin/python
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Global Configuration main models'

from django.utils.translation import ugettext_lazy as _
from djongo import models

# Django project imports
from authentication.ldap.models import LDAPRepository
from toolkit.mongodb.mongo_base import MongoBase

# Required exceptions imports
from services.exceptions import ServiceExit
from system.exceptions import VultureSystemConfigError, VultureSystemError
from subprocess import CalledProcessError

# Extern modules imports
from ast import literal_eval
from tempfile import mktemp
from re import match as re_match
from subprocess import check_output, PIPE

# Logger configuration imports
import logging
logger = logging.getLogger('gui')


class Config(models.Model):
    """
    Global vulture Configuration class
    """

    pf_ssh_restrict = models.TextField(blank=False, null=False, default='any')
    pf_admin_restrict = models.TextField(blank=False, null=False, default='any')
    cluster_api_key = models.TextField(blank=False, null=False, default='changeme')
    oauth2_header_name = models.TextField(blank=False, null=False, default='X-Vlt-Token')
    portal_cookie_name = models.TextField(blank=False, null=False, default='changeme')
    public_token = models.TextField(blank=False, null=False, default='changeme')
    ldap_repository = models.ForeignKey(to=LDAPRepository, null=True, blank=False, on_delete=models.SET_NULL)
    customer_name = models.TextField(default="ACME Corporation")
    branch = models.TextField(default="community")
    predator_apikey = models.TextField(default="fdsqJr_45;..", blank=True)
    shodan_apikey = models.TextField(default="", blank=True)
    chameleon_apikey = models.TextField(default="", blank=True)
    smtp_server = models.TextField(blank=True, default="")
    pf_whitelist = models.TextField(blank=True, null=True, default="")
    pf_blacklist = models.TextField(blank=True, null=True, default="")
    ssh_authorized_key = models.TextField(blank=True, null=True, default="")
    rsa_encryption_key = models.TextField(blank=True, null=True, default="")
    logs_ttl = models.PositiveIntegerField(default=86400,
                                           verbose_name=_("Retention period of internal database logs (seconds)"),
                                           help_text=_("Retention period in seconds, of PF logs and Internal logs "
                                                       "into cluster database"))

    def to_dict(self):
        result = {
            'pf_ssh_restrict': self.pf_ssh_restrict,
            'pf_admin_restrict': self.pf_admin_restrict,
            'cluster_api_key': self.cluster_api_key,
            'oauth2_header_name': self.oauth2_header_name,
            'portal_cookie_name': self.portal_cookie_name,
            'public_token': self.public_token,
            'ldap_repository': self.ldap_repository.id if self.ldap_repository else None,
            'customer_name': self.customer_name,
            'branch': self.branch,
            'predator_apikey': self.predator_apikey,
            'shodan_apikey': self.shodan_apikey,
            'smtp_server': self.smtp_server,
            'pf_whitelist': self.pf_whitelist,
            'pf_blacklist': self.pf_blacklist,
            'ssh_authorized_key': self.ssh_authorized_key,
            'rsa_encryption_key': self.rsa_encryption_key,
            'logs_ttl': self.logs_ttl
        }

        return result

    class Meta:
        app_label = "system"

    def set_logs_ttl(self):
        """ Set keep-time of internal logs database
             by setting MongoDB indexes on PF, messageQueues and Internal logs
        """
        # Connect to mongodb
        mongo = MongoBase()
        mongo.connect()
        # Call the current node, it will connect to primary automatically
        res, mess = mongo.set_index_ttl("logs", "pf", "time", self.logs_ttl)
        if not res:
            return res, mess
        res, mess = mongo.set_index_ttl("logs", "internal", "timestamp", self.logs_ttl)
        if not res:
            return res, mess
        res, mess = mongo.set_index_ttl("vulture", "system_messagequeue", "modified", self.logs_ttl)
        if not res:
            return res, mess
        res, mess = mongo.set_index_ttl("vulture", "system_messagequeue", "date_add", self.logs_ttl)
        if not res:
            return res, mess
        return True, ""


def write_conf(logger, args):
    """ Dedicated method used to write a file on disk """
    # parse arguments because we can be called by asynchronous api
    if isinstance(args, str):
        file_path, file_content, owner, perm = literal_eval(args)
    else:
        file_path, file_content, owner, perm = args

    # Write temporary file info /tmp dir,
    #  because everybody can write onto
    temp_dir = "/var/tmp/"
    """ Create a temporary named file in {prefix} path """
    tmpfile = mktemp(prefix=temp_dir)
    logger.debug("Config::write_conf: Writing into {}".format(tmpfile))

    command = ""
    try:
        """ Try to open the tmp file - it might not raise.... """
        with open(tmpfile, "w", encoding="utf8") as f:
            f.write(str(file_content))

        """ Sudo move the file from tmp to file_path """
        logger.debug("Moving file from '{}' to '{}'".format(tmpfile, file_path))
        command = ['/usr/local/bin/sudo', '/bin/mv', tmpfile, file_path]
        check_output(command, stderr=PIPE)

        """ Sudo apply owner on file_path """
        logger.debug("Applying owner '{}' on file '{}'".format(owner, file_path))
        command = ['/usr/local/bin/sudo', '/usr/sbin/chown', owner, file_path]
        check_output(command, stderr=PIPE)

        """ Sudo apply permissions on file_path """
        logger.debug("Applying permissions '{}' on file '{}'".format(perm, file_path))
        command = ['/usr/local/bin/sudo', '/bin/chmod', perm, file_path]
        check_output(command, stderr=PIPE)

        logger.info("File '{}' successfully written.".format(file_path))

    except FileNotFoundError as e:
        logger.error("Failed to open file {}: {}".format(file_path, str(e)))
        raise VultureSystemConfigError("The path '{}' or '{}' does not seem to exist.".format(temp_dir,
                                                                                              "/".join(file_path.split('/')[:-1])))

    except PermissionError as e:
        logger.error("Failed to create/write file {}:".format(file_path))
        logger.exception(e)
        raise VultureSystemConfigError("The path '{}' does not have correct permissions. \n "
                                       "Cannot create/write the file '{}'.".format(temp_dir, tmpfile))
    except CalledProcessError as e:
        logger.error("Failed to execute command {}: {}".format(command, e.stderr))
        logger.exception(e)

        # Catch sudoers failure
        if "sudo: no tty present and no askpass program specified" in e.stderr.decode('utf8'):
            raise VultureSystemConfigError("The file '/usr/local/etc/sudoers.d/vulture_sudoers' is not correct, "
                                           "cannot execute command", traceback=e.stderr.decode('utf8'))
        if "No such file or directory" in e.stderr.decode('utf8'):
            raise VultureSystemConfigError("Directory '{}' does not seems to exists.".format('/'.join(file_path.split('/')[:-1])),
                                           traceback=e.stderr.decode('utf8'))

        raise VultureSystemConfigError("Bad permissions on directory '{}'.".format(temp_dir),
                                       traceback=(e.stdout or e.stderr).decode('utf8'))
    # Do NOT remove THIS ! Used to handle "service vultured stop"
    except ServiceExit:
        raise

    except Exception as e:
        logger.error("No referenced error in write_conf method : ")
        logger.exception(e)
        raise VultureSystemConfigError("Unknown error occurred. \n"
                                       "Please see traceback for more informations.")


def delete_conf(logger, filename):
    """ """
    # Import here to prevent circular import
    from system.error_templates.models import CONF_PATH as ERROR_TPL_PATH
    from applications.reputation_ctx.models import DATABASES_PATH as REPUTATION_CTX_DB_PATH
    from system.pki.models import CERT_PATH
    from darwin.defender_policy.models import DEFENDER_PATH
    from darwin.defender_policy.policy import HAPROXY_PATH
    from services.darwin.darwin import DARWIN_PATH
    from services.rsyslogd.rsyslog import RSYSLOG_PATH

    allowed_files_regex = ["{}/\w+_\d+\.html".format(ERROR_TPL_PATH),
                           "{}/reputation_ctx_\d+\.mmdb".format(REPUTATION_CTX_DB_PATH),
                           "{}/[\w\_\-\.]+-\d\.(chain|crt|pem|key)".format(CERT_PATH),
                           "{}/defender_[0-9]+?\.conf".format(DEFENDER_PATH),
                           "{}/spoe_defender_[0-9]+?\.txt".format(HAPROXY_PATH),
                           "{}/backend_defender_[0-9]+?\.cfg".format(HAPROXY_PATH),
                           "{}/parser_[0-9]+\.rb".format(RSYSLOG_PATH),
                           "{}/f[\w-]+/f[\w-]+_[0-9]+.conf".format(DARWIN_PATH)]

    allowed = False
    for regex in allowed_files_regex:
        if re_match(regex, filename):
            allowed = True
            break

    if not allowed:
        raise VultureSystemConfigError("File '{}' not allowed to be deleted.".format(filename))

    try:
        cmd_res = check_output(["/bin/rm", filename], stderr=PIPE).decode('utf8')

        if cmd_res:
            raise VultureSystemConfigError("'{}' : {}".format(filename, cmd_res.strip()),
                                           "delete config file", traceback=" ")

        return "Config'{}' successfully deleted.".format(filename)

    except CalledProcessError as e:
        """ Command raise if permission denied or file does not exist """
        stdout = e.stdout.decode('utf8')
        stderr = e.stderr.decode('utf8')
        # logger.exception("Failed to delete frontend filename '{}': {}".format(frontend_filename, stderr or stdout))
        raise VultureSystemError("'{}' : {}".format(filename, (stderr or stdout)), "delete config file",
                                 traceback=" ")
