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
__doc__ = 'Frontends & Listeners model classes'

# Django system imports
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils.crypto import get_random_string
from django.utils.translation import ugettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models

# Django project imports
from services.haproxy.haproxy import hot_action_frontend, hot_action_backend, test_haproxy_conf, HAPROXY_OWNER, HAPROXY_PATH, HAPROXY_PERMS, TEST_CONF_PATH
from toolkit.http.headers import Header
from system.cluster.models import Cluster, NetworkAddress, Node
from system.pki.models import TLSProfile
from toolkit.network.network import JAIL_ADDRESSES

# Extern modules imports
from jinja2 import Environment, FileSystemLoader

# Required exceptions imports
from jinja2.exceptions import (TemplateAssertionError, TemplateNotFound, TemplatesNotFound, TemplateRuntimeError,
                               TemplateSyntaxError, UndefinedError)
from services.exceptions import (ServiceConfigError, ServiceJinjaError, ServiceStatusError, ServiceStartError,
                                 ServiceTestConfigError, ServiceError)
from system.exceptions import VultureSystemConfigError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

# Modes choices of HAProxy Frontends
MODE_CHOICES = (
    ('tcp', 'TCP'),
    ('http', 'HTTP'),
)

SERVER_MODE_CHOICES = (
    ('net', 'network'),
    ('unix', 'unix sockets'),
)

LOG_LEVEL_CHOICES = (
    ('info', "Info"),
    ('debug', "Debug")
)

# Modes choices of HAProxy HTTP Backend
HEALTH_CHECK_VERSION_CHOICES = (
    ('HTTP/1.0\\r\\n', 'HTTP/1.0'),
    ('HTTP/1.1\\r\\n', 'HTTP/1.1')
)

HEALTH_CHECK_METHOD_CHOICES = (
    ('GET', 'GET'),
    ('POST', 'POST'),
    ('PUT', 'PUT'),
    ('PATCH', 'PATCH'),
    ('DELETE', 'DELETE'),
)

HEALTH_CHECK_EXPECT_CHOICES = (
    ('status', 'Status code is'),
    ('rstatus', 'Status code match regex'),
    ('string', 'Response content contains'),
    ('rstring', 'Response content match regex'),
    ('! status', 'Status code different'),
    ('! rstatus', 'Status code does not match regex'),
    ('! string', 'Response content does not contain'),
    ('! rstring', 'Response content does not match regex')
)

BALANCING_CHOICES = (
    ('roundrobin', "RoundRobin"),
    ('static-rr', "Static RoundRobin"),
    ('leastconn', "Least Conn"),
    ('first', "First server"),
    ('source', "Source IP based"),
    ('uri', "URI based"),
    ('url_param', "URL param based"),
    ('hdr', "Header based"),
    ('rdp-cookie', "Cookie based"),
)

# Jinja template for backends rendering
JINJA_PATH = "/home/vlt-os/vulture_os/applications/backend/config/"
JINJA_TEMPLATE = "haproxy_backend.conf"

BACKEND_OWNER = HAPROXY_OWNER
BACKEND_PERMS = HAPROXY_PERMS

UNIX_SOCKET_PATH = "/var/sockets/rsyslog"


class Backend(models.Model):
    """ Model used to generated fontends configuration of HAProxy """
    """ Is that section enabled or disabled """
    enabled = models.BooleanField(
        default=True,
        help_text=_("Enable the backend"),
    )
    """ Name of the frontend, unique constraint """
    name = models.TextField(
        unique=True,
        default="Backend",
        help_text=_("Name of HAProxy backend"),
    )
    """ Listening mode of Frontend : tcp or http """
    mode = models.TextField(
        default=MODE_CHOICES[0][0],
        choices=MODE_CHOICES,
        help_text=_("Proxy mode"),
    )
    timeout_connect = models.PositiveIntegerField(
        default=2000,
        validators=[MinValueValidator(1), MaxValueValidator(20000)],
        help_text=_("HTTP request Timeout"),
        verbose_name=_("Timeout")
    )
    timeout_server = models.PositiveIntegerField(
        default=60,
        validators=[MinValueValidator(1), MaxValueValidator(3600)],
        help_text=_("HTTP request Timeout"),
        verbose_name=_("Timeout")
    )
    """ Save of generated configuration """
    configuration = models.TextField(
        default="{}"
    )
    """ Status of frontend for each nodes """
    status = models.JSONField(
        default={}
    )
    """ Headers """
    headers = models.ArrayReferenceField(
        Header,
        null=True,
        blank=False,
        on_delete=models.CASCADE,
        help_text=_("Header rules")
    )
    """ Custom HAProxy Backend directives """
    custom_haproxy_conf = models.TextField(
        default="",
        help_text=_("Custom HAProxy configuration directives.")
    )

    """ HTTP Options """
    """ URI of backends """
    http_backend_dir = models.TextField(
        default="/",
        help_text=_("Servers directory to prefix in front of requests uri"),
        verbose_name=_("Servers directory")
    )
    """ Enable or disable relaxing of HTTP response parsing """
    accept_invalid_http_response = models.BooleanField(
        default=False,
        help_text=_("Enable relaxing of HTTP response parsing"),
        verbose_name=_("Accept invalid HTTP response")
    )
    """ Enable insertion of the X-Forwarded-For header to requests sent to servers """
    http_forwardfor_header = models.TextField(
        blank=True,
        null=True,
        help_text=_("Insertion of the X-Forwarded-For header"),
        verbose_name=_("Send source ip in ")
    )
    """ Except the following IP"""
    http_forwardfor_except = models.GenericIPAddressField(
        protocol='IPv4',
        blank=True,
        null=True,
        help_text=_("Except the specified IP address"),
        verbose_name=_("Except for ")
    )
    """ Enable HTTP protocol to check on the servers health """
    enable_http_health_check = models.BooleanField(
        default=False,
        help_text=_("Enable HTTP protocol health checker"),
        verbose_name=_("HTTP health check")
    )
    """ The optional HTTP method used with the requests """
    http_health_check_method = models.TextField(
        default=HEALTH_CHECK_METHOD_CHOICES[0][0],
        choices=HEALTH_CHECK_METHOD_CHOICES,
        help_text=_("HTTP method used"),
        verbose_name=_("Method")
    )
    """ The URI referenced in the HTTP requests """
    http_health_check_uri = models.TextField(
        default='/',
        blank=True,
        null=True,
        help_text=_("URI referenced"),
        verbose_name=_("URI")
    )
    """ The optional HTTP version string """
    http_health_check_version = models.TextField(
        default=HEALTH_CHECK_VERSION_CHOICES[0][0],
        choices=HEALTH_CHECK_VERSION_CHOICES,
        help_text=_("HTTP version"),
        verbose_name=_("Version")
    )
    """ """
    http_health_check_headers = models.JSONField(
        default={},
        help_text=_("HTTP Health Check Headers"),
        verbose_name=_("HTTP Health Check Headers")
    )
    """ Health check expect """
    http_health_check_expect_match = models.TextField(
        choices=HEALTH_CHECK_EXPECT_CHOICES,
        default=HEALTH_CHECK_EXPECT_CHOICES[0][0],
        null=True,
        help_text=_("Type of match to expect"),
        verbose_name=_("HTTP Health Check expected")
    )
    http_health_check_expect_pattern = models.TextField(
        default="200",
        help_text=_("Type of pattern to match to expect"),
        verbose_name=_("HTTP Health Check expected pattern")
    )
    """ Enable or disable HTTP keep-alive from client to server """
    enable_http_keep_alive = models.BooleanField(
        default=True,
        help_text=_("Enable HTTP keep-alive"),
        verbose_name=_("HTTP Keep alive")
    )
    """ Keep-alive Timeout """
    http_keep_alive_timeout = models.PositiveIntegerField(
        default=60,
        validators=[MinValueValidator(1), MaxValueValidator(20000)],
        help_text=_("HTTP request Timeout"),
        verbose_name=_("Timeout")
    )
    """ Balancing mode """
    balancing_mode = models.TextField(
        choices=BALANCING_CHOICES,
        default=BALANCING_CHOICES[0][0],
        help_text=_("Balancing mode between servers"),
        verbose_name=_("Balancing mode")
    )
    """ Balancing param """
    balancing_param = models.TextField(
        null=True,
        default="",
        help_text=_("Balancing param for balancing mode"),
        verbose_name=_("Balancing parameter")
    )
    """ Tags """
    tags = models.JSONField(
        models.SlugField(default=""),
        default=[],
        help_text=_("Tags to set on this object for search")
    )

    @property
    def balancing(self):
        if self.balancing_mode == "hdr":
            result = "hdr({})".format(self.balancing_param)
        elif self.balancing_mode == "url_param":
            result = "url_param {}".format(self.balancing_param)
        elif self.balancing_mode == "rdp-cookie":
            result = "rdp-cookie({})".format(self.balancing_param)
        else:
            result = self.balancing_mode
        return result

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name', 'mode']

    def __str__(self):
        return "{} Backend '{}'".format(self.mode.upper(), self.name)

    def to_dict(self, fields=None):
        """ This method MUST be used in API instead of to_template() method
                to prevent no-serialization of sub-models like Listeners
        :return     A JSON object
        """
        result = model_to_dict(self, fields=fields)
        if not fields or "id" in fields:
            result['id'] = str(result['id'])
        if not fields or "servers" in fields:
            result['servers'] = []
            """ Add listeners """
            for server in self.server_set.all():
                # Remove backend to prevent infinite loop
                s = server.to_dict(fields=['id','target','port','mode','weight', 'tls_profile'])
                result['servers'].append(s)
        if not fields or "status" in fields:
            result['status'] = dict(self.status)
        if not fields or "headers" in fields:
            """ Other attributes """
            if self.mode == "http":
                result['headers'] = []
                for header in self.headers.all():
                    result['headers'].append(header.to_template())
            ## set headers field anyway if requested
            elif "headers" in fields:
                result['headers'] = []

        return result

    def to_html_template(self):
        """ Dictionary used to render object as html
        :return     Dictionnary of configuration parameters
        """
        """ Retrieve list/custom objects """
        servers_list = [str(s) for s in self.server_set.all().only(*Server.str_attrs())]

        mode = "UNKNOWN"
        for m in MODE_CHOICES:
            if self.mode == m[0]:
                mode = m[1]

        balancing_mode = "unknown"
        for m in BALANCING_CHOICES:
            if self.balancing_mode == m[0]:
                balancing_mode = m[1]
        additional_infos = "Balancing mode : {}".format(balancing_mode)

        """ And returns the attributes of the class """
        return {
            'id': str(self.id),
            'enabled': self.enabled,
            'name': self.name,
            'servers': servers_list,
            'mode': mode,
            'status': self.status,
            'additional_infos': additional_infos,
            'tags': self.tags
        }

    def to_template(self, server_list=None, header_list=None):
        """ Dictionary used to create configuration file

        :return     Dictionnary of configuration parameters
        """

        workflow_list = []
        access_controls_list = []
        for workflow in self.workflow_set.filter(enabled=True):
            tmp = workflow.to_template()

            access_controls_deny = []
            access_controls_301 = []
            access_controls_302 = []
            for acl in workflow.workflowacl_set.filter(before_policy=False):
                rules, acls_name = acl.access_control.generate_rules()
                access_controls_list.append(rules)

                condition = acl.generate_condition(acls_name)

                redirect_url = None
                deny = acl.action_satisfy == "403"
                redirect = acl.action_satisfy in ("301", "302")
                for type_acl in ('action_satisfy', 'action_not_satisfy'):
                    action = getattr(acl, type_acl)
                    if action != "200":
                        if action in ("301", "302"):
                            redirect_url = getattr(acl, type_acl.replace('action', 'redirect_url'))

                        break

                tmp_acl = {
                    'before_policy': acl.before_policy,
                    'redirect_url': redirect_url,
                    'conditions': condition,
                    'action': action,
                    'deny': deny,
                    "redirect": redirect,
                }

                if action == "403":
                    access_controls_deny.append(tmp_acl)
                elif action == "301":
                    access_controls_301.append(tmp_acl)
                elif action == "302":
                    access_controls_302.append(tmp_acl)

            tmp['access_controls_deny'] = access_controls_deny
            tmp['access_controls_302'] = access_controls_302
            tmp['access_controls_301'] = access_controls_301
            workflow_list.append(tmp)

        """ Simple attributes of the class """
        result = {
            'id': str(self.id),
            'enabled': self.enabled,
            'name': self.name,
            'mode': self.mode,
            'timeout_connect': self.timeout_connect,
            'timeout_server': self.timeout_server,
            'unix_socket': self.get_unix_socket(),
            'custom_haproxy_conf': self.custom_haproxy_conf,
            'JAIL_ADDRESSES': JAIL_ADDRESSES,
            'accept_invalid_http_response': self.accept_invalid_http_response,
            'http_forwardfor_header': self.http_forwardfor_header,
            'http_forwardfor_except': self.http_forwardfor_except,
            'enable_http_health_check': self.enable_http_health_check,
            'http_health_check_method': self.http_health_check_method,
            'http_health_check_uri': self.http_health_check_uri,
            'http_health_check_version': self.http_health_check_version,
            'http_health_check_headers': self.http_health_check_headers,
            'enable_http_keep_alive': self.enable_http_keep_alive,
            'http_keep_alive_timeout': self.http_keep_alive_timeout,
            'access_controls_list': set(access_controls_list),
            'http_backend_dir': self.http_backend_dir,
            'balancing': self.balancing,
            'workflows': workflow_list,
            'tags': self.tags,
            'CONF_PATH': HAPROXY_PATH
        }
        """ Retrieve list/custom objects """
        # If facultative arg listener_list is not given
        # Retrieve all the objects used by the current frontend
        # No .only ! Used to generated conf, neither str cause we need the object
        result['servers'] = server_list or self.server_set.all()  # No .only() ! Used to generated conf
        if self.mode == "http":
            # Same for headers
            result['headers'] = header_list or self.headers.all()
            if self.enable_http_health_check and self.http_health_check_expect_match:
                result['http_health_check_expect'] = "{} {}".format(self.http_health_check_expect_match,
                                                                    self.http_health_check_expect_pattern)
        return result

    def generate_conf(self, server_list=None, header_list=None):
        """ Render the conf with Jinja template and self.to_template() method 
        :return     The generated configuration as string, or raise
        """
        # The following var is only used by error, do not forget to adapt if needed
        template_name = JINJA_PATH + JINJA_TEMPLATE
        try:
            jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
            template = jinja2_env.get_template(JINJA_TEMPLATE)
            return template.render({'conf': self.to_template(server_list=server_list,
                                                             header_list=header_list)})
        # In ALL exceptions, associate an error message
        # The exception instantiation MUST be IN except statement, to retrieve traceback in __init__
        except TemplateNotFound:
            exception = ServiceJinjaError("The following file cannot be found : '{}'".format(template_name), "haproxy")
        except TemplatesNotFound:
            exception = ServiceJinjaError("The following files cannot be found : '{}'".format(template_name), "haproxy")
        except (TemplateAssertionError, TemplateRuntimeError):
            exception = ServiceJinjaError("Unknown error in template generation: {}".format(template_name), "haproxy")
        except UndefinedError:
            exception = ServiceJinjaError("A variable is undefined while trying to render the following template: "
                                          "{}".format(template_name), "haproxy")
        except TemplateSyntaxError:
            exception = ServiceJinjaError("Syntax error in the template: '{}'".format(template_name), "haproxy")
        # If there was an exception, raise a more general exception with the message and the traceback
        raise exception

    def test_conf(self):
        """ Write the configuration attribute on disk, in test directory, as {id}.conf.new
            And test the conf with 'haproxy -c'
        :return     True or raise
        """
        """ No need to do API request cause Backends are not relative-to-node objects """
        test_filename = self.get_test_filename()
        conf = self.configuration
        # NO Node-specific configuration, we can test-it on local node
        # Backends can not be used, so do not handle the HAProxy "not used" error by setting disabled=True
        test_haproxy_conf(test_filename,
                          conf.replace("backend {}".format(self.name),
                                       "backend test_{}".format(self.id or "test")),
                          disabled=True)

    def get_test_filename(self):
        """ Return test filename for test conf with haproxy 
        """
        """ If object is not already saved : no id so default=test """
        return "backend_{}.conf".format(self.id or "test")

    def get_base_filename(self):
        """ Return the base filename (without path) """
        return "backend_{}.cfg".format(self.id)

    def get_filename(self):
        """ Return filename depending on current frontend object
        """
        return "{}/{}".format(HAPROXY_PATH, self.get_base_filename())

    def get_unix_socket(self):
        """ Return filename of unix socket on which HAProxy send data
         and on which Rsyslog listen 
        """
        return "{}/backend_{}.sock".format(UNIX_SOCKET_PATH, self.id)

    def save_conf(self):
        """ Write configuration on disk
        """
        if not self.configuration:
            return
        params = [self.get_filename(), self.configuration, BACKEND_OWNER, BACKEND_PERMS]
        try:
            Cluster.api_request('system.config.models.write_conf', config=params)
        except Exception as e:  # e used by VultureSystemConfigError
            logger.error(e, exc_info=1)
            raise VultureSystemConfigError("on cluster.\nRequest failure to write_conf()")

    def reload_conf(self):
        """ Generate conf and save it """
        self.configuration = self.generate_conf()
        self.save_conf()
        self.save()

    def enable(self):
        """ Enable backend in HAProxy, by management socket """
        """ Cannot enable a disabled frontend ('enable' field) """
        if not self.enabled:
            raise ServiceError("Cannot start a disabled backend.", "haproxy", "enable backend",
                               traceback="Please edit, enable and save a backend to start-it.")
        return hot_action_backend(self.name, "enable")

    def disable(self):
        """ Disable frontend in HAProxy, by management socket """
        if not self.enabled:
            return "This frontend is already disabled."
        """ If it is an Rsyslog only conf, return error """
        if self.mode == "log" and self.listening_mode == "udp":
            raise ServiceError("Cannot hot disable an Rsyslog only frontend.", "rsyslog", "disable frontend",
                               traceback="Please edit, disable and save the frontend.")
        return hot_action_backend(self.name, "disable")


class Server(models.Model):
    """ Link class between NetworkAddress/UnixSocket and Backend """

    """ NetworkAddress object to listen on """
    target = models.TextField(
        help_text=_("IP/hostname/socket of server"),
        default="1.2.3.4"
    )
    """ Server mode """
    mode = models.TextField(
        default=SERVER_MODE_CHOICES[0][0],
        choices=SERVER_MODE_CHOICES,
        help_text=_("Server mode (IP, unix socket)"),
    )
    """ Port to listen on """
    port = models.PositiveIntegerField(
        default=80,
        validators=[MinValueValidator(1), MaxValueValidator(65535)]
    )
    """ Backend associated to this server """
    backend = models.ForeignKey(
        to=Backend,
        on_delete=models.CASCADE
    )
    """ TLSProfile to use when listening """
    tls_profile = models.ForeignKey(
        TLSProfile,
        null=True,
        default="",
        on_delete=models.SET_DEFAULT
    )
    """ Weight of the server """
    weight = models.PositiveIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(256)],
        default=1,
        help_text=_("")
    )
    """ Source """
    source = models.GenericIPAddressField(
        default="",
        help_text=_("IP address to assign to sources")
    )

    def to_template(self):
        """ Create a JSON representation of the object

        :return     Dictionnary of configuration parameters
        """
        """ Retrieve list/custom objects """

        result = {
            'id': str(self.id),
            'target': self.target,
            'port': self.port,
            'backend':  self.backend,
            'mode': self.mode,
            'weight': self.weight,
        }

        if self.source:
            result['source'] = self.source

        return result

    def __str__(self):
        if self.mode == "net":
            return "{}:{}".format(self.target, self.port)
        else:
            return self.target

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['target', 'port']

    def generate_conf(self):
        """ Generate Listener HAProxy configuration
        :return     A string - Bind directive
        """
        result = "server srv{} {}{} weight {}".format(self.id or get_random_string(),
                                                       self.target,
                                                       ":" + str(self.port) if self.mode == "net" else "",
                                                       self.weight)
        if self.source:
            if ":" in self.source:
                result += " source [{}]".format(self.source)
            else:
                result += " source {}".format(self.source)
        if self.tls_profile:
            result += self.tls_profile.generate_conf(backend=True)
        return result
