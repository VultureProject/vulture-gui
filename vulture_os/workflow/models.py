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
__doc__ = 'Workflow model classes'

# Django system imports
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models
from django.template import Context
from django.template import Template

# Django project imports
from applications.backend.models import Backend
from darwin.access_control.models import AccessControl
from authentication.auth_access_control.models import AuthAccessControl
from authentication.user_portal.models import UserAuthentication
from services.frontend.models import Frontend
from services.haproxy.haproxy import HAPROXY_OWNER, HAPROXY_PERMS, HAPROXY_PATH
from system.cluster.models import Cluster, Node

# Extern modules imports
from jinja2 import Environment, FileSystemLoader
from os.path import join as path_join

# Required exceptions imports
from portal.system.exceptions import ACLError
from jinja2.exceptions import (TemplateAssertionError, TemplateNotFound, TemplatesNotFound, TemplateRuntimeError,
                               TemplateSyntaxError, UndefinedError)
from services.exceptions import ServiceJinjaError
from system.exceptions import VultureSystemConfigError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

# Jinja template for backends rendering
JINJA_PATH = path_join(settings.BASE_DIR, "workflow/config/")
JINJA_TEMPLATE = "haproxy_portal.conf"

WORKFLOW_OWNER = HAPROXY_OWNER
WORKFLOW_PERMS = HAPROXY_PERMS

CORS_METHODS = (
    ('*', 'All'),
    ('GET', 'GET'),
    ('POST', 'POST'),
    ('PUT', 'PUT'),
    ('PATCH', 'PATCH'),
    ('DELETE', 'DELETE'),
    ('HEAD', 'HEAD'),
    ('CONNECT', 'CONNECT'),
    ('OPTIONS', 'OPTIONS'),
    ('TRACE', 'TRACE')
)


class WorkflowACL(models.Model):
    workflow = models.ForeignKey('Workflow', on_delete=models.CASCADE)
    order = models.IntegerField(default=1)
    access_control = models.ForeignKey(AccessControl, on_delete=models.PROTECT, null=True)
    action_satisfy = models.TextField()
    action_not_satisfy = models.TextField()
    redirect_url_satisfy = models.TextField()
    redirect_url_not_satisfy = models.TextField()
    before_policy = models.BooleanField(default=True)


    def generate_condition(self, or_groups):
        conditions = []

        for or_group in or_groups:
            # join AND rules in a OR group
            conditions.append(" ".join(or_group))

        return conditions


    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "access_control" in fields:
            result['access_control'] = self.access_control.to_template()
        return result


class Workflow(models.Model):
    """ Join class of Frontend-Backend """
    enabled = models.BooleanField(default=True)
    name = models.TextField(help_text=_("Friendly name"), default="")

    """ Frontend """
    frontend = models.ForeignKey(
        Frontend,
        on_delete=models.PROTECT,
        help_text=_("Frontend"),
    )
    """ Authentication """
    authentication = models.ForeignKey(
        UserAuthentication,
        on_delete=models.PROTECT,
        null=True
    )
    authentication_filter = models.ForeignKey(
        AuthAccessControl,
        on_delete=models.PROTECT,
        null=True
    )
    """ FQDN """
    fqdn = models.TextField(
        help_text=_("Public name")
    )
    public_dir = models.TextField(
        help_text=_("Directory on which apply the conf")
    )
    """ Backend """
    backend = models.ForeignKey(
        Backend,
        on_delete=models.PROTECT,
        help_text=_("Backend"),
    )
    """ CORS Policy """
    enable_cors_policy = models.BooleanField(
        default=False,
        verbose_name=_("Enable CORS policy"),
        help_text=_("Switch to enable specified CORS policy")
    )
    cors_allowed_methods = models.JSONField(
        default=[CORS_METHODS[0][0]],
        choices=CORS_METHODS,
        blank=True,
        verbose_name=_("Allowed methods"),
        help_text=_("Restrict requests to provided methods")
    )
    cors_allowed_origins = models.TextField(
        default="*",
        blank=True,
        verbose_name=_("Allowed origins"),
        help_text=_("Origins allowed to handle the response")
    )
    cors_allowed_headers = models.TextField(
        default="*",
        blank=True,
        verbose_name=_("Allowed headers"),
        help_text=_("Headers field allowed in the request")
    )
    cors_max_age = models.PositiveIntegerField(
        default=600,
        blank=True,
        verbose_name=_("Max age"),
        help_text=_("Maximum number of seconds the results can be cached")
    )

    workflow_json = models.JSONField(default=[])

    class Meta:
        unique_together = (('frontend', 'fqdn', 'public_dir', 'backend'),)

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def __str__(self):
        return f"Workflow {self.name}"

    @property
    def mode(self):
        return "http" if self.frontend.mode == "http" else "tcp"

    def to_html_template(self):
        """ Dictionary used to render object as html
        :return     Dictionnary of configuration parameters
        """
        """ Retrieve list/custom objects """

        """ And returns the attributes of the class """
        tmp = {
            'id': str(self.id),
            'name': self.name,
            'fqdn': self.fqdn,
            'enabled': self.enabled,
            'frontend': str(self.frontend),
            'public_dir': self.public_dir,
            'backend': str(self.backend),
            'enable_cors_policy': self.enable_cors_policy,
            'cors_allowed_methods': self.cors_allowed_methods,
            'cors_allowed_origins': self.cors_allowed_origins,
            'cors_allowed_headers': self.cors_allowed_headers,
            'cors_max_age': self.cors_max_age,
            'frontend_status': dict(self.frontend.status),
            'backend_status': dict(self.backend.status),
            # Test self.pk to prevent M2M errors when object isn't saved in DB
            'acls': self.workflowacl_set.count() if self.pk else 0,
            'authentication': str(self.authentication)
        }
        return tmp

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "id" in fields:
            result['id'] = str(result['id'])
        if not fields or "frontend" in fields:
            result['frontend'] = self.frontend.to_dict()
        if not fields or "backend" in fields:
            result['backend'] = self.backend.to_dict()
        if not fields or "frontend_status" in fields:
            result['frontend_status'] = dict(self.frontend.status)
        if not fields or "backend_status" in fields:
            result['backend_status'] = dict(self.backend.status)
        if not fields or "authentication" in fields:
            result['authentication'] = self.authentication.to_dict() if self.authentication else None
        if not fields or "acls" in fields:
            # Test self.pk to prevent M2M errors when object isn't saved in DB
            result['acls'] = [acl.to_dict() for acl in self.workflowacl_set.all()] if self.pk else []
        return result

    def to_template(self):
        """ Dictionary used to create configuration file

        :return     Dictionary of configuration parameters
        """
        """ Retrieve list/custom objects """
        """ And returns the attributes of the class """

        access_controls_list = []
        access_controls_deny = []
        access_controls_301 = []
        access_controls_302 = []
        for acl in self.workflowacl_set.filter(before_policy=True):
            rules, acls_name = acl.access_control.generate_rules()
            access_controls_list.append(rules)

            conditions = acl.generate_condition(acls_name)

            redirect_url = None
            deny = acl.action_satisfy == "403"
            redirect = acl.action_satisfy in ("301", "302")
            action = "200"
            for type_acl in ('action_satisfy', 'action_not_satisfy'):
                action = getattr(acl, type_acl)
                if action != "200":
                    if action in ("301", "302"):
                        redirect_url = getattr(acl, type_acl.replace('action', 'redirect_url'))

                    break

            tmp_acl = {
                'redirect_url': redirect_url,
                'conditions': conditions,
                'deny': deny,
                "redirect": redirect,
            }

            if action == "403":
                access_controls_deny.append(tmp_acl)
            elif action == "301":
                access_controls_301.append(tmp_acl)
            elif action == "302":
                access_controls_302.append(tmp_acl)

        client_ids = []
        if self.authentication:
            client_ids = [repo.get_daughter().client_id for repo in self.authentication.repositories.filter(subtype="openid")]
            client_ids.append(self.authentication.oauth_client_id)

        return {
            'id': str(self.pk),
            'name': self.name,
            'enabled': self.enabled,
            'fqdn': self.fqdn,
            'public_dir': self.public_dir,
            'mode': self.mode,
            'frontend': self.frontend,
            'backend': self.backend,
            'enable_cors_policy': self.enable_cors_policy,
            'cors_allowed_methods': self.cors_allowed_methods,
            'cors_allowed_origins': self.cors_allowed_origins,
            'cors_allowed_headers': self.cors_allowed_headers,
            'cors_max_age': self.cors_max_age,
            'authentication': self.authentication.to_template() if self.authentication else None,
            'check_jwt': self.authentication.repositories.filter(openidrepository__enable_jwt=True).exists() if self.authentication else False,
            'access_controls_list': set(access_controls_list),
            'access_controls_deny': access_controls_deny,
            'access_controls_302': access_controls_302,
            'access_controls_301': access_controls_301,
            'openid_client_ids': client_ids,
            'redirect_uri': self.get_redirect_uri(),
            'disconnect_url': self.get_disconnect_url()
        }

    def get_disconnect_url(self):
        if not self.authentication:
            return ""
        tpl = Template(self.authentication.disconnect_url)
        return tpl.render(Context({'workflow': self})).replace("//", "/")

    def generate_conf(self):
        """ Render the conf with Jinja template and self.to_template() method
        :return     The generated configuration as string, or raise
        """
        # The following var is only used by error, do not forget to adapt if needed
        template_name = JINJA_PATH + JINJA_TEMPLATE
        try:
            jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
            template = jinja2_env.get_template(JINJA_TEMPLATE)
            return template.render({'conf': self.to_template(),
                                    'nodes': Node.objects.exclude(name=settings.HOSTNAME),
                                    'global_config': Cluster.get_global_config().to_dict(fields=['public_token', 'portal_cookie_name'])})
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

    def get_base_filename(self):
        """ Return the workflow filename, without directory """
        return "workflow_{}.cfg".format(self.id)

    def get_filename(self):
        """  """
        return "{}/{}".format(HAPROXY_PATH, self.get_base_filename())

    # DEPRECATED DO NOT USE ANYMORE
    # use workflow.workflow.build_conf instead to generate/build conf on each node separately
    @DeprecationWarning
    def save_conf(self):
        """
        :return   A message of what has been done
        """
        if not self.authentication:
            return "No authentication activated, no need to write portal conf."

        params = [self.get_filename(), self.generate_conf(), WORKFLOW_OWNER, WORKFLOW_PERMS]
        try:
            api_res = Cluster.api_request("system.config.models.write_conf", config=params)
            if not api_res.get('status'):
                raise VultureSystemConfigError(". API request failure ", traceback=api_res.get('message'))
        except Exception:
            raise VultureSystemConfigError("API request failure.")

        return "Workflow configuration written."

    def get_redirect_uri(self):
        listener = None
        for l in self.frontend.listener_set.all().only('tls_profiles', 'port'):
            """ TLS priority """
            if l.tls_profiles.count() > 0:
                listener = l

        """ No TLS listener, get the first one """
        if not listener:
            listener = self.frontend.listener_set.first()

        port = listener.port

        if listener.tls_profiles.count() > 0:
            if port in ("443", 443):
                url = "https://" + str(self.fqdn) + str(self.public_dir)
            else:
                url = "https://" + str(self.fqdn) + ":" + str(port) + str(self.public_dir)
        else:
            if port in ("80", 80):
                url = "http://" + str(self.fqdn) + str(self.public_dir)
            else:
                url = "http://" + str(self.fqdn) + ":" + str(port) + str(self.public_dir)
        return url

    def get_and_validate_scope(self, claims, repo_attributes):
        user_scope = {}
        if self.authentication:
            user_scope = self.authentication.get_user_scope(claims, repo_attributes)
            if self.authentication_filter:
                if not self.authentication_filter.apply_rules_on_scope(user_scope):
                    logger.warning(f"scope '{user_scope}' could not be validated with filtering rules '{self.authentication_filter.name}'")
                    raise ACLError(f"Could not validate user scope against filtering rules '{self.authentication_filter.name}'")

        return user_scope
