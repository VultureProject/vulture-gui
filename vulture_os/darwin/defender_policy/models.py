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
__doc__ = 'Darwin model'

# Django system imports
from django.conf import settings
from django.forms import model_to_dict
from djongo import models
from darwin.log_viewer.models import DefenderRuleset
from services.haproxy.haproxy import HAPROXY_OWNER, HAPROXY_PATH, HAPROXY_PERMS
from system.config.models import write_conf
from system.exceptions import VultureSystemConfigError

# Extern modules imports
from jinja2 import Environment, FileSystemLoader

# Required exceptions imports
from services.exceptions import ServiceJinjaError
from jinja2.exceptions import (TemplateAssertionError, TemplateNotFound, TemplatesNotFound, TemplateRuntimeError,
                               TemplateSyntaxError, UndefinedError)


JINJA_PATH = "/home/vlt-os/vulture_os/darwin/log_viewer/config/"
JINJA_SPOE_TEMPLATE = "haproxy_spoe_defender.conf"
JINJA_BACKEND_TEMPLATE = "haproxy_backend_defender.conf"
JINJA_TEMPLATE = "defender.conf"

DEFENDER_PATH = "/usr/local/etc/defender.d"
DEFENDER_OWNER = "vlt-os:vlt-web"
DEFENDER_PERMS = "644"

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

SOCKETS_PATH = "/var/sockets/darwin"
FILTERS_PATH = "/home/darwin/filters"
CONF_PATH = "/home/darwin/conf/"
TEMPLATE_OWNER = "darwin:vlt-web"
TEMPLATE_PERMS = "644"


class DefenderPolicy(models.Model):
    name = models.TextField(unique=True, default="Default defender policy")
    defender_ruleset = models.ForeignKey(DefenderRuleset, null=True, on_delete=models.PROTECT)
    request_body_limit = models.PositiveIntegerField(default=8388608)
    enable_libinjection_sql = models.BooleanField(default=True)
    enable_libinjection_xss = models.BooleanField(default=True)

    def to_dict(self):
        return model_to_dict(self)

    def to_template(self):
        """  returns the attributes of the class """
        return {
            'id': str(self.id),
            'name': self.name,
            'request_body_limit': self.request_body_limit,
            'enable_libinjection_sql': self.enable_libinjection_sql,
            'enable_libinjection_xss': self.enable_libinjection_xss,
        }

    def to_html_template(self):
        """ Returns needed attributes for html rendering """
        return {
            'id': str(self.id),
            'name': self.name,
            'request_body_limit': self.request_body_limit,
            'enable_libinjection_sql': self.enable_libinjection_sql,
            'enable_libinjection_xss': self.enable_libinjection_xss,
        }

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def __str__(self):
        return self.name

    @property
    def decision_filter(self):
        return "decision_{}".format(self.id)

    def get_base_filename(self):
        """ return base filename (without path) for ModDefender configuration file """
        return "defender_{}.conf".format(self.id)

    def get_spoe_base_filename(self):
        """ return base filename (without path) for SPOE configuration file """
        return "spoe_defender_{}.txt".format(self.id)

    def get_backend_base_filename(self):
        """ return base filename (without path) for SPOE backend configuration file """
        return "backend_defender_{}.cfg".format(self.id)

    def get_filename(self):
        """ return full filename (including path) for ModDefender configuration file """
        return "{}/{}".format(DEFENDER_PATH, self.get_base_filename())

    def get_spoe_filename(self):
        """ Return full filename (including path) of SPOE configuration file """
        return "{}/{}".format(HAPROXY_PATH, self.get_spoe_base_filename())

    def get_backend_filename(self):
        """ Return full filename (including path) of SPOE backend configuration file """
        return "{}/{}".format(HAPROXY_PATH, self.get_backend_base_filename())

    def generate_defender_conf(self):
        logger.info("generate_defender_conf")
        try:
            jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
            template = jinja2_env.get_template(JINJA_TEMPLATE)

            ruleset = None

            if self.defender_ruleset:
                ruleset = self.defender_ruleset.to_dict()

            return template.render({'ruleset': ruleset, 'policy': self.to_template()})
        except (TemplateNotFound, TemplatesNotFound):
            raise ServiceJinjaError("The following file cannot be found : '{}'".format(JINJA_TEMPLATE), "haproxy")
        except (TemplateAssertionError, TemplateRuntimeError):
            raise ServiceJinjaError("Unknown error in template generation: {}".format(JINJA_TEMPLATE), "haproxy")
        except UndefinedError:
            raise ServiceJinjaError("A variable is undefined while trying to render the following template: "
                                    "{}".format(JINJA_TEMPLATE), "haproxy")
        except TemplateSyntaxError:
            raise ServiceJinjaError("Syntax error in the template: '{}'".format(JINJA_TEMPLATE), "haproxy")

    def generate_haproxy_spoe_conf(self):
        logger.info("generate_haproxy_spoe_conf")
        try:
            jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
            template_spoe = jinja2_env.get_template(JINJA_SPOE_TEMPLATE)
            workflows = set()
            for w in self.workflow_set.all():
                workflows.add(w)
            return template_spoe.render({'id': self.id, 'workflows': workflows})
        except (TemplateNotFound, TemplatesNotFound):
            raise ServiceJinjaError("The following file cannot be found : '{}'".format(JINJA_SPOE_TEMPLATE), "haproxy")
        except (TemplateAssertionError, TemplateRuntimeError):
            raise ServiceJinjaError("Unknown error in template generation: {}".format(JINJA_SPOE_TEMPLATE), "haproxy")
        except UndefinedError:
            raise ServiceJinjaError("A variable is undefined while trying to render the following template: "
                                          "{}".format(JINJA_SPOE_TEMPLATE), "haproxy")
        except TemplateSyntaxError:
            raise ServiceJinjaError("Syntax error in the template: '{}'".format(JINJA_SPOE_TEMPLATE), "haproxy")

    def generate_haproxy_backend_conf(self):
        logger.info("generate_haproxy_backend_conf")
        try:
            jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
            template_backend = jinja2_env.get_template(JINJA_BACKEND_TEMPLATE)
            return template_backend.render({'id': self.id})
        except (TemplateNotFound, TemplatesNotFound):
            raise ServiceJinjaError("The following file cannot be found : '{}'".format(JINJA_BACKEND_TEMPLATE), "haproxy")
        except (TemplateAssertionError, TemplateRuntimeError):
            raise ServiceJinjaError("Unknown error in template generation: {}".format(JINJA_BACKEND_TEMPLATE), "haproxy")
        except UndefinedError:
            raise ServiceJinjaError("A variable is undefined while trying to render the following template: "
                                          "{}".format(JINJA_BACKEND_TEMPLATE), "haproxy")
        except TemplateSyntaxError:
            raise ServiceJinjaError("Syntax error in the template: '{}'".format(JINJA_BACKEND_TEMPLATE), "haproxy")

    def write_defender_conf(self):
        logger.info("write_defender_conf")
        new_conf = self.generate_defender_conf()

        if not new_conf:
            return False

        filename = self.get_filename()

        try:
            with open(filename, 'r') as conf_file:
                current_conf = conf_file.read()
        except Exception as error:
            logger.warning(error)
            current_conf = None

        # If we don't have any current configuration, or if our new configuration differs
        if current_conf is None or new_conf != current_conf:
            try:
                write_conf(logger, [filename, new_conf, DEFENDER_OWNER, DEFENDER_PERMS])
                return True
            except Exception as e:
                raise VultureSystemConfigError(
                    "log viewer: error while writing configuration for DefenderPolicy"
                )

        return False

    def write_spoe_conf(self):
        logger.info("write_spoe_conf")
        new_conf = self.generate_haproxy_spoe_conf()

        if not new_conf:
            return False

        filename = self.get_spoe_filename()

        try:
            with open(filename, 'r') as conf_file:
                current_conf = conf_file.read()
        except Exception as error:
            logger.warning(error)
            current_conf = None

        # If we don't have any current configuration, or if our new configuration differs
        if current_conf is None or new_conf != current_conf:
            try:
                write_conf(logger, [filename, new_conf, HAPROXY_OWNER, HAPROXY_PERMS])
                return True
            except Exception as e:
                raise VultureSystemConfigError(
                    "log viewer: error while writing haproxy configuration (SPOE) for DefenderPolicy"
                )

        return False

    def write_backend_conf(self):
        logger.info("write_backend_conf")
        new_conf = self.generate_haproxy_backend_conf()

        if not new_conf:
            return False

        filename = self.get_backend_filename()

        try:
            with open(filename, 'r') as conf_file:
                current_conf = conf_file.read()
        except Exception as error:
            logger.warning(error)
            current_conf = None

        # If we don't have any current configuration, or if our new configuration differs
        if current_conf is None or new_conf != current_conf:
            try:
                write_conf(logger, [filename, new_conf, HAPROXY_OWNER, HAPROXY_PERMS])
                return True
            except Exception as e:
                raise VultureSystemConfigError(
                    "log viewer: error while writing haproxy configuration (backend) for DefenderPolicy"
                )

        return False
