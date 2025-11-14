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
__doc__ = 'Openvpn model classes'

# Django system imports
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.forms.models import model_to_dict
from django.db import models

# Django project imports
from system.cluster.models import Node
from system.pki.models import TLSProfile

# Extern modules imports
from jinja2 import Environment, FileSystemLoader
from os.path import join as path_join
from services.exceptions import (ServiceJinjaError)
from system.exceptions import VultureSystemConfigError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

from toolkit.network.network import get_proxy


PROTO = (
    ('tcp', 'TCP'),
    #('udp', 'UDP'),
)

KEYEXCHANGE = (
    ('ikev2', 'IKE version 2'),
)


# Jinja template for frontends rendering
JINJA_PATH = path_join(settings.BASE_DIR, "services/openvpn/config/")
JINJA_TEMPLATE_OPENVPN = "client.conf"

CONF_PATH = path_join(settings.LOCALETC_PATH, "openvpn")

OPENVPN_OWNER = "root:vlt-conf"


class Openvpn(models.Model):
    node                = models.OneToOneField(Node, on_delete=models.CASCADE)
    enabled             = models.BooleanField(default=False)
    remote_server       = models.TextField(default="")
    remote_port         = models.PositiveIntegerField(default=443)
    tls_profile         = models.ForeignKey(to=TLSProfile, on_delete=models.CASCADE, help_text=_("TLS Profile to use."))
    proto               = models.TextField(choices=PROTO, default="tcp")
    status              = models.TextField(default="WAITING")
    tunnels_status      = models.JSONField(default={})

    def to_template(self):
        """ Dictionary used to create configuration file.

        :return: Dictionary of configuration parameters
        """
        return {'conf': self.to_html_template()}

    def to_dict(self, fields=None):
        """ Serialized version of object """
        result = model_to_dict(self, fields=fields)
        if not fields or "id" in fields:
            result['id'] = str(result['id'])
        if not fields or "node" in fields:
            result['node'] = self.node.to_dict()
        if not fields or "tls_profile" in fields:
            result['tls_profile'] = self.tls_profile.to_dict()
        return result


    def get_status(self):
        return {
            'node': self.node.to_dict(),
            'status': self.status,
            'tunnels_status': self.tunnels_status
        }

    def to_html_template(self):
        """ Dictionary used to render FORM

        :return     Dictionnary of configuration parameters
        """

        """ Retrieve optional proxy configuration """
        tmp = get_proxy(True)
        if tmp:
            proxy_configuration = "http-proxy-retry" + '\n'
            proxy_configuration += "http-proxy {} {}".format(tmp[0], tmp[1]) + '\n'
        else:
            proxy_configuration = ""

        """ And returns the attributes of the class """
        return {
            'id': str(self.id),
            'node': self.node.name,
            'remote_server': self.remote_server,
            'remote_port': self.remote_port,
            'proto': self.proto,
            'status': self.status,
            'tunnels_status': self.tunnels_status,
            'proxy_configuration': proxy_configuration,
            'ca': self.tls_profile.x509_certificate.get_base_filename() + ".chain",
            'cert': self.tls_profile.x509_certificate.get_base_filename() + ".crt",
            'key': self.tls_profile.x509_certificate.get_base_filename() + ".key"
        }


    def generate_conf(self):
        """ Render the conf with Jinja template and self.to_template() method 
        :return     The generated configuration as string, or raise
        """

        try:
            jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
            template_client = jinja2_env.get_template(JINJA_TEMPLATE_OPENVPN)
            conf = self.to_template()
            return {
                'template_client': template_client.render(conf)
            }

        # In ALL exceptions, associate an error message
        except Exception as e:
            # If there was an exception, raise a more general exception with the message and the traceback
            raise ServiceJinjaError("Openvpn config generation error: '{}'".format(str(e)), "openvpn")


    def save_conf(self):
        """ Write configuration on disk
        """
        conf = self.generate_conf()
        params = [path_join(CONF_PATH, 'openvpn_client.conf'), conf['template_client'], OPENVPN_OWNER, "644"]
        try:
            self.node.api_request('system.config.models.write_conf', config=params)
        except Exception:
            raise VultureSystemConfigError("on node '{}'.\nRequest failure.".format(self.node.name))


