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
__doc__ = 'Frontends & Listeners model classes'

# Django system imports
from django.conf import settings
from djongo import models

# Django project imports
from system.cluster.models import Node

# Extern modules imports
from jinja2 import Environment, FileSystemLoader
from services.exceptions import ServiceJinjaError
from system.exceptions import VultureSystemConfigError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


TYPE = (
    ('tunnel', 'Tunnel'),
)

KEYEXCHANGE = (
    ('ikev2', 'IKE version 2'),
)

DPD = (
    ('none', 'None'),
    ('clear', 'Clear'),
    ('hold', 'Hold'),
    ('restart', 'Restart'),
)

AUTHBY = (
    ('secret', 'PSK Authentication'),
)

# Jinja template for frontends rendering
JINJA_PATH = "/home/vlt-os/vulture_os/services/strongswan/config/"
JINJA_TEMPLATE_IPSEC = "ipsec.conf"
JINJA_TEMPLATE_SECRETS = "ipsec.secrets"
JINJA_TEMPLATE_STRONGSWAN = "strongswan.conf"

CONF_PATH = "/usr/local/etc/"

STRONGSWAN_OWNER = "root:wheel"


class Strongswan(models.Model):
    node = models.OneToOneField(Node, on_delete=models.CASCADE)
    enabled = models.BooleanField(default=False)
    ipsec_type = models.TextField(choices=TYPE, default="tunnel")
    ipsec_keyexchange = models.TextField(choices=KEYEXCHANGE, default="ikev2")
    ipsec_authby = models.TextField(choices=AUTHBY, default="secret")
    ipsec_psk = models.TextField(default="V3ryStr0ngP@ssphr@se")
    ipsec_fragmentation = models.BooleanField(default=True)
    ipsec_forceencaps = models.BooleanField(default=False)
    ipsec_ike = models.TextField(default="aes256-sha512-modp8192")
    ipsec_esp = models.TextField(default="aes256-sha512-modp8192")
    ipsec_dpdaction = models.TextField(choices=DPD, default="restart")
    ipsec_dpddelay = models.TextField(default="35s")
    ipsec_rekey = models.BooleanField(default=True)
    ipsec_ikelifetime = models.TextField(default="3h")
    ipsec_keylife = models.TextField(default="1h")
    ipsec_right = models.TextField(default="")
    ipsec_leftsubnet = models.TextField(default="")
    ipsec_leftid = models.TextField(default="")
    ipsec_rightsubnet = models.TextField(default="")
    status = models.TextField(default="WAITING")
    statusall = models.TextField(default="")
    tunnels_status = models.JSONField(default={})
    tunnels_up = models.PositiveIntegerField(default=0)
    tunnels_connecting = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f"Ipsec configuration"

    def to_template(self):
        """ Dictionary used to create configuration file.

        :return: Dictionary of configuration parameters
        """
        return {'conf': self.to_html_template()}

    def to_dict(self):
        """ Serialized version of object """
        return {
            'id': str(self.id),
            'node': self.node.to_dict(),
            'enabled': self.enabled,
            'status': self.status,
            'statusall': self.statusall,
            'ipsec_type': self.ipsec_type,
            'ipsec_keyexchange': self.ipsec_keyexchange,
            'ipsec_authby': self.ipsec_authby,
            'ipsec_psk': self.ipsec_psk,
            'ipsec_fragmentation': self.ipsec_fragmentation,
            'ipsec_forceencaps': self.ipsec_forceencaps,
            'ipsec_ike': self.ipsec_ike,
            'ipsec_esp': self.ipsec_esp,
            'ipsec_dpdaction': self.ipsec_dpdaction,
            'ipsec_dpddelay': self.ipsec_dpddelay,
            'ipsec_rekey': self.ipsec_rekey,
            'ipsec_ikelifetime': self.ipsec_ikelifetime,
            'ipsec_keylife': self.ipsec_keylife,
            'ipsec_right': self.ipsec_right,
            'ipsec_leftsubnet': self.ipsec_leftsubnet,
            'ipsec_leftid': self.ipsec_leftid,
            'ipsec_rightsubnet': self.ipsec_rightsubnet
        }

    def get_status(self):
        return {
            'node': self.node.to_dict(),
            'status': self.status,
            'statusall': self.statusall,
            'tunnels_status': self.tunnels_status,
            'tunnels_up': self.tunnels_up,
            'tunnels_connecting': self.tunnels_connecting
        }

    def to_html_template(self):
        """ Dictionary used to render FORM

        :return     Dictionnary of configuration parameters
        """

        """ And returns the attributes of the class """
        return {
            'id': str(self.id),
            'node': self.node.name,
            'status': self.status,
            'statusall': self.statusall,
            'ipsec_type': self.ipsec_type,
            'ipsec_keyexchange': self.ipsec_keyexchange,
            'ipsec_authby': self.ipsec_authby,
            'ipsec_psk': self.ipsec_psk,
            'ipsec_fragmentation': self.ipsec_fragmentation,
            'ipsec_forceencaps': self.ipsec_forceencaps,
            'ipsec_ike': self.ipsec_ike,
            'ipsec_esp': self.ipsec_esp,
            'ipsec_dpdaction': self.ipsec_dpdaction,
            'ipsec_dpddelay': self.ipsec_dpddelay,
            'ipsec_rekey': self.ipsec_rekey,
            'ipsec_ikelifetime': self.ipsec_ikelifetime,
            'ipsec_keylife': self.ipsec_keylife,
            'ipsec_right': self.ipsec_right,
            'ipsec_leftsubnet': self.ipsec_leftsubnet,
            'ipsec_leftid': self.ipsec_leftid,
            'ipsec_rightsubnet': self.ipsec_rightsubnet,
            'tunnels_status': self.tunnels_status,
            'tunnels_up': self.tunnels_up,
            'tunnels_connecting': self.tunnels_connecting,
        }

    def generate_conf(self):
        """ Render the conf with Jinja template and self.to_template() method 
        :return     The generated configuration as string, or raise
        """

        try:
            jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
            template_ipsec = jinja2_env.get_template(JINJA_TEMPLATE_IPSEC)
            template_secrets = jinja2_env.get_template(JINJA_TEMPLATE_SECRETS)
            template_strongswan = jinja2_env.get_template(JINJA_TEMPLATE_STRONGSWAN)

            conf = self.to_template()

            return {
                'template_ipsec': template_ipsec.render(conf),
                'template_secrets': template_secrets.render(conf),
                'template_strongswan': template_strongswan.render(conf)
            }

        # In ALL exceptions, associate an error message
        except Exception as e:
            # If there was an exception, raise a more general exception with the message and the traceback
            raise ServiceJinjaError("Strongswan config generation error: '{}'".format(str(e)), "strongswan")

    def save_conf(self):
        """ Write configuration on disk
        """

        conf = self.generate_conf()

        params_ipsec = ['/usr/local/etc/ipsec.conf', conf['template_ipsec'], STRONGSWAN_OWNER, "644"]
        params_secrets = ['/usr/local/etc/ipsec.secrets', conf['template_secrets'], STRONGSWAN_OWNER, "600"]
        params_strongswan = ['/usr/local/etc/strongswan.conf', conf['template_strongswan'], STRONGSWAN_OWNER, "644"]

        for params in (params_ipsec, params_secrets, params_strongswan):
            try:
                self.node.api_request('system.config.models.write_conf', config=params)
            except Exception as e:
                raise VultureSystemConfigError("on node '{}'.\nRequest failure.".format(self.node.name))
