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
__doc__ = 'PKI main models'


from django.conf import settings
from djongo import models

from system.cluster.models import Node
from system.exceptions import VultureSystemConfigError

import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

class ZFS(models.Model):

    """ Representation of ZFS dataset """
    node = models.ForeignKey(to=Node, on_delete=models.CASCADE)
    name = models.TextField()
    used = models.TextField()
    avail = models.TextField()
    refer = models.TextField()
    mount = models.TextField()

    @property
    def type(self):
        if self.mount == "-":
            return "snapshot"
        else:
            return "dataset"

    def to_template(self):
        """ Dictionary used to create configuration file related to the node
        :return     Dictionnary of configuration parameters
        """
        conf = {
            'id': str(self.id),
            'node': self.node.name,
            'name': self.name,
            'used': self.used,
            'avail': self.avail,
            'refer': self.refer,
            'mount': self.mount,
            'type': self.type
        }

        return conf

    def create_snapshot(self):
        try:
            self.node.api_request('system.zfs.zfs.create_snapshot', config=self.name)
        except Exception as e:
            raise VultureSystemConfigError("on node '{}'.\nRequest failure.".format(self.node.name))

    def restore_snapshot(self):
        try:
            self.node.api_request('system.zfs.zfs.restore_snapshot', config=self.name)
        except Exception as e:
            raise VultureSystemConfigError("on node '{}'.\nRequest failure.".format(self.node.name))

    def delete_snapshot(self):
        try:
            self.node.api_request('system.zfs.zfs.delete_snapshot', config=self.id)
        except Exception as e:
            raise VultureSystemConfigError("on node '{}'.\nRequest failure.".format(self.node.name))

