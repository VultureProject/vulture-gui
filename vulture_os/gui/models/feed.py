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
__doc__ = 'Model for reputation / ipsets databases'

from djongo import models


DATABASES_PATH = "/var/db/darwin/"
DATABASES_OWNER = "vlt-os:vlt-conf"
DATABASES_PERMS = "644"


class Feed(models.Model):
    filename = models.FilePathField(unique=True, path=DATABASES_PATH)
    label = models.TextField()
    description = models.TextField()
    last_update = models.DateTimeField()
    nb_netset = models.IntegerField()
    nb_unique = models.IntegerField()
    type = models.TextField()

    """ Use DjongoManager to use mongo_find() & Co """
    objects = models.DjongoManager()

    def to_template(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'label': self.label,
            'description': self.description,
            'last_update': self.last_update,
            'nb_netset': self.nb_netset,
            'nb_unique': self.nb_unique,
            'type': self.type
        }

    def __str__(self):
        return self.label

    @staticmethod
    def str_attrs():
        return ['label']

    @property
    def absolute_filename(self):
        return DATABASES_PATH + self.filename
