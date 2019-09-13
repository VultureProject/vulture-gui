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
__doc__ = 'Repositories\' mother class'


# Django system imports
from django.conf import settings
from django.contrib.auth import authenticate as django_authenticate
from django.utils.translation import ugettext as _
from djongo import models

# Django project imports

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class BaseRepository(models.Model):

    name = models.TextField(default="Authentication repository",
                            unique=True,
                            help_text=_("Name of the authentication repository"))

    subtype = models.TextField(default="")

    def __str__(self):
        return "{} ({})".format(self.name, self.subtype)

    def to_template(self):
        return {
            'id': str(self.pk),
            'name': self.name,
            'subtype': self.subtype
        }

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name', 'subtype']

    def authenticate(self, *args, **kwargs):
        if hasattr(self, "internalrepository"):
            return self.internalrepository.authenticate(*args, **kwargs)
        elif hasattr(self, "ldaprepository"):
            return self.ldaprepository.get_client().authenticate(*args, **kwargs)
        elif hasattr(self, "otprepository"):
            return self.otprepository.get_client().authenticate(*args, **kwargs)
        elif hasattr(self, "radiusrepository"):
            return self.radiusrepository.get_client().authenticate(*args, **kwargs)
        raise NotImplementedError("Client not implemented for this type of repository")


class InternalRepository(BaseRepository):

    def authenticate(self, *args, **kwargs):
        # FIXME : ACL group
        return django_authenticate(username=args[0], password=args[1])

    # Do NOT forget this on all BaseRepository subclasses
    def save(self, *args, **kwargs):
        self.subtype = "internal"
        super().save(*args, **kwargs)
