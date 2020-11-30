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

__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'User Access Control model'

from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from djongo import models
import logging
import json

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


OPERATOR_CHOICES = (
    ("eq", _("Equal")),
    ("ne", _("Not equal")),
)


class AuthAccessControl(models.Model):
    enabled = models.BooleanField(default=True)

    name = models.TextField(verbose_name=_("Friendly name"), help_text=_("Friendly name"), unique=True)
    rules = models.ListField(default=[])

    def __str__(self):
        return f"Authentication ACL {self.name}"

    def to_dict(self):
        return {
            "id": str(self.pk),
            "name": self.name,
            "rules": self.rules,
            "enabled": self.enabled,
        }

    def to_template(self):
        return {
            "id": str(self.pk),
            "name": self.name,
            "enabled": self.enabled,
            "rules": json.dumps(self.rules)
        }