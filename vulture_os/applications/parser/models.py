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
__doc__ = 'FParser model classes'

# Django system imports
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from djongo import models

# Django project imports
from toolkit.log.lognormalizer import test_lognormalizer
from services.rsyslogd.rsyslog import RSYSLOG_PATH, RSYSLOG_OWNER, RSYSLOG_PERMS
from system.cluster.models import Cluster

# Extern modules imports
import json

# Required exceptions imports
from system.exceptions import VultureSystemConfigError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class Parser(models.Model):
    """ Model used to transform raw logs into parsed ECS Json format """
    """ Name of the parser, unique constraint """
    name = models.TextField(
        unique=True,
        default="Parser",
        verbose_name=_("Friendly name"),
        help_text=_("Custom name of the current object"),
    )
    """ Rulebase """
    rulebase = models.TextField(
        default="version=2\nrule=:%timestamp_app:float{\"format\": \"number\"}%",
        verbose_name=_("Rulebase"),
        help_text=_("Parser rules"),
    )
    to_test = models.TextField(
        default="1553103776.045449327",
        verbose_name=_("Lines to test"),
        help_text=_("Lines to apply te parser on")
    )
    tags = models.JSONField(
        default=[],
        blank=True,
        verbose_name=_("Tags"),
        help_text=_("Tags to set on this object for search")
    )

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def __str__(self):
        return "Parser '{}'".format(self.name)

    def to_dict(self):
        """ This method MUST be used in API instead of to_template() method
                to prevent no-serialization of sub-models 
        :return     A JSON object
        """
        result = {
            'id': str(self.id),
            'name': self.name,
            'rulebase': self.rulebase,
            'to_test': self.to_test,
            'tags': self.tags
        }
        return result

    def get_base_filename(self):
        return "parser_{}.rb".format(self.id or "tmp")

    def get_filename(self):
        return "{}/{}".format(RSYSLOG_PATH, self.get_base_filename())

    def test_conf(self):
        try:
            if test_lognormalizer(self.get_base_filename(), self.rulebase, self.to_test):
                return True
        except json.JSONDecodeError:
            return False
        return False

    def save_conf(self):
        params = [self.get_filename(), self.rulebase, RSYSLOG_OWNER, RSYSLOG_PERMS]
        try:
            Cluster.api_request('system.config.models.write_conf', config=params)
        except Exception as e:  # e used by VultureSystemConfigError
            logger.error(e, exc_info=1)
            raise VultureSystemConfigError("on cluster.\nRequest failure to write_conf()")

    def delete_conf(self):
        Cluster.api_request("system.config.models.delete_conf", self.get_filename())

    def to_template(self):
        return {
            "id": self.id,
            "name": self.name,
            "rulebase": self.rulebase,
            "tags": json.dumps(self.tags)
        }
