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
__author__ = "Kévin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Perimeter Configuration main models'

from django.utils.translation import ugettext_lazy as _
from djongo import models

# Django project imports
from applications.reputation_ctx.models import ReputationContext

# Required exceptions imports

# Extern modules imports
from base64 import b64encode

# Logger configuration imports
import logging
logger = logging.getLogger('gui')


class Tenants(models.Model):
    """
    Tenants vulture Configuration class
    """
    name = models.TextField(default="ACME Corporation", unique=True)
    predator_apikey = models.TextField(default="fdsqJr_45;..", blank=True)
    shodan_apikey = models.TextField(default="", blank=True)
    chameleon_apikey = models.TextField(default="", blank=True)

    """ Use DjongoManager to use mongo_find() & Co """
    objects = models.DjongoManager()

    def __str__(self):
        return "Tenants config {}".format(self.name)

    @property
    def encoded_predator_apikey(self):
        return b64encode(self.predator_apikey.encode('utf8')).decode('utf8')

    def to_dict(self):
        result = {
            'id': str(self.id),
            'name': self.name,
            'predator_apikey': self.predator_apikey,
            'shodan_apikey': self.shodan_apikey
        }

        return result

    def to_template(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "reputation_contexts": ",".join([r.name for r in ReputationContext.objects.filter(filename__contains=self.encoded_predator_apikey)]),
            'frontends': [f.name for f in self.frontend_set.all().only("name")],
            'internal': self.config_set.all().count() > 0
        }

    class Meta:
        app_label = "system"

    def reload_frontends_conf(self):
        for frontend in self.frontend_set.filter(enabled=True, enable_logging=True):
            for node in frontend.get_nodes():
                node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.id)
