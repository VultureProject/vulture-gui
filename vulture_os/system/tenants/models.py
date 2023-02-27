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

from django.utils.translation import gettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models
from applications.reputation_ctx.models import ReputationContext

# Extern modules imports
from base64 import b64encode

# Logger configuration imports
import logging
logger = logging.getLogger('gui')


class Tenants(models.Model):
    """
    Tenants vulture Configuration class
    """
    name = models.TextField(default="ACME_Corporation", unique=True)
    chameleon_apikey = models.TextField(default="", blank=True)

    """ Use DjongoManager to use mongo_find() & Co """
    objects = models.DjongoManager()

    def __str__(self):
        return "Tenants config {}".format(self.name)

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "id" in fields:
            result['id'] = str(result['id'])
        return result

    def to_template(self):
        # Build CTI feed list associated to this tenant
        frontend_list = list()
        feed_list = set()
        for f in self.frontend_set.all().only("name"):
            frontend_list.append(f.name)
            for ctx in f.frontendreputationcontext_set.all().only("reputation_ctx"):
                try:
                    feed = ReputationContext.objects.get(id=ctx.reputation_ctx.id)
                    feed_list.add(feed.name)
                except Exception as e:
                    logger.error("Error when getting reputation context for tenant {}: {}".format(f.name, str(e)))
                    pass
        return {
            "id": str(self.id),
            "name": self.name,
            "frontends": frontend_list,
            "reputation_contexts": list(feed_list),
            "internal": self.config_set.all().count() > 0
        }

    class Meta:
        app_label = "system"

    def reload_frontends_conf(self):
        for frontend in self.frontend_set.filter(enabled=True, enable_logging=True):
            for node in frontend.get_nodes():
                node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.id)
