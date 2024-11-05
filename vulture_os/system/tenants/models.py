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

from django.forms.models import model_to_dict
from djongo import models
from applications.reputation_ctx.models import ReputationContext
from django.utils.translation import gettext_lazy as _

# Extern modules imports

# Logger configuration imports
import logging
logger = logging.getLogger('gui')


class Tenants(models.Model):
    """
    Tenants vulture Configuration class
    """
    name = models.TextField(default="ACME_Corporation", unique=True)
    chameleon_apikey = models.TextField(default="", blank=True)
    additional_config = models.JSONField(
        default= dict,
        blank=True,
        help_text=_("Add a more flexible configuration for the tenant"),
        verbose_name=_("Custom tenant configuration")
    )

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
        # Test self.pk to prevent M2M errors when object isn't saved in DB
        if self.pk:
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
            # Test self.pk to prevent M2M errors when object isn't saved in DB
            "internal": self.config_set.all().count() > 0 if self.pk else False
        }

    class Meta:
        app_label = "system"

    def reload_frontends_conf(self):
        updated_nodes = set()
        # Test self.pk to prevent M2M errors when object isn't saved in DB
        if self.pk:
            for frontend in self.frontend_set.filter(enabled=True, enable_logging=True):
                for node in frontend.get_nodes():
                    updated_nodes.add(node)
                    node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.id)

        for node in updated_nodes:
            node.api_request("services.rsyslogd.rsyslog.restart_service")
