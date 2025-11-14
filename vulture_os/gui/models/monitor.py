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
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Monitoring models'


from django.contrib.humanize.templatetags.humanize import naturaltime
from system.cluster.models import Node
from django.db import models


class ServiceStatus(models.Model):
    name = models.TextField()
    friendly_name = models.TextField()
    status = models.TextField()


class Monitor(models.Model):
    node = models.ForeignKey(Node, on_delete=models.CASCADE)
    date = models.DateTimeField()
    services = models.ManyToManyField(
        to=ServiceStatus,
        default=[]
    )

    class meta:
        unique_together = ("date", 'node')

    def to_template(self):
        tmp = {
            'date': self.date,
            'date_human': naturaltime(self.date),
            'services': []
        }

        for service in self.services.all():
            tmp['services'].append({
                'name': service.name,
                'friendly_name': service.friendly_name,
                'status': service.status
            })

        return tmp
