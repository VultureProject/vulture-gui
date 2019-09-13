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
__email__ = ""
__doc__ = 'Settings View of Vulture OS'

from system.cluster.models import Node
from gui.models.monitor import Monitor
from django.http import JsonResponse
from django.shortcuts import render
from django.conf import settings
import logging.config

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('debug')


def dashboard_services(request):
    if request.is_ajax():
        try:
            monitor = {}
            for tmp_node in Node.objects.all():
                tmp_mon = Monitor.objects.filter(
                    node=tmp_node).order_by("-date").first()

                try:
                    monitor[tmp_node.name] = tmp_mon.to_template()
                except AttributeError:
                    monitor[tmp_node.name] = {
                        'date': '',
                        'services': []
                    }

            return JsonResponse({
                'monitor': monitor,
                'status': True
            })

        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.error(e, exc_info=1)
            return JsonResponse({
                'status': False
            })

    return render(request, 'dashboard_services.html', {
        'nodes': Node.objects.all()
    })
