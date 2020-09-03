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
__doc__ = 'Dashboard API'


from django.views.decorators.csrf import csrf_exempt
from gui.decorators.apicall import api_need_key
from gui.models.monitor import Monitor
from system.cluster.models import Node
from django.http import JsonResponse
from django.conf import settings
import requests
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@csrf_exempt
@api_need_key('cluster_api_key')
def services_monitor(request):
    try:
        services = {}

        for node in Node.objects.all():
            tmp_mon = Monitor.objects.filter(
                node=node).order_by("-date").first()

            try:
                services[node.name] = tmp_mon.to_template()['services']
            except AttributeError:
                services = [node.name] = False

        return JsonResponse({
            'data': services,
            'status': True
        })

    except Exception as e:
        if settings.DEV_MODE:
            raise

        logger.error(e, exc_info=1)
        return JsonResponse({
            'status': False
        })

