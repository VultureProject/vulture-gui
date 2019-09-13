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
__doc__ = 'Apache service dedicated views'

# Django system imports
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest

# Django project imports
from gui.decorators.apicall import api_need_key
from services.apache.models import ApacheSettings
from system.cluster.models import Node

# Required exceptions imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


@api_need_key('cluster_api_key')
def reload(request):
    if not request.is_ajax():
        return HttpResponseBadRequest()

    error_nodes = {}
    for node in Node.objects.all():
        """ Send API request to reload apache service """
        api_res = node.api_request("services.apache.apache.reload_service")

        if not api_res.get('status'):
            error_nodes[node.name] = api_res.get('message')

    if not error_nodes:
        result = {'status': True, 'message': "Apache reload request sent."}
    else:
        result = {
            'status': False,
            'error': "API error on node(s): {}".format(','.join(error_nodes.keys())),
            'error_details': "\n".join(["Error on node {}\nDetails: \n{}".format(key, val)
                                        for key, val in error_nodes.items()])
        }

    return JsonResponse(result)
