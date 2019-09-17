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
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Response API toolkit functions'

# Django system imports
from django.http import JsonResponse
from django.urls import reverse

# Django project imports

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging
logger = logging.getLogger('authentication')


def build_response(id, module_url, command_list):
    result = {
        'id': str(id),
        'links': {
            'get': {
                'rel': 'self', 'type': 'GET',
                'href': reverse(module_url, kwargs={
                    'object_id': str(id)
                })
            },
            'put': {
                'rel': 'self', 'type': 'PUT',
                'href': reverse(module_url, kwargs={
                    'object_id': str(id)
                })
            },
            'delete': {
                'rel': 'self', 'type': 'DELETE',
                'href': reverse(module_url, kwargs={
                    'object_id': str(id)
                })
            }
        }
    }
    for command in command_list:
        result[command] = {
            'rel': 'self', 'type': "POST", 'name': command,
            'href': reverse(module_url, kwargs={
                'object_id': str(id), 'action': command,
            })
        }

    return JsonResponse(result, status=201)
