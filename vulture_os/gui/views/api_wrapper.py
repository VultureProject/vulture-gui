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

__author__ = "Jérémie Jourdin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "support@vultureproject.org"
__doc__ = ''


from django.http import JsonResponse, HttpResponseForbidden
from django.utils.module_loading import import_string
from django.conf import settings
from django import views
import logging.config

from gui.decorators.apicall import api_need_key


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

class ApiWrapperGet(views.View):
    @api_need_key('cluster_api_key')
    def get(self, request, objclass, object_id=None):
        """
        API WRAPPER arround all project's objects
        This is used by CI tools to interact with VultureOS in an automated WAY

        All objects are available, only via GET method. This allow to fetch objects from Vulture's database

        :param request: Django request
        :param view_path: The Django object to retrieve from database
        :param object_id: An optional objectID. If None, we return all objects from database
        :return: A JSON serialized list of objects
        """

        try:
            my_object = import_string(objclass)
        except ImportError:
            return JsonResponse({'status': False, 'message': 'ObjectClass does not exist'}, status=404)
        except Exception as e:
            logger.error("API Wrapper::api_wrapper_get: {}".format(e))
            return JsonResponse({'status': False, 'message': 'API call failure: {}'.format(e)}, status=500)


        if object_id:
            try:
                return JsonResponse(my_object.objects.get(pk=object_id).to_template())
            except Exception as e:
                logger.error("API Wrapper::api_wrapper_get: {}".format(e))
                return JsonResponse({'status': False, 'message': 'API call failure: {}'.format(e)}, status=500)
        else:
            try:
                res = list()
                for obj in my_object.objects.all():
                    res.append(obj.to_template())
                return JsonResponse(res, safe=False)
            except Exception as e:
                logger.error("API Wrapper::api_wrapper_get: {}".format(e))
                return JsonResponse({'status': False, 'message': 'API call failure: {}'.format(e)}, status=500)

    def post(self, request):
        return HttpResponseForbidden()