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
__version__ = "3.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'OPENID API'

import logging
from django.views import View
from django.conf import settings
from django.http import JsonResponse
from gui.decorators.apicall import api_need_key
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.utils.translation import ugettext_lazy as _
from authentication.openid.views import edit as openid_edit
from authentication.openid.models import OpenIDRepository
from authentication.generic_delete import DeleteOpenIDRepository


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger("api")


@method_decorator(csrf_exempt, name="dispatch")
class OPENIDApi(View):
    @api_need_key("cluster_api_key")
    def get(self, request, object_id=None):
        try:
            fields = request.GET.getlist('fields') or None
            if object_id:
                open_id = OpenIDRepository.objects.get(pk=object_id).to_dict(fields=fields)
            elif request.GET.get('name'):
                open_id = OpenIDRepository.objects.get(name=request.GET.get("name")).to_dict(fields=fields)
            else:
                open_id = [obj.to_dict(fields=fields) for obj in OpenIDRepository.objects.all()]

            return JsonResponse({
                "data": open_id
            })
        except OpenIDRepository.DoesNotExist:
            return JsonResponse({
                "error": _("Object does not exist")
            }, status=404)


    @api_need_key("cluster_api_key")
    def post(self, request):
        try:
            return openid_edit(request, None, api=True)
        
        except Exception as e:
            logger.critical(e, exc_info=1)
            if settings.DEV_MODE:
                error = str(e)
            else:
                error = _("An error has occurred")

        return JsonResponse({
            'error': error
        }, status=500) 
    
    @api_need_key('cluster_api_key')
    def put(self, request, object_id):
        try:
            return openid_edit(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def delete(self, request, object_id):
        try:
            openid = OpenIDRepository.objects.get(pk=object_id)
            openid.delete()

            return JsonResponse({
                "status": True
            })
        
        except OpenIDRepository.DoesNotExist:
            return JsonResponse({
                "status": False,
                "error": _("Object not found")
            }, status=404)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)