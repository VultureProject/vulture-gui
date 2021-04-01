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
__doc__ = 'Defender Policy API'

from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.views import View
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from gui.decorators.apicall import api_need_key
from darwin.defender_policy.models import DefenderPolicy
from darwin.defender_policy.views import defender_policy_edit

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@method_decorator(csrf_exempt, name="dispatch")
class DefenderPolicyAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            if object_id:
                obj = DefenderPolicy.objects.get(pk=object_id).to_dict()
            elif request.GET.get('name'):
                obj = DefenderPolicy.objects.get(name=request.GET.get('name')).to_dict()
            else:
                obj = [s.to_dict() for s in DefenderPolicy.objects.all()]

            return JsonResponse({
                'data': obj
            })
        
        except DefenderPolicy.DoesNotExist:
            return JsonResponse({
                'error': _('Object does not exist')
            }, status=404)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def post(self, request):
        try:
            return defender_policy_edit(request, None, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def put(self, request, object_id=None):
        try:
            return defender_policy_edit(request, object_id, api=True)
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
    def delete(self, request, object_id):
        try:
            defender_policy = DefenderPolicy.objects.get(pk=object_id)
            defender_policy.delete()

        except DefenderPolicy.DoesNotExist:
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
