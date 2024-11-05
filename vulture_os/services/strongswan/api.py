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
__doc__ = 'Strongswan API'

from services.strongswan import views as strongswan_view
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from services.strongswan.models import Strongswan
from gui.decorators.apicall import api_need_key
from django.http import JsonResponse
from django.conf import settings
from django.views import View
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@method_decorator(csrf_exempt, name="dispatch")
class StrongswanAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        node_id = request.GET.get("node")
        try:
            fields = request.GET.getlist('fields') or None
            if object_id:
                try:
                    obj = Strongswan.objects.get(pk=object_id).to_dict(fields=fields)
                except Strongswan.DoesNotExist:
                    return JsonResponse({
                        'error': _('Object does not exist')
                    }, status=404)
            elif node_id:
                obj = Strongswan.objects.get(node__pk=node_id).to_dict(fields=fields)
            else:
                obj = [s.to_dict(fields=fields) for s in Strongswan.objects.all()]

            return JsonResponse({
                'data': obj
            })

        except Strongswan.DoesNotExist:
            return JsonResponse({
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

    @api_need_key('cluster_api_key')
    def post(self, request, object_id=None, action=None):
        try:
            if not action:
                return strongswan_view.strongswan_edit(request, None, api=True)

            if action and not object_id:
                return JsonResponse({
                    'error': _('You must specify an ID')
                }, status=401)

            command_available = {
                'status': strongswan_view.strongswan_status,
                'start': strongswan_view.strongswan_start,
                'reload': strongswan_view.strongswan_reload,
                'stop': strongswan_view.strongswan_stop,
                'restart': strongswan_view.strongswan_restart,
            }

            if action not in list(command_available.keys()):
                return JsonResponse({
                    'error': _('Action not allowed')
                }, status=403)

            return command_available[action](request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

        if settings.DEV_MODE:
            error = str(e)

        return JsonResponse({
            'error': error
        }, status=500)

    @api_need_key('cluster_api_key')
    def put(self, request, object_id):
        try:
            return strongswan_view.strongswan_edit(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def patch(self, request, object_id):
        allowed_fields = ('ipsec_type', 'ipsec_keyexchange', 'ipsec_authby', 'ipsec_psk', 'ipsec_fragmentation',
                          'ipsec_forceencaps', 'ipsec_ike', 'ipsec_esp', 'ipsec_dpdaction', 'ipsec_dpddelay',
                          'ipsec_rekey', 'ipsec_ikelifetime', 'ipsec_keylife', 'ipsec_right', 'ipsec_leftsubnet',
                          'ipsec_leftid', 'ipsec_rightsubnet')

        try:
            for key in request.JSON.keys():
                if key not in allowed_fields:
                    return JsonResponse({'error': _("Attribute not allowed : '{}'."
                                                    "Allowed attributes are {}".format(key, allowed_fields))})
            return strongswan_view.strongswan_edit(request, object_id, api=True, update=True)

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
            return strongswan_view.strongswan_delete(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)
