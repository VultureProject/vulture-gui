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

__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'OpenVPN API'

from services.openvpn import views as openvpn_view
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from gui.decorators.apicall import api_need_key
from services.openvpn.models import Openvpn
from django.http import JsonResponse
from django.conf import settings
from django.views import View
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@method_decorator(csrf_exempt, name="dispatch")
class OpenvpnAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            remote_server = request.GET.get('remote_server')
            if object_id:
                obj = Openvpn.objects.get(pk=object_id).to_dict()
            elif remote_server:
                obj = Openvpn.objects.get(remote_server=remote_server).to_dict()
            else:
                obj = [s.to_dict() for s in Openvpn.objects.all()]

            return JsonResponse({
                'data': obj
            })

        except Openvpn.DoesNotExist:
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
    def post(self, request, object_id=None, action=None):
        try:
            if not action:
                return openvpn_view.openvpn_edit(request, None, api=True)

            if action and not object_id:
                return JsonResponse({
                    'error': _('You must specify an ID')
                }, status=401)

            command_available = {
                'status': openvpn_view.openvpn_status,
                'start': openvpn_view.openvpn_start,
                'reload': openvpn_view.openvpn_reload,
                'stop': openvpn_view.openvpn_stop,
                'restart': openvpn_view.openvpn_restart,
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
            return openvpn_view.openvpn_edit(request, object_id, api=True)

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
        allowed_fields = ('remote_server', 'remote_port', 'tls_profile', 'proto')
        try:
            for key in request.JSON.keys():
                if key not in allowed_fields:
                    return JsonResponse({'error': _("Attribute not allowed : '{}'."
                                                    "Allowed attributes are {}".format(key, allowed_fields))})
            return openvpn_view.openvpn_edit(request, object_id, api=True, update=True)

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
            return openvpn_view.openvpn_delete(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)
