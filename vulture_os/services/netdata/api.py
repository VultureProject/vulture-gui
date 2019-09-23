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
__doc__ = 'Netdata API'


# Django system imports
from django.conf import settings
from django.http import JsonResponse
from django.utils.translation import ugettext_lazy as _
from django.views import View

# Django project imports
from gui.decorators.apicall import api_need_key
from services.netdata.models import NetdataSettings
from services.netdata.views import COMMAND_LIST, netdata_edit
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

# Required exceptions imports

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@method_decorator(csrf_exempt, name="dispatch")
class NetdataAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request):
        try:
            obj = NetdataSettings.objects.get().to_dict()
            return JsonResponse({
                'data': obj
            })

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def post(self, request, action=None):
        try:
            if not action:
                return netdata_edit(request, api=True)

            if action not in list(COMMAND_LIST.keys()):
                return JsonResponse({
                    'error': _('Action not allowed')
                }, status=403)

            return COMMAND_LIST[action](request, api=True)

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
    def put(self, request):
        try:
            return netdata_edit(request, api=True)
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
    def patch(self, request):
        allowed_fields = ('history', 'backend_enabled', 'backend_type', 'backend_host_tags', 'backend_destination',
                          'backend_data_source', 'backend_prefix', 'backend_update_every', 'backend_buffer_on_failure',
                          'backend_timeout', 'backend_send_hosts_matching', 'backend_send_charts_matching',
                          'backend_send_names_or_ids')
        try:
            for key in request.JSON.keys():
                if key not in allowed_fields:
                    return JsonResponse({'error': _("Attribute not allowed : '{}'."
                                                    "Allowed attributes are {}".format(key, allowed_fields))})
            return netdata_edit(request, api=True, update=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            if settings.DEV_MODE:
                error = str(e)
            else:
                error = _("An error has occurred")

        return JsonResponse({
            'error': error
        }, status=500)
