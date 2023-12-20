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
__doc__ = 'Global config API'

from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.views import View
from system.config.models import Config
from gui.decorators.apicall import api_need_key
from django.http import JsonResponse
from system.config.views import config_edit, pf_whitelist_blacklist
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@method_decorator(csrf_exempt, name="dispatch")
class ConfigAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request):
        try:
            fields = request.GET.getlist('fields') or None
            obj = [s.to_dict(fields=fields) for s in Config.objects.all()]
            return JsonResponse({
                'data': obj
            })

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'status': False,
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def put(self, request, object_id):
        try:
            return config_edit(request, object_id, api=True)
        except Exception as e:
            logger.critical(e, exc_info=1)
            if settings.DEV_MODE:
                error = str(e)
            else:
                error = _("An error has occurred")

        return JsonResponse({
            'status': False,
            'error': error
        }, status=500)

    @api_need_key('cluster_api_key')
    def patch(self, request, object_id):
        allowed_fields = ('pf_ssh_restrict', 'pf_admin_restrict', 'pf_whitelist', 'pf_blacklist',
                          'cluster_api_key', 'ldap_repository', 'oauth2_header_name', 'portal_cookie_name',
                          'public_token', 'redis_password', 'branch', 'smtp_server', 'ssh_authorized_key', 'rsa_encryption_key',
                          'logs_ttl', 'internal_tenants')
        try:
            for key in request.JSON.keys():
                if key not in allowed_fields:
                    return JsonResponse({'error': _("Attribute not allowed : '{}'."
                                                    "Allowed attributes are {}".format(key, allowed_fields))},
                                                    status=400)
            return config_edit(request, object_id, api=True, update=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            if settings.DEV_MODE:
                error = str(e)
            else:
                error = _("An error has occurred")

        return JsonResponse({
            'status': False,
            'error': error
        }, status=500)

@method_decorator(csrf_exempt, name="dispatch")
class PfAPIv1(View):
    @api_need_key('cluster_api_key')
    def post(self, request, list_type=None):
        try:
            return pf_whitelist_blacklist(request, list_type)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'status': False,
                'error': error
            }, status=500)