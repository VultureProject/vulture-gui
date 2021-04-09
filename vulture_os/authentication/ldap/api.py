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
__doc__ = 'LDAP API'

import logging
from django.views import View
from django.conf import settings
from django.http import JsonResponse
from authentication import ldap
from gui.decorators.apicall import api_need_key
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from authentication.ldap.models import LDAPRepository
from django.utils.translation import ugettext_lazy as _
from authentication.ldap.views import ldap_edit
from authentication.generic_delete import DeleteLDAPRepository
from authentication.ldap import tools

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')

@method_decorator(csrf_exempt, name="dispatch")
class LDAPApi(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            if object_id:
                ldap_repository = LDAPRepository.objects.get(pk=object_id)
            elif request.GET.get('name'):
                ldap_repository = LDAPRepository.objects.get(name=request.GET['name'])
            else:
                ldap_repos = [ld.to_dict() for ld in LDAPRepository.objects.all()]
                return JsonResponse({
                    "data": ldap_repos
                })

            return JsonResponse({
                "data": ldap_repository.to_dict()
            })

        except LDAPRepository.DoesNotExist:
            return JsonResponse({
                "error": _("Object does not exist")
            }, status=404)

    @api_need_key('cluster_api_key')
    def post(self, request):
        try:
            return ldap_edit(request, None, api=True)
        
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
            return ldap_edit(request, object_id, api=True)

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
            return DeleteLDAPRepository().post(request, object_id=object_id, confirm=True, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)
