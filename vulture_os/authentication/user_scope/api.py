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
__version__ = "3.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = "User's scopes API"

# Django system imports
from django.conf import settings
from django.http import JsonResponse
from django.utils.translation import ugettext_lazy as _
from django.views import View
from django.utils.decorators import method_decorator

# Django project imports
from gui.decorators.apicall import api_need_key
from django.views.decorators.csrf import csrf_exempt
from authentication.user_scope import views as user_scope_view
from authentication.user_scope.models import UserScope
from authentication.generic_delete import DeleteUserScope

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@method_decorator(csrf_exempt, name="dispatch")
class UserScopeApi(View):
    @api_need_key("cluster_api_key")
    def get(self, request, object_id=None):
        try:
            fields = request.GET.getlist('fields') or None
            if object_id:
                data = UserScope.objects.get(pk=object_id).to_dict(fields=fields)
            elif request.GET.get('name'):
                data = UserScope.objects.get(name=request.GET['name']).to_dict(fields=fields)
            else:
                data = [ua.to_dict(fields=fields) for ua in UserScope.objects.all()]

            return JsonResponse({
                "data": data
            })
        except UserScope.DoesNotExist:
            return JsonResponse({
                "error": _("Object does not exist")
            }, status=404)

    @api_need_key('cluster_api_key')
    def post(self, request):
        try:
            response = user_scope_view.user_scope_edit(request, None, api=True)
            return response

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
            return user_scope_view.user_scope_edit(request, object_id, api=True)

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
            return DeleteUserScope().post(request, object_id=object_id, confirm=True, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)
