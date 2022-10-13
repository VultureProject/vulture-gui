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
__doc__ = 'User portal API'


# Django system imports
from django.conf import settings
from django.http import JsonResponse
from django.utils.translation import ugettext_lazy as _
from django.views import View
from django.utils.decorators import method_decorator

# Django project imports
from gui.decorators.apicall import api_need_key
from django.views.decorators.csrf import csrf_exempt
from authentication.user_portal import views as user_portal_view
from authentication.user_portal.models import UserAuthentication
from authentication.generic_delete import DeleteUserAuthentication

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')

def write_templates(node_logger, portal_id):
    """  """
    portal = UserAuthentication.objects.get(pk=portal_id)
    return portal.write_login_template()


@method_decorator(csrf_exempt, name="dispatch")
class UserPortalApi(View):
    @api_need_key("cluster_api_key")
    def get(self, request, object_id=None):
        try:
            fields = request.GET.getlist('fields') or None
            enable_external = True if request.GET.get('enable_external') == "true" else False

            if object_id:
                data = UserAuthentication.objects.get(pk=object_id).to_dict(fields=fields)
            elif request.GET.get('name'):
                data = UserAuthentication.objects.get(name=request.GET['name']).to_dict(fields=fields)
            elif enable_external:
                data = [a.to_dict(fields=fields) for a in UserAuthentication.objects.filter(enable_external=enable_external)]
            else:
                data = [ua.to_dict(fields=fields) for ua in UserAuthentication.objects.all()]

            return JsonResponse({
                'status': True,
                "data": data
            })
        except UserAuthentication.DoesNotExist:
            return JsonResponse({
                "error": _("Object does not exist")
            }, status=404)

    @api_need_key('cluster_api_key')
    def post(self, request):
        try:
            response = user_portal_view.user_authentication_edit(request, None, api=True)
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
            return user_portal_view.user_authentication_edit(request, object_id, api=True)

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
            return DeleteUserAuthentication().post(request, object_id=object_id, confirm=True, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)
