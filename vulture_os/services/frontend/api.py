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
__doc__ = 'Frontends API'


# Django system imports
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.utils.translation import ugettext_lazy as _
from django.views import View
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.db.models import Q

# Django project imports
from gui.decorators.apicall import api_need_key
from services.frontend.models import Frontend
from services.frontend.views import frontend_delete, frontend_edit, COMMAND_LIST
from services.haproxy.haproxy import test_haproxy_conf
from django.views.decorators.csrf import csrf_exempt

# Required exceptions imports
from services.exceptions import ServiceError
from system.exceptions import VultureSystemError

# Extern modules imports
from sys import exc_info
from traceback import format_exception

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@csrf_exempt
@api_need_key('cluster_api_key')
@require_http_methods(["POST"])
def frontend_test_conf(request):
    """
    This is an API CALL

    :param request:
    :return:
    """

    try:
        conf = request.POST['conf']
        filename = request.POST['filename']
        disabled = request.POST['disabled']
        assert conf and filename
    except Exception as e:
        logger.exception(e)
        return HttpResponseBadRequest()

    if '/' in filename:
        logger.error("API::Frontend_test_conf: '/' in filename, not correct.")
        return HttpResponseForbidden("Injection detected in filename.")

    """ test_haproxy conf take conf and filename (without dir) as parameter """
    try:
        result = test_haproxy_conf(filename, conf, disabled=disabled)
        return JsonResponse({'status': True, 'message': result})
    except (ServiceError, VultureSystemError) as e:
        logger.exception(e)
        return JsonResponse({'status': False, 'error': str(e), 'error_details': e.traceback})
    except Exception as e:
        return JsonResponse({'status': False, 'error': "Unknown error occurred: {}".format(str(e)),
                             'error_details': str.join('', format_exception(*exc_info()))})


@method_decorator(csrf_exempt, name="dispatch")
class FrontendAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            name = request.GET.get('name')
            fields = request.GET.getlist('fields') or None
            mode = request.GET.getlist('mode') or None
            enabled = request.GET.get('enabled') or None

            filter= Q()
            if mode:
                filter.add(Q(mode__in=mode), Q.AND)
            if enabled:
                filter.add(Q(enabled__exact= True if enabled == "true" else False), Q.AND)

            if object_id:
                res = Frontend.objects.get(pk=object_id).to_dict(fields=fields)

            elif name:
                res = Frontend.objects.get(name=name).to_dict(fields=fields)

            elif len(filter) > 0:
                res = [f.to_dict(fields=fields) for f in Frontend.objects.filter(filter)]

            else:
                res = [s.to_dict(fields=fields) for s in Frontend.objects.all()]

            return JsonResponse({
                'status': True,
                'data': res
            })

        except Frontend.DoesNotExist:
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
                return frontend_edit(request, None, api=True)

            if action and not object_id:
                return JsonResponse({
                    'error': _('You must specify an ID')
                }, status=401)

            if action not in list(COMMAND_LIST.keys()):
                return JsonResponse({
                    'error': _('Action not allowed')
                }, status=403)

            return COMMAND_LIST[action](request, object_id, api=True)

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
            return frontend_edit(request, object_id, api=True)

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
            return frontend_delete(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)
