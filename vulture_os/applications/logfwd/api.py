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
from django.core.exceptions import ObjectDoesNotExist
from django.utils.decorators import method_decorator
from django.http import JsonResponse
from django.utils.translation import ugettext_lazy as _
from django.views import View

# Django project imports
from applications.logfwd.models import LogOM
from applications.logfwd.views import COMMAND_LIST, logfwd_edit, logfwd_delete, LOGFWD_MODELS
from gui.decorators.apicall import api_need_key
from django.views.decorators.csrf import csrf_exempt

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@method_decorator(csrf_exempt, name="dispatch")
class LogOMAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, fw_type=None, object_id=None):
        try:
            name = request.GET.get('name')
            fields = request.GET.getlist('fields') or None
            if object_id:
                res = LogOM().select_log_om(object_id).to_dict(fields=fields)

            elif name:
                res = LogOM().select_log_om_by_name(name).to_dict(fields=fields)

            elif fw_type:
                try:
                    res = [logOM.to_dict(fields=fields) for logOM in LOGFWD_MODELS[fw_type].objects.all()]
                except KeyError:
                    return JsonResponse({
                        'error': _('Type does not exist')
                    }, status=404)

            else:
                res = [LogOM().select_log_om(logom.pk).to_dict(fields=fields) for logom in LogOM.objects.all().only('pk')]

            return JsonResponse({
                'data': res
            })

        except ObjectDoesNotExist:
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
    def post(self, request, fw_type=None, object_id=None, action=None):
        try:
            if not action and fw_type:
                return logfwd_edit(request, fw_type, None, api=True)

            elif not action and not fw_type:
                return JsonResponse({'error': _("You must specify a type if no action.")})

            elif action and not object_id:
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
    def put(self, request, fw_type=None, object_id=None):
        if not fw_type:
            return JsonResponse({'error': _("You must specify a type.")})
        if not object_id:
            return JsonResponse({'error': _("You must specify an id.")})

        try:
            return logfwd_edit(request, fw_type, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def delete(self, request, fw_type=None, object_id=None):
        if not fw_type:
            return JsonResponse({'error': _("You must specify a type.")})
        if not object_id:
            return JsonResponse({'error': _("You must specify an id.")})

        try:
            return logfwd_delete(request, fw_type, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)
