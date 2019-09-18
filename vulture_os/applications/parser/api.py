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
from django.http import JsonResponse
from django.utils.translation import ugettext_lazy as _
from django.views import View
from django.views.decorators.http import require_http_methods

# Django project imports
from applications.parser.models import Parser
from applications.parser.views import COMMAND_LIST, parser_edit, parser_delete
from gui.decorators.apicall import api_need_key
from toolkit.log.lognormalizer import test_lognormalizer
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

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


@require_http_methods(["POST"])
def parser_test(request):
    """
    This is an API CALL

    :param request:
    :return:
    """
    filename = "test.rb"
    rulebase_content = request.POST.get('rulebase')

    to_parse = request.POST.get('to_test')
    try:
        res = test_lognormalizer(filename, rulebase_content, to_parse)
        return JsonResponse({'status': True, 'message': res})
    except (ServiceError, VultureSystemError) as e:
        logger.exception(e)
        return JsonResponse({'status': False, 'error': str(e), 'error_details': e.traceback})
    except Exception as e:
        logger.exception(e)
        return JsonResponse({'status': False, 'error': "Unknown error occured: {}".format(str(e)),
                             'error_details': str.join('', format_exception(*exc_info()))})


@method_decorator(csrf_exempt, name="dispatch")
class ParserAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            if object_id:
                try:
                    obj = Parser.objects.get(pk=object_id).to_dict()
                except Parser.DoesNotExist:
                    return JsonResponse({
                        'error': _('Object does not exist')
                    }, status=404)

            else:
                obj = [s.to_dict() for s in Parser.objects.all()]

            return JsonResponse({
                'data': obj
            })

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occured")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def post(self, request, object_id=None, action=None):
        try:
            if not action:
                return parser_edit(request, None, api=True)

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
                error = _("An error has occured")

        return JsonResponse({
            'error': error
        }, status=500)

    @api_need_key('cluster_api_key')
    def put(self, request, object_id):
        try:
            return parser_edit(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occured")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def delete(self, request, object_id):
        try:
            return parser_delete(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occured")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)
