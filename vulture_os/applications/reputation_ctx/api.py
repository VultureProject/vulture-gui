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
from django.utils.crypto import get_random_string
from django.views import View
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator

# Django project imports
from gui.decorators.apicall import api_need_key
from django.views.decorators.csrf import csrf_exempt
from gui.forms.form_utils import DivErrorList
from applications.reputation_ctx.form import ReputationContextForm
from applications.reputation_ctx.models import ReputationContext
from applications.reputation_ctx.views import reputation_ctx_delete, reputation_ctx_edit, reputation_ctx_download

# Required exceptions imports
from services.exceptions import ServiceError
from system.exceptions import VultureSystemError

# Extern modules imports
from datetime import datetime
from sys import exc_info
from traceback import format_exception

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@csrf_exempt
@require_http_methods(["POST"])
def reputation_ctx_download_test(request):
    """
    This is an API CALL

    :param request:
    :return:
    """
    post_body = request.POST.copy()
    post_body['name'] = get_random_string()  # Set random name to prevent duplicate name error in form
    form = ReputationContextForm(post_body, error_class=DivErrorList)
    if not form.is_valid():
        return JsonResponse({'status': False, 'error': "Some fields are not valid.",
                             'form_errors': form.errors})

    """ Try to download asked file """
    try:
        # Backends can not be used, so do not handle the HAProxy "not used" error by setting disabled=True
        db_reader = form.save(commit=False).download_mmdb()
        db_metadata = db_reader.metadata()
        db_reader.close()
        metadata_serialized = {
            'build_epoch': datetime.fromtimestamp(db_metadata.build_epoch).strftime("%Y-%m-%d %H:%M:%S"),
            'database_type': db_metadata.database_type,
            'description': db_metadata.description,
            'ip_version': db_metadata.ip_version,
            'languages': db_metadata.languages,
            'node_byte_size': db_metadata.node_byte_size,
            'node_count': db_metadata.node_count,
            'record_size': db_metadata.record_size,
            'search_tree_size': db_metadata.search_tree_size
        }
        return JsonResponse({'status': True, 'message': metadata_serialized})
    except (ServiceError, VultureSystemError) as e:
        logger.exception(e)
        return JsonResponse({'status': False, 'error': str(e), 'error_details': e.traceback})
    except Exception as e:
        return JsonResponse({'status': False, 'error': "Unknown error occurred: {}".format(str(e)),
                             'error_details': str.join('', format_exception(*exc_info()))})


@method_decorator(csrf_exempt, name="dispatch")
class ReputationContextAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            if object_id:
                obj = ReputationContext.objects.get(pk=object_id).to_dict()
            elif request.GET.get('name'):
                obj = ReputationContext.objects.get(name=request.GET.get('name')).to_dict()
            else:
                obj = [s.to_dict() for s in ReputationContext.objects.all()]

            return JsonResponse({
                'data': obj
            })

        except ReputationContext.DoesNotExist:
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
                return reputation_ctx_edit(request, None, api=True)

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
            return reputation_ctx_edit(request, object_id, api=True)

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
            return reputation_ctx_delete(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)


COMMAND_LIST = {
    'download': reputation_ctx_download,
}
