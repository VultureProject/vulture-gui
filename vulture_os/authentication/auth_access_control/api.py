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
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Authentication ACL API'

from authentication.auth_access_control.form import AuthAccessControlRuleForm
from authentication.auth_access_control.form import AuthAccessControlForm
from authentication.auth_access_control.models import AuthAccessControl
from django.views.decorators.http import require_http_methods
from django.utils.translation import ugettext_lazy as _
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.utils.crypto import get_random_string
from gui.decorators.apicall import api_need_key
from django.http import JsonResponse
from django.conf import settings
from django.views import View
import logging


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


def save_access_control(data, instance):
    form = AuthAccessControlForm(data, instance=instance)
    rules = data.get('or_lines', [])
    
    if form.is_valid():
        ac = form.save(commit=False)

        for rule in rules:
            for line in rule['lines']:
                rule_form = AuthAccessControlRuleForm(line)
                if not rule_form.is_valid():
                    return JsonResponse({
                        "error": rule_form.errors
                    }, status=404)
        
        ac.rules = rules
        ac.save()

    return JsonResponse({
        "message": _("Authentication ACL saved")
    })            


@method_decorator(csrf_exempt, name="dispatch")
class AuthenticationAccessControlAPIv1(View):
    @api_need_key("cluster_api_key")
    def get(self, request):
        try:
            object_id = request.GET.get('object_id')
            name = request.GET.get('name')

            if object_id:
                res = AuthAccessControl.objects.get(pk=object_id).to_dict()
            elif name:
                res = AuthAccessControl.objects.get(name=name).to_dict()
            else:
                res = [a.to_dict() for a in AuthAccessControl.objects.all()]
            
            return JsonResponse({
                "res": res
            })
        
        except AuthAccessControl.DoesNotExist:
            return JsonResponse({
                "error": _("Object does not exist")
            }, status=404)
        
        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)
            
            return JsonResponse({
                "error": error
            }, status=500)

    @api_need_key("cluster_api_key")
    def put(self, request, object_id):
        try:
            auth_access_control = AuthAccessControl.objects.get(pk=object_id)

            if hasattr(request, "JSON"):
                data = request.JSON
            else:
                data = request.POST

            return save_access_control(data, instance=auth_access_control)

        except AuthAccessControl.DoesNotExist:
            return JsonResponse({
                "error": _("Object not found")
            }, status=404)

        except Exception as err:
            logger.critical(err, exc_info=1)
            error = _("An error has occured")
            if settings.DEV_MODE:
                error = str(err)
            
            return JsonResponse({
                "error": error
            }, status=500)

    @api_need_key("cluster_api_key")
    def post(self, request):
        try:
            if hasattr(request, "JSON"):
                data = request.JSON
            else:
                data = request.POST

            return save_access_control(data, instance=AuthAccessControl())

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occured")
            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                "error": error
            }, status=500)


@csrf_exempt
@api_need_key("cluster_api_key")
@require_http_methods(["POST"])
def auth_access_control_clone(request):
    try:
        if hasattr(request, "JSON"):
            pk = request.JSON.get('pk')
        else:
            pk = request.POST.get('pk')

        access_control = AuthAccessControl.objects.get(pk=pk)
        access_control.pk = None
        access_control.name = "Clone of {} {}".format(access_control.name, get_random_string(length=4))
        access_control.save()

        return JsonResponse({
            "res": access_control.to_dict()
        })

    except AuthAccessControl.DoesNotExist:
        return JsonResponse({
            'error': _('ACL does not exist')
        }, status=404)

    except Exception as e:
        logger.critical(e, exc_info=1)
        if settings.DEV_MODE:
            raise

        return JsonResponse({
            'error': _('An error occurred')
        }, status=400)
