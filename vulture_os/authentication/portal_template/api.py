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
__doc__ = 'Frontends API'


# Django system imports
from authentication.portal_template.models import PortalTemplate, TemplateImage
from authentication.portal_template.form import PortalTemplateForm, TemplateImageForm
from system.cluster.models import Cluster
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


def save_portal_template(data, instance):
    form = PortalTemplateForm(data, instance=instance)

    if not form.is_valid():
        return JsonResponse({
            "error": form.errors
        }, status=400)

    obj = form.save()
    # Reload template for all portals that uses this template
    for portal in obj.userauthentication_set.all().only('pk'):
        Cluster.api_request("authentication.user_portal.api.write_templates", portal.id)

    return JsonResponse({
        "message": _("Portal Template saved"),
        "object": obj.to_dict()
    })

@method_decorator(csrf_exempt, name="dispatch")
class PortalTemplateAPIv1(View):
    @api_need_key("cluster_api_key")
    def get(self, request):
        try:
            object_id = request.GET.get('object_id')
            name = request.GET.get('name')
            fields = request.GET.getlist('fields[]') or None
            if object_id:
                ret = PortalTemplate.objects.get(pk=object_id).to_dict(fields=fields)
            elif name:
                ret = PortalTemplate.objects.get(name=name).to_dict(fields=fields)
            else:
                ret = [p.to_dict(fields=fields) for p in PortalTemplate.objects.all()]
            
            return JsonResponse({
                "data": ret
            })

        except PortalTemplate.DoesNotExist:
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
    
    @api_need_key('cluster_api_key')
    def put(self, request, object_id):
        try:
            portal_template = PortalTemplate.objects.get(pk=object_id)

            if hasattr(request, "JSON"):
                data = request.JSON
            else:
                data = request.POST

            return save_portal_template(data, instance=portal_template)
        
        except PortalTemplate.DoesNotExist:
            return JsonResponse({
                "error": _("Object does not exist")
            }, status=404)
        
        except Exception as err:
            logger.critical(err, exc_info=1)
            error = _("An error has occurred")
            if settings.DEV_MODE:
                error = str(err)
            
            return JsonResponse({
                "error": error
            }, status=500)

    @api_need_key('cluster_api_key')
    def post(self, request):
        try:
            if hasattr(request, "JSON"):
                data = request.JSON
            else:
                data = request.POST

            print(data)
            return save_portal_template(data, instance=PortalTemplate())

        except Exception as err:
            logger.critical(err, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(err)
            
            return JsonResponse({
                "error": error
            }, status=500)

@csrf_exempt
@api_need_key("cluster_api_key")
@require_http_methods(["POST"])
def portal_template_clone(request):
    try:
        if hasattr(request, "JSON"):
            pk = request.JSON.get('pk')
        else:
            pk = request.POST.get('pk')

        portal_template = PortalTemplate.objects.get(pk=pk)
        portal_template.pk = None
        portal_template.name = f"Clone of {portal_template.name} {get_random_string(length=4)}"
        portal_template.save()

        return JsonResponse({
            "res": portal_template.to_dict()
        })
    
    except PortalTemplate.DoesNotExist:
        return JsonResponse({
            "error": _("Portal Template does not exist")
        }, status=404)
    
    except Exception as err:
        logger.critical(err, exc_info=1)
        if settings.DEV_MODE:
            raise

        return JsonResponse({
            "error": _("An error has occurred")
        }, status=500)



@method_decorator(csrf_exempt, name="dispatch")
class PortalImageAPIv1(View):
    @api_need_key("cluster_api_key")
    def get(self, request):
        try:
            object_id = request.GET.get('object_id')
            name = request.GET.get('name')
            fields = request.GET.getlist('fields[]') or None
            if object_id:
                ret = TemplateImage.objects.get(pk=object_id).to_dict(fields=fields)
            elif name:
                ret = TemplateImage.objects.get(name=name).to_dict(fields=fields)
            else:
                ret = [p.to_dict(fields=fields) for p in TemplateImage.objects.all()]
            
            return JsonResponse({
                "res": ret
            })

        except TemplateImage.DoesNotExist:
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
