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
__doc__ = 'PKI API'

from django.views.decorators.http import require_http_methods
from django.http import HttpResponseForbidden, JsonResponse
from system.pki.models import X509Certificate, TLSProfile
from django.core.exceptions import ObjectDoesNotExist
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.utils.translation import gettext_lazy as _
from gui.decorators.apicall import api_need_key
from system.pki.views import tls_profile_edit, pki_edit, pki_delete
from django.views.generic.base import View
from django.conf import settings
import logging

logger = logging.getLogger('system')


@csrf_exempt
@api_need_key('cluster_api_key')
@require_http_methods(["POST"])
def pki_get_ca(request):
    """

    :param secret: secret Key of the cluster
    :return: The CA certificate of the cluster. This is used at bootstrap time, to join the cluster
    """

    try:
        internal_ca = X509Certificate.objects.get(is_vulture_ca=True, name__startswith="Vulture_PKI")
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Node is not initialized")

    return JsonResponse({
        "ca_cert": internal_ca.cert,
        "ca_key": internal_ca.key
    })


@csrf_exempt
@api_need_key('cluster_api_key')
@require_http_methods(["POST"])
def pki_issue_cert(request):
    """

    :param secret: secret Key of the cluster
    :return: The Node certificate and private key. This is used at bootstrap time, to join the cluster
    """

    node_name = request.POST['node_name']
    bundle = X509Certificate().gen_cert(node_name, node_name)

    if bundle:
        return JsonResponse(bundle)
    else:
        return HttpResponseForbidden("Error when issuing Node's certificate")


@method_decorator(csrf_exempt, name="dispatch")
class PKIView(View):
    @api_need_key("cluster_api_key")
    def get(self, request, object_id=None):
        try:
            object_id = request.GET.get('object_id', object_id)
            name = request.GET.get('name')
            fields = request.GET.getlist('fields') or None
            if object_id:
                ret = X509Certificate.objects.get(pk=object_id).to_dict(fields=fields)
            elif name:
                ret = X509Certificate.objects.get(name=name).to_dict(fields=fields)
            else:
                ret = [p.to_dict(fields=fields) for p in X509Certificate.objects.all()]

            return JsonResponse({
                "data": ret
            })

        except X509Certificate.DoesNotExist:
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
            return pki_edit(request, object_id, api=True)
        except X509Certificate.DoesNotExist:
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
            return pki_edit(request, api=True)

        except Exception as err:
            logger.critical(err, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(err)

            return JsonResponse({
                "error": error
            }, status=500)

    @api_need_key("cluster_api_key")
    def delete(self, request, object_id):
        try:
            return pki_delete(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

@method_decorator(csrf_exempt, name="dispatch")
class TLSProfileApiView(View):
    @api_need_key("cluster_api_key")
    def get(self, request):
        try:
            object_id = request.GET.get('object_id')
            name = request.GET.get('name')
            fields = request.GET.getlist('fields') or None
            if object_id:
                ret = TLSProfile.objects.get(pk=object_id).to_dict(fields=fields)
            elif name:
                ret = TLSProfile.objects.get(name=name).to_dict(fields=fields)
            else:
                ret = [p.to_dict(fields=fields) for p in TLSProfile.objects.all()]

            return JsonResponse({
                "data": ret
            })

        except TLSProfile.DoesNotExist:
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
            return tls_profile_edit(request, object_id, api=True)
        except TLSProfile.DoesNotExist:
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
            return tls_profile_edit(request, api=True)

        except Exception as err:
            logger.critical(err, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(err)

            return JsonResponse({
                "error": error
            }, status=500)

    @api_need_key("cluster_api_key")
    def delete(self, request, object_id):
        try:
            obj = TLSProfile.objects.get(pk=object_id)
            obj.delete()

            return JsonResponse({
                "status": True
            }, status=204)
        except TLSProfile.DoesNotExist:
            return JsonResponse({
                "status": False,
                "error": _("Object does not exist")
            }, status=404)
