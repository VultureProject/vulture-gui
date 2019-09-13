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

from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators.http import require_http_methods
from django.http import HttpResponseForbidden, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from gui.decorators.apicall import api_need_key
from system.pki.models import X509Certificate
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
        "ca_cert": internal_ca.cert
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
