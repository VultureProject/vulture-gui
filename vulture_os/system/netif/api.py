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
__doc__ = 'Network API'

from system.cluster.models import Cluster, NetworkInterfaceCard, NetworkAddress, Node
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from gui.decorators.apicall import api_need_key
from system.netif import views as netif_views
from django.db.models import Q
from django.http import JsonResponse
from django.conf import settings
from django.views import View
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@method_decorator(csrf_exempt, name="dispatch")
class NetworkInterfaceCardAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        excluded_intf = ("lo0", "lo1", "lo2", "lo3", "lo4", "lo5", "lo6", "pflog0", "vm-public")

        dev = request.GET.get('dev')
        node_name = request.GET.get('node_name')
        try:
            if object_id:
                res = NetworkInterfaceCard.objects.get(pk=object_id).to_template()

            elif dev and node_name:
                node = Node.objects.get(name=node_name)
                res = NetworkInterfaceCard.objects.get(dev=dev, node=node).to_template()

            else:
                res = []
                for s in NetworkInterfaceCard.objects.all().exclude(dev__in=excluded_intf):
                    res.append(s.to_template())

            return JsonResponse({
                'status': True,
                'data': res
            })

        except NetworkInterfaceCard.DoesNotExist:
            return JsonResponse({
                'status': False,
                'error': _('Object does not exist')
            }, status=404)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'status': False,
                'error': error
            }, status=500)


@csrf_exempt
@api_need_key('cluster_api_key')
def netif_refresh(request):
    """
    Read system configuration and refresh NIC list
    :param request:
    :return:
    """
    if request.method != "POST":
        return JsonResponse({
            'status': False,
            'message': 'waiting for POST request'
        }, status=400)

    try:
        status, results = Cluster.await_api_request('toolkit.network.network.refresh_nic')
        if status:
            return JsonResponse({
                'status': status,
                'data': results
            })
        else:
            return JsonResponse({
                'status': status,
                'error': results
            }, status=500)

    except Exception as e:
        return JsonResponse({
            'status': False,
            'error': str(e)
        }, status=500)

    return JsonResponse({
        'status': True,
        'data': "Refresh started"
    })


@method_decorator(csrf_exempt, name="dispatch")
class NetworkAddressAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            query = Q()
            if "name" in request.GET:
                query = query & Q(name=request.GET['name'])
            if "type" in request.GET:
                query = query & Q(type=request.GET['type'])
            if "ip" in request.GET:
                query = query & Q(ip=request.GET['ip'])
            if "nic" in request.GET:
                nic = request.GET['nic']
                if not isinstance(nic, list):
                    nic = [nic]
                query = query & Q(nic__in=nic)
            fields = request.GET.getlist('fields') or None
            if object_id:
                obj = NetworkAddress.objects.get(pk=object_id).to_dict(fields=fields)
            else:
                obj = [s.to_dict(fields=fields) for s in NetworkAddress.objects.filter(query)]

            return JsonResponse({
                'status': True,
                'data': obj
            })

        except NetworkAddress.DoesNotExist:
            return JsonResponse({
                'status': False,
                'error': _('Object does not exist')
            }, status=404)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'status': False,
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def post(self, request):
        try:
            return netif_views.netif_edit(request, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'status': False,
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def put(self, request, object_id=None):
        try:
            return netif_views.netif_edit(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'status': False,
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def delete(self, request, object_id=None):
        try:
            return netif_views.netif_delete(request, object_id, api=True)

        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'status': False,
                'error': error
            }, status=500)
