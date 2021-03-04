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
__doc__ = 'Cluster API'


# Django system imports
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.conf import settings
from django.views import View

# Django project imports
from gui.decorators.apicall import api_need_key
from system.cluster.models import Node
from system.cluster.views import COMMAND_LIST, cluster_edit
from system.cluster.models import Cluster
from toolkit.mongodb.mongo_base import MongoBase

# Required exceptions imports

# Extern modules imports
import time

import logging
logger = logging.getLogger('system')


@csrf_exempt
@api_need_key('cluster_api_key')
@require_http_methods(["POST"])
def cluster_add(request):

    slave_ip = request.POST.get('slave_ip')
    slave_name = request.POST.get('slave_name')

    # FIXME: improve security check (valid IPv4 / IPv6 and valid name)
    if not slave_name or not slave_ip:
        return JsonResponse({
            'status': False,
            'message': 'Invalid call'
        })

    """ Make the slave_name resolvable on all Cluster nodes"""
    Cluster.api_request("toolkit.network.network.make_hostname_resolvable", (slave_name, slave_ip))

    """ Now the slave should be in the cluster:
        Add it's management IP """
    node = Node()
    node.name = slave_name
    node.management_ip = slave_ip
    node.internet_ip = slave_ip
    node.backends_outgoing_ip = slave_ip
    node.logom_outgoing_ip = slave_ip
    node.save()

    # We need to wait for the VultureD daemon to reload PF Conf
    time.sleep(6)

    """ Add NEW node into the REPLICASET, as a pending member """
    c = MongoBase()
    c.connect()
    cpt = 0
    response = None
    while not response:
        try:
            logger.debug("Adding {} to replicaset".format(slave_name))
            response = c.repl_add(slave_name + ':9091')
        except Exception as e:
            logger.error("Cannot connect to slave for the moment : {}".format(e))
            cpt += 1
            if cpt > 10:
                logger.error("Failed to connect to the slave 10 times, aborting.")
                return JsonResponse({
                    'status': False,
                    'message': 'Error during repl_add. Check logs'
                })
        logger.info("Waiting for next connection to slave ...")
        time.sleep(1)

    if response:
        node.api_request('toolkit.network.network.refresh_nic')

        return JsonResponse({
            'status': True,
            'message': 'ok'
        })
    else:
        return JsonResponse({
            'status': False,
            'message': 'Error during repl_add. Check logs'
        })


@csrf_exempt
@api_need_key('cluster_api_key')
@require_http_methods(['GET'])
def cluster_info(request):
    try:
        nodes = {}
        for node in Node.objects.all():
            nodes[node.name] = node.to_dict()

        return JsonResponse({
            'status': True,
            'data': nodes
        })

    except Exception as e:
        logger.critical(e, exc_info=1)
        if settings.DEV_MODE:
            raise

        return JsonResponse({
            'status': False,
            'data': _('An error has occurred')
        }, 500)


@method_decorator(csrf_exempt, name="dispatch")
class NodeAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            if object_id:
                try:
                    obj = Node.objects.get(pk=object_id).to_dict()
                except Node.DoesNotExist:
                    return JsonResponse({
                        'error': _('Object does not exist')
                    }, status=404)

            else:
                obj = [s.to_dict() for s in Node.objects.all()]

            return JsonResponse({
                'data': obj
            })

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def post(self, request, object_id, action=None):
        try:
            if not action:
                return cluster_edit(request, object_id, api=True)

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
            return cluster_edit(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def patch(self, request, object_id):
        allowed_fields = ('pf_limit_states', 'pf_limit_frags', 'pf_limit_src',
                          'pf_custom_param_config', 'pf_custom_nat_config', 'pf_custom_rdr_config', 'pf_custom_config',
                          'gateway', 'gateway_ipv6', 'static_routes', 'management_ip', 'pstats_forwarders')

        try:
            for key in request.JSON.keys():
                if key not in allowed_fields:
                    return JsonResponse({'error': _("Attribute not allowed : '{}'."
                                                    "Allowed attributes are {}".format(key, allowed_fields))})
            return cluster_edit(request, object_id, api=True, update=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    # It is not possible (yet?) to delete a node
