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
__doc__ = 'Cluster View'


from django.http import (HttpResponseForbidden, HttpResponseRedirect, JsonResponse, HttpResponseBadRequest)
from system.cluster.form import NodeForm
from toolkit.mongodb.mongo_base import MongoBase
from django.shortcuts import render
from services.pf.pf import PFService
from system.cluster.models import Cluster, Node
from gui.forms.form_utils import DivErrorList
from django.utils.translation import gettext_lazy as _
from toolkit.api.responses import build_response

from django.core.exceptions import ObjectDoesNotExist


def cluster_stepdown(request, object_id, api=False):
    """
    Ask the primary node to become secondary so that a promotion can occur
    This is an API request
    :param request:
    :param object_id:
    :param api:
    :return:
    """
    if not request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return HttpResponseBadRequest()

    try:
        node_model = Node.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    c = MongoBase()
    c.connect()

    # If the asked node is not primary, return error
    if c.get_primary() != node_model.name + ":9091":
        return JsonResponse({'status': False, 'error': _("Cannot step down a non-primary node.")}, status=400)
    if Node.objects.count() < 2:
        return JsonResponse({'status': False, 'error': _("Cannot step down a node outside a cluster")}, status=400)

    status, message = c.repl_set_step_down()  # Automagically connect to the primary node

    c = MongoBase()
    c.connect()

    return JsonResponse({'status': status, 'message': message})


def cluster_remove(request, object_id, api=False):
    """ Remove a node from the MongoDB replicaset
    This is an API request
    """
    if not request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return HttpResponseBadRequest()

    try:
        node_model = Node.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    c = MongoBase()
    c.connect()

    # Automagically connect to the primary node
    status, message = c.repl_remove(node_model.name + ":9091")

    return JsonResponse({'status': status, 'message': message})


def cluster_join(request, object_id, api=False):
    """ Join a node into the MongoDB replicaset
    This is an API request
    """
    if not request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return HttpResponseBadRequest()

    try:
        node_model = Node.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    c = MongoBase()
    c.connect()

    # Automagically connect to the primary node
    status, message = c.repl_add(node_model.name + ':9091')

    return JsonResponse({'status': status, 'message': message})


def cluster_edit(request, object_id, api=False, update=False):
    """ View used to edit a node """
    # Node MUST exists - It should be created by an API Call from a replica
    # Unlike vulture3 we cannot add a new node from the GUI
    # But we can add an existing node from the GUI, if it has previously been removed from replicaset

    try:
        node_model = Node.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    if hasattr(request, "JSON") and api:
        if update:
            request.JSON = {**node_model.to_small_dict(), **request.JSON}
        form = NodeForm(request.JSON, instance=node_model, error_class=DivErrorList)
    else:
        form = NodeForm(request.POST or None, instance=node_model, error_class=DivErrorList)

    def render_form(**kwargs):
        # if not object_id:
        #     return render(request, 'system/cluster_add.html', {'form': form, **kwargs})
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                return JsonResponse(form.errors.get_json_data(), status=400)
            if save_error:
                return JsonResponse({'error': save_error[0]}, status=500)
        return render(request, 'system/cluster_edit.html', {'form': form, **kwargs})

    if request.method in ("POST", "PUT", "PATCH") and form.is_valid():
        ip_changed = "management_ip" or "internet_ip" or "backends_outgoing_ip" or "logom_outgoing_ip"in form.changed_data
        gateway_changed = "gateway" in form.changed_data
        gateway_ipv6_changed = "gateway_ipv6" in form.changed_data
        static_route_changed = "static_routes" in form.changed_data
        pstats_forwarders_changed = "pstats_forwarders" in form.changed_data
        pf_custom_param_config_changed = "pf_custom_param_config" in form.changed_data
        pf_custom_nat_config_changed = "pf_custom_nat_config" in form.changed_data
        pf_custom_rdr_config_changed = "pf_custom_rdr_config" in form.changed_data
        pf_custom_config_changed = "pf_custom_config" in form.changed_data

        node = form.save(commit=False)

        if pf_custom_param_config_changed or \
            pf_custom_nat_config_changed or \
            pf_custom_rdr_config_changed or \
            pf_custom_config_changed:

            updated_conf = PFService().get_conf(node=node)

            status, results = Cluster.await_api_request(
                node=node,
                action="services.pf.pf.test_config",
                config=(updated_conf),
                internal=True)
            if not status:
                return render_form(save_error=f"Invalid PF configuration: {str(results)}")
        node.save()

        if ip_changed or gateway_changed or gateway_ipv6_changed or static_route_changed:
            node.api_request('toolkit.network.network.write_network_config')
            node.api_request('toolkit.network.network.restart_routing')

        if ip_changed:
            Cluster.api_request("toolkit.network.network.make_hostname_resolvable", (node.name, node.management_ip))
            node.api_request('toolkit.network.network.write_management_ips')

        if pstats_forwarders_changed:
            node.api_request("services.rsyslogd.rsyslog.configure_pstats")
            node.api_request("services.rsyslogd.rsyslog.restart_service")

        # Update Cluster's pf configurations if needed
        if ip_changed or pstats_forwarders_changed or pf_custom_param_config_changed or pf_custom_nat_config_changed or \
           pf_custom_rdr_config_changed or pf_custom_config_changed:
            Cluster.api_request ("services.pf.pf.gen_config")

        if api:
            return build_response(node.id, "system.node.api", COMMAND_LIST)
        return HttpResponseRedirect('/system/cluster/')

    return render_form()


COMMAND_LIST = {
    'stepdown': cluster_stepdown,
    'remove': cluster_remove,
    'join': cluster_join
}
