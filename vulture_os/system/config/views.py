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
__doc__ = 'Config View'

# Django system imports
from django.db.models import Q
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext as _

# Django project imports
from authentication.user_portal.models import UserAuthentication
from services.frontend.models import Frontend
from system.cluster.models import Cluster, Node
from system.config.form import ConfigForm
from workflow.models import Workflow

# Required exceptions imports
from gui.forms.form_utils import DivErrorList
from system.exceptions import VultureSystemConfigError

# Extern modules imports

# Required exceptions imports
from system.exceptions import VultureSystemConfigError

# Logger configuration imports
import logging
logger = logging.getLogger('services')


def build_response_config(module_url, command_list):
    result = {
        'links': {
            'get': {
                'rel': 'self', 'type': 'GET',
                'href': reverse(module_url)
            },
            'put': {
                'rel': 'self', 'type': 'PUT',
                'href': reverse(module_url)
            },
            'patch': {
                'rel': 'self', 'type': 'PATCH',
                'href': reverse(module_url)
            }
        }
    }
    for command in command_list:
        result[command] = {
            'rel': 'self', 'type': "POST", 'name': command,
            'href': reverse(module_url, kwargs={
                'object_id': str(id), 'action': command,
            })
        }

    return JsonResponse(result, status=201)


def config_edit(request, api=False, update=False):
    config_model = Cluster.get_global_config()
    old_redis_password = config_model.redis_password

    if hasattr(request, "JSON") and api:
        if update:
            request.JSON = {**config_model.to_dict(), **request.JSON}
        request_data = request.JSON
    else:
        request_data = request.POST

    form = ConfigForm(request_data or None, instance=config_model, error_class=DivErrorList)

    def render_form(**kwargs):
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                return JsonResponse(form.errors.get_json_data(), status=400)
            if save_error:
                return JsonResponse({'error': save_error[0]}, status=500)
        return render(request, 'config/config.html', {'form': form, **kwargs})

    if request.method in ("POST", "PUT", "PATCH") and form.is_valid():
        config = form.save(commit=False)

        if "redis_password" in form.changed_data:
            # Deploy redis password
            status, results = Cluster.await_api_request("toolkit.redis.redis_base.set_password", (config.redis_password, old_redis_password), internal=True)
            if not status:
                error_msg = "Could not change password"
                try:
                    error_msg += f": {results[0]['result']}"
                except:
                    pass
                form.add_error('redis_password', error_msg)

        if not form.is_valid():
            return render_form()

        config.save()

        """ Write .ssh/authorized_keys if any change detected """
        if "ssh_authorized_key" in form.changed_data:
            params = [ "/usr/home/vlt-adm/.ssh/authorized_keys", request_data.get('ssh_authorized_key'), 'vlt-adm:wheel', '600' ]
            for node in Node.objects.all():
                try:
                    node.api_request('system.config.models.write_conf', config=params)
                except Exception as e:
                    raise VultureSystemConfigError("on node '{}'.\nRequest failure.".format(node.name))

        """ If customer name has changed, rewrite rsyslog templates """
        # If the internal Tenants config has changed, reload Rsyslog configuration of pstats
        if "internal_tenants" in form.changed_data:
            Cluster.api_request("services.rsyslogd.rsyslog.configure_pstats")
            Cluster.api_request("services.rsyslogd.rsyslog.restart_service")
        if "portal_cookie_name" in form.changed_data or "public_token" in form.changed_data:
            # Reload Workflows with authentication : session checks must be updated with the new cookie's name/public token
            for workflow in Workflow.objects.filter(authentication__isnull=False):
                for node in workflow.frontend.get_nodes():
                    node.api_request("workflow.workflow.build_conf", workflow.pk)
            for portal in UserAuthentication.objects.filter(enable_external=True):
                portal.save_conf()
            Cluster.api_request("services.haproxy.haproxy.reload_service")
        if "redis_password" in form.changed_data:
            Cluster.api_request("services.haproxy.haproxy.configure_node")
            for frontend in Frontend.objects.filter(Q(mode="log", listening_mode="redis") | Q(mode="filebeat")):
                frontend.redis_password = config.redis_password
                frontend.save()
                for node in frontend.get_nodes():
                    node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.pk)
                    if frontend.mode == "filebeat":
                        node.api_request("services.filebeat.filebeat.build_conf", frontend.pk)
            Cluster.api_request("services.rsyslogd.rsyslog.restart_service")
        if "logs_ttl" in form.changed_data:
            res, mess = config_model.set_logs_ttl()
            if not res:
                return render_form(save_error=mess)
        if any(value in form.changed_data for value in ["pf_whitelist", "pf_blacklist"]):
            Cluster.api_request("services.pf.pf.gen_config")

        if api:
            return build_response_config("system.config.api", [])

        return HttpResponseRedirect('/system/config/')

    return render_form()


def pf_whitelist_blacklist(request, list_type=None):
    """
        Add or Delete an IP from PacketFilter Whitelist or Blacklist
        JSON Parameters:
            ip_address: IPv4/IPv6
            action: (str: add/delete)
    """

    #FIXME: Use decorators
    try:
        ip_address = request.JSON.get('ip_address')
        action = request.JSON.get('action')
    except:
        #We are coming from the GUI
        if not list_type:
            list_type = request.POST.get("list_type")

        ip_address = request.POST.get("ip_address")
        action = request.POST.get("action")

    if list_type not in ('blacklist', 'whitelist'):
        return JsonResponse({
            'status': False,
            'error': _('Invalid Packet Filter list')
        }, status=400)

    if action not in ('add', 'del'):
        return JsonResponse({
            'status': False,
            'error': _('Invalid action')
        }, status=400)

    if not ip_address:
        return JsonResponse({
            'status': False,
            'error': _('No ip address specified')
        }, status=400)

    config_model = Cluster.get_global_config()
    if list_type == "whitelist":
        pf_list = config_model.pf_whitelist.split(',')
    else:
        pf_list = config_model.pf_blacklist.split(',')

    if action == "add":
        if ip_address not in pf_list:
            pf_list.append(ip_address)
        else:
            return JsonResponse({
                'status': False,
                'error': _('address already present in list')
            }, status=400)
    elif action == "del":
        if ip_address in pf_list:
            pf_list.remove(ip_address)
        else:
            return JsonResponse({
                'status': False,
                'error': _('address not present in list')
            }, status=400)

    try:
        ConfigForm.validate_ip_list(pf_list)
        if list_type == "whitelist":
            config_model.pf_whitelist = ",".join(pf_list)
        else:
            config_model.pf_blacklist = ",".join(pf_list)

    except Exception as e:
        return JsonResponse({'status': False, 'error': str(e)}, status=500)

    config_model.save()
    Cluster.api_request("services.pf.pf.gen_config")
    return JsonResponse({'status': True, "data": ""})
